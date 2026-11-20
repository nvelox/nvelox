package httpproxy

import (
	"context"
	"io"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"sync/atomic"
	"time"

	"nvelox/config"
	"nvelox/core/httpproxy/errorhtml"
	"nvelox/core/logging"

	"github.com/yookoala/gofast"
)

// ServeFastCGI forwards r to the FastCGI upstream cfg.Pass (e.g. PHP-FPM)
// and writes its response.
//
// nvelox picks the script, and only an existing regular .php file inside
// document_root reaches the upstream. The script path — the request path,
// the first split_path_info capture, or script_name — must not contain a
// "." or ".." segment, a backslash or a NUL byte (400); joined onto
// document_root it must stay inside it, on a path-separator boundary (400);
// and it must end in .php and, symlinks resolved, be a regular file inside
// the resolved document root (404). This is what nginx gets from
// `try_files $uri =404` in its PHP location, and it keeps PHP's
// cgi.fix_pathinfo walk (/uploads/x.jpg/y.php running x.jpg) out of reach.
//
// serveError writes the error responses nvelox generates itself; nil uses
// the built-in error pages.
func ServeFastCGI(w http.ResponseWriter, r *http.Request, cfg config.FastCGIConfig, serveError func(http.ResponseWriter, int)) {
	if serveError == nil {
		serveError = builtinErrorPage
	}

	network := "tcp"
	address := cfg.Pass
	if strings.HasPrefix(cfg.Pass, "unix:") {
		network = "unix"
		address = strings.TrimPrefix(cfg.Pass, "unix:")
	}

	// Config validation requires document_root on every fastcgi route.
	// Never fall back to the working directory — "/" in the container image.
	if cfg.DocumentRoot == "" {
		logging.Error("[FCGI] fastcgi route without document_root — refusing %s", logging.SanitizeLogField(r.URL.Path))
		serveError(w, http.StatusInternalServerError)
		return
	}
	docRoot, err := filepath.Abs(cfg.DocumentRoot)
	if err != nil {
		logging.Error("[FCGI] document_root %q: %v", cfg.DocumentRoot, err)
		serveError(w, http.StatusInternalServerError)
		return
	}

	scriptName := r.URL.Path
	if cfg.ScriptName != "" {
		scriptName = cfg.ScriptName
	}

	// Split path info
	pathInfo := ""
	if cfg.SplitPathInfo != "" {
		re, err := regexp.Compile(cfg.SplitPathInfo)
		if err != nil {
			// Config validation compiles it; fail closed if it got here anyway.
			logging.Error("[FCGI] invalid split_path_info %q: %v", cfg.SplitPathInfo, err)
			serveError(w, http.StatusInternalServerError)
			return
		}
		matches := re.FindStringSubmatch(r.URL.Path)
		if len(matches) >= 2 {
			scriptName = matches[1]
			if len(matches) >= 3 {
				pathInfo = matches[2]
			}
		}
	}

	if unsafeTargetPath(scriptName) {
		logging.Warn("[FCGI] Refusing script path %q: dot segment, backslash or NUL",
			logging.SanitizeLogField(scriptName))
		serveError(w, http.StatusBadRequest)
		return
	}
	scriptFilename := filepath.Join(docRoot, scriptName)
	if !withinRoot(docRoot, scriptFilename) {
		logging.Warn("[FCGI] Refusing SCRIPT_FILENAME %q outside document_root %q",
			logging.SanitizeLogField(scriptFilename), docRoot)
		serveError(w, http.StatusBadRequest)
		return
	}
	if !fastCGIScript(docRoot, scriptFilename) {
		serveError(w, http.StatusNotFound)
		return
	}

	// Use gofast to handle the request. The dial is bounded by the connect
	// timeout (the route's, else the listener's, else 10s) and ends when the
	// client goes away; the connection is kept for the response-head timer.
	var upstream net.Conn
	connectTimeout := cfg.Timeouts.ParseConnect()
	clientFactory := gofast.SimpleClientFactory(func() (net.Conn, error) {
		c, err := fcgiDial(r.Context(), network, address, connectTimeout)
		upstream = c
		return c, err
	})

	// Build a session handler chain
	chain := gofast.Chain(
		gofast.BasicParamsMap,
		mapFCGIHeaders,
		func(inner gofast.SessionHandler) gofast.SessionHandler {
			return func(client gofast.Client, req *gofast.Request) (*gofast.ResponsePipe, error) {
				// Custom params first: the script variables below are set
				// last, so no param can replace the checked script (the
				// config load also refuses them).
				for k, v := range cfg.Params {
					req.Params[k] = expandFCGIVar(v, r)
				}
				req.Params["SCRIPT_FILENAME"] = scriptFilename
				req.Params["SCRIPT_NAME"] = scriptName
				req.Params["DOCUMENT_ROOT"] = docRoot
				delete(req.Params, "PATH_TRANSLATED")
				if pathInfo != "" {
					req.Params["PATH_INFO"] = pathInfo
				} else {
					delete(req.Params, "PATH_INFO")
				}

				return inner(client, req)
			}
		},
	)

	logging.Info("[FCGI] %s %s -> %s:%s (script: %s)",
		logging.SanitizeLogField(r.Method), logging.SanitizeLogField(r.URL.Path),
		network, address, logging.SanitizeLogField(scriptFilename))

	// The exchange, without gofast's own handler (gofast.NewHandler): that
	// one keeps all of the upstream's stderr in memory until the response
	// ends, then writes it to the standard logger as it came, where a
	// newline in it (a PHP warning quoting a request) starts a log line of
	// the upstream's making.
	client, err := clientFactory()
	if err != nil {
		logging.Error("[FCGI] %s %s: %s:%s: %v", logging.SanitizeLogField(r.Method),
			logging.SanitizeLogField(r.URL.Path), network, address, err)
		serveError(w, http.StatusBadGateway)
		return
	}
	defer client.Close()
	// The exchange lasts no longer than the client's request: when that
	// ends (the client went away, the server is shutting down), the
	// upstream's connection is closed, which ends the exchange whatever the
	// upstream is doing. Without it, an upstream that stalls holds the
	// request, its goroutines and both connections until it closes itself.
	stopWithRequest := context.AfterFunc(r.Context(), func() { upstream.Close() })
	defer stopWithRequest()
	fw := &fcgiResponseWriter{ResponseWriter: w, base: w.Header().Clone(), serveError: serveError}
	req := gofast.NewRequest(r)
	if d := cfg.Timeouts.ResolveResponseHeader(defaultBackendResponseHeader); d > 0 {
		// The upstream gets d to start answering once it has the request,
		// as an HTTP backend does: the timer starts when the request body
		// has been read to its end (at once without one), and the response
		// head stops it. When it fires first, the upstream's connection is
		// closed, which ends the exchange, and the client gets a 504.
		var timer atomic.Pointer[time.Timer]
		start := func() {
			timer.Store(time.AfterFunc(d, func() {
				if fw.headTimeout() {
					logging.Warn("[FCGI] %s %s: no response head within %v, answering 504",
						logging.SanitizeLogField(r.Method), logging.SanitizeLogField(r.URL.Path), d)
					upstream.Close()
				}
			}))
		}
		defer func() {
			if t := timer.Load(); t != nil {
				t.Stop()
			}
		}()
		if req.Stdin == nil {
			start()
		} else {
			req.Stdin = &fcgiBody{ReadCloser: req.Stdin, sent: start}
		}
	}
	resp, err := chain(gofast.BasicSession)(client, req)
	if err != nil {
		logging.Error("[FCGI] %s %s: %s:%s: %v", logging.SanitizeLogField(r.Method),
			logging.SanitizeLogField(r.URL.Path), network, address, err)
		serveError(w, http.StatusInternalServerError)
		return
	}
	if err := resp.WriteTo(fw, fcgiStderr{r}); err != nil {
		logging.Warn("[FCGI] %s %s: %s", logging.SanitizeLogField(r.Method),
			logging.SanitizeLogField(r.URL.Path), logging.SanitizeLogField(err.Error()))
	}
}

// fcgiStderr writes what the FastCGI upstream sends on stderr (PHP's errors
// and warnings, for one) to the error log as it arrives, at error level as
// nginx does: a line for each piece read (at most io.Copy's 32 KiB),
// control characters escaped, nothing kept.
type fcgiStderr struct{ r *http.Request }

func (e fcgiStderr) Write(p []byte) (int, error) {
	logging.Error("[FCGI] %s %s: upstream stderr: %s", logging.SanitizeLogField(e.r.Method),
		logging.SanitizeLogField(e.r.URL.Path), logging.SanitizeLogField(string(p)))
	return len(p), nil
}

// fastCGIScript reports whether scriptFilename may be handed to the FastCGI
// upstream: it ends in .php and, symlinks resolved, is a regular file inside
// the resolved document root.
func fastCGIScript(root, scriptFilename string) bool {
	if filepath.Ext(scriptFilename) != ".php" {
		return false
	}
	realRoot, err := filepath.EvalSymlinks(root)
	if err != nil {
		return false
	}
	realScript, err := filepath.EvalSymlinks(scriptFilename)
	if err != nil || !withinRoot(realRoot, realScript) {
		return false
	}
	fi, err := os.Stat(realScript)
	return err == nil && fi.Mode().IsRegular()
}

// mapFCGIHeaders replaces gofast.MapHeader: every request header becomes an
// HTTP_* param, except
//   - names with a character other than a letter, digit or '-': after the
//     '-' → '_' mapping, "X_Forwarded_For: 6.6.6.6" lands on the same
//     HTTP_X_FORWARDED_FOR as the X-Forwarded-For nvelox sets, and Go's
//     random map order decides which one PHP sees (nginx drops such names
//     by default);
//   - Proxy, which would become HTTP_PROXY — the environment variable HTTP
//     clients in PHP and other CGI runtimes take as their outbound proxy
//     (httpoxy, CVE-2016-5385).
//
// Content-Type and Content-Length travel as CONTENT_TYPE / CONTENT_LENGTH
// (gofast.BasicParamsMap), as before.
func mapFCGIHeaders(inner gofast.SessionHandler) gofast.SessionHandler {
	return func(client gofast.Client, req *gofast.Request) (*gofast.ResponsePipe, error) {
		r := req.Raw
		if r.Host != "" {
			req.Params["HTTP_HOST"] = r.Host
		}
		for k, v := range r.Header {
			if !fcgiHeaderName(k) || strings.EqualFold(k, "Proxy") {
				continue
			}
			key := strings.ToUpper(strings.ReplaceAll(k, "-", "_"))
			if key == "CONTENT_TYPE" || key == "CONTENT_LENGTH" {
				continue
			}
			req.Params["HTTP_"+key] = strings.Join(v, ",")
		}
		return inner(client, req)
	}
}

// fcgiHeaderName reports whether a request header name is made of letters,
// digits and '-' only.
func fcgiHeaderName(name string) bool {
	if name == "" {
		return false
	}
	for i := 0; i < len(name); i++ {
		c := name[i]
		if !('a' <= c && c <= 'z' || 'A' <= c && c <= 'Z' || '0' <= c && c <= '9' || c == '-') {
			return false
		}
	}
	return true
}

// fcgiResponseWriter is the ResponseWriter gofast writes the FastCGI
// response into. gofast takes the first three characters of the upstream's
// "Status:" line as the code and calls WriteHeader with it on its own
// goroutine; net/http panics on a code below 100, and a panic outside the
// handler goroutine ends the process — one "Status: 099" from a PHP script
// took nvelox down. A status outside 200-599 (1xx included: a FastCGI
// response has a single header block) becomes a 502 from nvelox instead,
// without the upstream's headers or body; gofast still reads the upstream
// response to its end. A response head that comes after the response-head
// timeout fired (headTimeout) becomes a 504 the same way.
type fcgiResponseWriter struct {
	http.ResponseWriter
	base        http.Header // response headers set before the exchange
	serveError  func(http.ResponseWriter, int)
	wroteHeader bool
	discard     bool         // the upstream response was replaced by nvelox's answer
	head        atomic.Int32 // the response head against its timer: headWaiting, headCame or headTimedOut
}

const (
	headWaiting int32 = iota
	headCame
	headTimedOut
)

// headTimeout is called by the response-head timer: it reports whether the
// head had not come yet. From then on the client is answered 504 and the
// upstream's answer, if one still comes, is dropped.
func (f *fcgiResponseWriter) headTimeout() bool {
	return f.head.CompareAndSwap(headWaiting, headTimedOut)
}

func (f *fcgiResponseWriter) WriteHeader(code int) {
	if f.wroteHeader {
		return
	}
	f.wroteHeader = true
	if !f.head.CompareAndSwap(headWaiting, headCame) {
		f.replace(http.StatusGatewayTimeout)
		return
	}
	if code >= 200 && code <= 599 {
		f.ResponseWriter.WriteHeader(code)
		return
	}
	logging.Warn("[FCGI] upstream sent Status %d — answering 502", code)
	f.replace(http.StatusBadGateway)
}

// replace answers code from nvelox in place of the upstream's response: the
// headers gofast already copied from it are dropped (back to the ones set
// before the exchange), and so is its body.
func (f *fcgiResponseWriter) replace(code int) {
	h := f.ResponseWriter.Header()
	for k := range h {
		delete(h, k)
	}
	for k, v := range f.base {
		h[k] = v
	}
	f.discard = true
	f.serveError(f.ResponseWriter, code)
}

func (f *fcgiResponseWriter) Write(b []byte) (int, error) {
	if !f.wroteHeader {
		f.WriteHeader(http.StatusOK)
	}
	if f.discard {
		return len(b), nil
	}
	return f.ResponseWriter.Write(b)
}

// fcgiBody is the request body as gofast reads it for the upstream: sent
// is called once, when gofast has read the last of it (a read that ends or
// fails, or one that gives nothing, which gofast takes as the end). Only
// gofast's request writer reads it.
type fcgiBody struct {
	io.ReadCloser
	sent func()
	done bool
}

func (b *fcgiBody) Read(p []byte) (int, error) {
	n, err := b.ReadCloser.Read(p)
	if (err != nil || n == 0) && !b.done {
		b.done = true
		b.sent()
	}
	return n, err
}

// fcgiDial dials the FastCGI upstream within timeout (0: no limit); the
// dial also ends with ctx.
func fcgiDial(ctx context.Context, network, address string, timeout time.Duration) (net.Conn, error) {
	d := net.Dialer{Timeout: timeout}
	return d.DialContext(ctx, network, address)
}

// builtinErrorPage writes nvelox's built-in error page for code.
func builtinErrorPage(w http.ResponseWriter, code int) {
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.Header().Set("X-Content-Type-Options", "nosniff")
	w.WriteHeader(code)
	w.Write(errorhtml.DefaultErrorPage(code))
}

// expandFCGIVar expands nginx-style variables in FastCGI param values.
func expandFCGIVar(value string, r *http.Request) string {
	if !strings.Contains(value, "$") {
		return value
	}

	host, _, _ := net.SplitHostPort(r.RemoteAddr)

	replacer := strings.NewReplacer(
		"$request_uri", r.RequestURI,
		"$document_root", "",
		"$http_x_real_ip", r.Header.Get("X-Real-IP"),
		"$http_x_forwarded_port", r.Header.Get("X-Forwarded-Port"),
		"$remote_addr", host,
		"$server_name", r.Host,
		"$request_method", r.Method,
		"$query_string", r.URL.RawQuery,
	)
	return replacer.Replace(value)
}
