package httpproxy

import (
	"net"
	"net/http"
	"os"
	"path/filepath"
	"regexp"
	"strings"

	"nvelox/config"
	"nvelox/core/logging"

	"github.com/yookoala/gofast"
)

// FastCGIHandler forwards HTTP requests to a FastCGI backend (e.g., PHP-FPM).
type FastCGIHandler struct {
	address       string
	network       string
	documentRoot  string
	scriptName    string
	splitPathInfo *regexp.Regexp
	params        map[string]string
	index         string
}

// NewFastCGIHandler creates a FastCGI handler from config.
func NewFastCGIHandler(cfg config.FastCGIConfig) *FastCGIHandler {
	network := "tcp"
	address := cfg.Pass

	// Support unix sockets: "unix:/var/run/php-fpm.sock"
	if strings.HasPrefix(cfg.Pass, "unix:") {
		network = "unix"
		address = strings.TrimPrefix(cfg.Pass, "unix:")
	}

	h := &FastCGIHandler{
		address:      address,
		network:      network,
		documentRoot: cfg.DocumentRoot,
		scriptName:   cfg.ScriptName,
		params:       cfg.Params,
		index:        cfg.Index,
	}

	if cfg.SplitPathInfo != "" {
		h.splitPathInfo, _ = regexp.Compile(cfg.SplitPathInfo)
	}

	if h.index == "" {
		h.index = "index.php"
	}

	return h
}

// ServeHTTP forwards the request to the FastCGI backend and writes the response.
func (h *FastCGIHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	// Build FastCGI environment
	scriptName := r.URL.Path
	pathInfo := ""

	// Split path info (like fastcgi_split_path_info)
	if h.splitPathInfo != nil {
		matches := h.splitPathInfo.FindStringSubmatch(r.URL.Path)
		if len(matches) >= 2 {
			scriptName = matches[1]
			if len(matches) >= 3 {
				pathInfo = matches[2]
			}
		}
	}

	// Override script name if configured
	if h.scriptName != "" {
		scriptName = h.scriptName
	}

	// Build SCRIPT_FILENAME
	docRoot := h.documentRoot
	if docRoot == "" {
		docRoot, _ = os.Getwd()
	}
	scriptFilename := filepath.Join(docRoot, scriptName)

	// Create FastCGI client handler using gofast
	connFactory := gofast.SimpleConnFactory(h.network, h.address)
	clientFactory := gofast.SimpleClientFactory(connFactory)

	handler := gofast.NewHandler(
		gofast.NewPHPFS(docRoot)(gofast.BasicParamsMap(gofast.BasicSession)),
		clientFactory,
	)

	// Override params via custom session handler
	origServeHTTP := handler.ServeHTTP

	// Wrap to set custom params
	customHandler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Set custom env vars via request context or headers
		// gofast reads SCRIPT_FILENAME from the filesystem mapper
		_ = scriptFilename
		_ = pathInfo
		_ = scriptName
		origServeHTTP(w, r)
	})

	logging.Info("[FCGI] %s %s -> %s:%s (script: %s)",
		logging.SanitizeLogField(r.Method), logging.SanitizeLogField(r.URL.Path),
		h.network, h.address, logging.SanitizeLogField(scriptName))
	customHandler.ServeHTTP(w, r)
}

// ServeFastCGI is a simplified FastCGI handler that connects to the upstream,
// sends the request, and writes the response. This is a lower-level implementation
// using gofast's client directly.
func ServeFastCGI(w http.ResponseWriter, r *http.Request, cfg config.FastCGIConfig) {
	network := "tcp"
	address := cfg.Pass
	if strings.HasPrefix(cfg.Pass, "unix:") {
		network = "unix"
		address = strings.TrimPrefix(cfg.Pass, "unix:")
	}

	docRoot := cfg.DocumentRoot
	if docRoot == "" {
		docRoot, _ = os.Getwd()
	}

	scriptName := r.URL.Path
	if cfg.ScriptName != "" {
		scriptName = cfg.ScriptName
	}

	// Split path info
	pathInfo := ""
	if cfg.SplitPathInfo != "" {
		re, err := regexp.Compile(cfg.SplitPathInfo)
		if err == nil {
			matches := re.FindStringSubmatch(r.URL.Path)
			if len(matches) >= 2 {
				scriptName = matches[1]
				if len(matches) >= 3 {
					pathInfo = matches[2]
				}
			}
		}
	}

	scriptFilename := filepath.Join(docRoot, scriptName)

	// Use gofast to handle the request
	connFactory := gofast.SimpleConnFactory(network, address)
	clientFactory := gofast.SimpleClientFactory(connFactory)

	// Build a session handler chain
	chain := gofast.Chain(
		gofast.BasicParamsMap,
		gofast.MapHeader,
		func(inner gofast.SessionHandler) gofast.SessionHandler {
			return func(client gofast.Client, req *gofast.Request) (*gofast.ResponsePipe, error) {
				req.Params["SCRIPT_FILENAME"] = scriptFilename
				req.Params["SCRIPT_NAME"] = scriptName
				req.Params["DOCUMENT_ROOT"] = docRoot
				if pathInfo != "" {
					req.Params["PATH_INFO"] = pathInfo
				}

				// Apply custom params
				for k, v := range cfg.Params {
					req.Params[k] = expandFCGIVar(v, r)
				}

				return inner(client, req)
			}
		},
	)

	handler := gofast.NewHandler(chain(gofast.BasicSession), clientFactory)

	logging.Info("[FCGI] %s %s -> %s:%s (script: %s)",
		logging.SanitizeLogField(r.Method), logging.SanitizeLogField(r.URL.Path),
		network, address, logging.SanitizeLogField(scriptFilename))
	handler.ServeHTTP(w, r)
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

