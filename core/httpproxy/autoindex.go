package httpproxy

import (
	"bytes"
	"html/template"
	"net/http"
	"net/url"
	"os"
	"path"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"nvelox/core/logging"
)

// autoindexMaxEntries caps the entries one listing reads and shows, so a
// huge directory cannot make every request expensive.
var autoindexMaxEntries = 10000

type listingEntry struct {
	Name     string // shown (HTML-escaped by the template)
	Href     string // URL-escaped
	Dir      bool
	Size     int64
	Modified time.Time
}

var listingPage = template.Must(template.New("autoindex").Parse(`<!doctype html>
<html><head><meta charset="utf-8"><title>Index of {{.Path}}</title>
<style>body{font:14px/1.5 system-ui,sans-serif;margin:24px}td{padding:2px 16px 2px 0}td.n{text-align:right}</style>
</head><body><h1>Index of {{.Path}}</h1>
<table>{{if .Parent}}<tr><td><a href="../">../</a></td><td></td><td></td></tr>{{end}}
{{range .Entries}}<tr><td><a href="{{.Href}}">{{.Name}}{{if .Dir}}/{{end}}</a></td><td class="n">{{if .Dir}}-{{else}}{{.Size}}{{end}}</td><td>{{.Modified.UTC.Format "2006-01-02 15:04"}}</td></tr>
{{end}}</table>{{if .Truncated}}<p>Listing cut at {{.Max}} entries.</p>{{end}}
</body></html>
`))

// serveListing answers a directory request with an HTML listing (static
// autoindex). Only what the route would serve is listed: no dotfiles, no
// scripts, no special files, and symlinks only when they resolve inside the
// root. Names are HTML-escaped and links URL-escaped; the page carries a CSP
// that runs no script.
func (h *StaticHandler) serveListing(w http.ResponseWriter, r *http.Request, f staticFile) {
	if r.Method != http.MethodGet && r.Method != http.MethodHead {
		w.Header().Set("Allow", "GET, HEAD")
		http.Error(w, http.StatusText(http.StatusMethodNotAllowed), http.StatusMethodNotAllowed)
		return
	}
	if !strings.HasSuffix(r.URL.Path, "/") {
		// Relative links need the trailing slash (net/http and nginx do the same).
		target := url.PathEscape(path.Base(r.URL.Path)) + "/"
		if r.URL.RawQuery != "" {
			target += "?" + r.URL.RawQuery
		}
		http.Redirect(w, r, target, http.StatusMovedPermanently)
		return
	}
	realRoot, err := filepath.EvalSymlinks(filepath.Clean(h.root))
	if err != nil {
		realRoot = filepath.Clean(h.root)
	}
	dir, err := os.Open(f.path)
	if err != nil {
		http.Error(w, http.StatusText(http.StatusNotFound), http.StatusNotFound)
		return
	}
	des, err := dir.ReadDir(autoindexMaxEntries + 1)
	dir.Close()
	if err != nil && len(des) == 0 {
		logging.Warn("[STATIC] autoindex %s: %v", logging.SanitizeLogField(f.urlPath), err)
	}
	truncated := len(des) > autoindexMaxEntries
	if truncated {
		des = des[:autoindexMaxEntries]
	}
	entries := make([]listingEntry, 0, len(des))
	for _, de := range des {
		name := de.Name()
		if strings.HasPrefix(name, ".") || isScriptFile(name) {
			continue
		}
		full := filepath.Join(f.path, name)
		if real, err := filepath.EvalSymlinks(full); err != nil || !withinRoot(realRoot, real) {
			continue // dangling, or a symlink out of the root
		}
		fi, err := os.Stat(full)
		if err != nil || !(fi.IsDir() || fi.Mode().IsRegular()) {
			continue
		}
		// "./": a name with a colon is not taken for a URL scheme.
		href := "./" + url.PathEscape(name)
		if fi.IsDir() {
			href += "/"
		}
		entries = append(entries, listingEntry{Name: name, Href: href, Dir: fi.IsDir(), Size: fi.Size(), Modified: fi.ModTime()})
	}
	sort.Slice(entries, func(i, j int) bool {
		if entries[i].Dir != entries[j].Dir {
			return entries[i].Dir
		}
		return entries[i].Name < entries[j].Name
	})
	var buf bytes.Buffer
	err = listingPage.Execute(&buf, struct {
		Path      string
		Parent    bool
		Entries   []listingEntry
		Truncated bool
		Max       int
	}{r.URL.Path, r.URL.Path != "/", entries, truncated, autoindexMaxEntries})
	if err != nil {
		http.Error(w, http.StatusText(http.StatusInternalServerError), http.StatusInternalServerError)
		return
	}
	hdr := w.Header()
	hdr.Set("Content-Type", "text/html; charset=utf-8")
	hdr.Set("Content-Security-Policy", "default-src 'none'; style-src 'unsafe-inline'")
	hdr.Set("X-Content-Type-Options", "nosniff")
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write(buf.Bytes())
}
