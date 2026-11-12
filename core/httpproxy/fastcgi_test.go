package httpproxy

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"nvelox/config"
)

// TestServeFastCGI_RefusesUnsafeScriptPath: the FastCGI layer refuses a
// script path with a dot segment, a backslash or a NUL on its own, whatever
// handled the request path before it.
func TestServeFastCGI_RefusesUnsafeScriptPath(t *testing.T) {
	root := phpDocRoot(t)
	fpm, addr := startFakeFPM(t)
	cfg := config.FastCGIConfig{Pass: addr, DocumentRoot: root, SplitPathInfo: `^(.+\.php)(/.*)$`}
	for _, p := range []string{
		"/index.php/../admin/maint.php/x",
		"/index.php/./index.php/x",
		"/admin\\maint.php",
		"/index.php\x00.txt",
	} {
		r := httptest.NewRequest("GET", "/", nil)
		r.URL.Path = p
		rec := httptest.NewRecorder()
		before, _, _ := fpm.last()
		ServeFastCGI(rec, r, cfg, nil)
		after, env, _ := fpm.last()
		if after != before || rec.Code != http.StatusBadRequest {
			t.Errorf("%q: HTTP %d, PHP-FPM calls %d→%d (SCRIPT_FILENAME=%q), want 400 and no call",
				p, rec.Code, before, after, env["SCRIPT_FILENAME"])
		}
	}
}
