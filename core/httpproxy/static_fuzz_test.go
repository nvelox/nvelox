package httpproxy

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"nvelox/config"
)

// staticFixture is a document root with what a request must never reach
// around it and in it: a dotfile, scripts, a link that leaves the root, and
// a sibling directory whose name begins with the root's.
func staticFixture(tb testing.TB) (root, realRoot string) {
	tb.Helper()
	base := tb.TempDir()
	root = filepath.Join(base, "www")
	files := map[string]string{
		"www/index.html":       "home",
		"www/a.txt":            "a",
		"www/dir/b.txt":        "b",
		"www/dir/index.php":    "<?php // a script",
		"www/script.php":       "<?php // a script",
		"www/upload.PhTmL":     "<?php // a script",
		"www/.env":             "SECRET=1",
		"www/.git/config":      "[core]",
		"www/.well-known/acme": "token",
		"www/empty/.keep":      "",
		"www-old/secret.txt":   "outside, next to the root",
		"outside/secret.txt":   "outside",
		"outside/index.html":   "outside",
	}
	for name, body := range files {
		p := filepath.Join(base, filepath.FromSlash(name))
		if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
			tb.Fatal(err)
		}
		if err := os.WriteFile(p, []byte(body), 0o644); err != nil {
			tb.Fatal(err)
		}
	}
	for link, target := range map[string]string{
		"www/out":         filepath.Join(base, "outside"),
		"www/dir/up":      "../../outside/secret.txt",
		"www/in":          filepath.Join(root, "dir"),
		"www/old":         filepath.Join(base, "www-old"),
		"www/script.html": filepath.Join(root, "script.php"),
	} {
		if err := os.Symlink(target, filepath.Join(base, filepath.FromSlash(link))); err != nil {
			tb.Fatal(err)
		}
	}
	realRoot, err := filepath.EvalSymlinks(root)
	if err != nil {
		tb.Fatal(err)
	}
	return root, realRoot
}

// checkResolved fails when what Resolve returned for urlPath breaks a rule
// of the static file server: outside the root (after links), a dotfile (but
// .well-known), a script given to a handler that cannot run it, a listing
// without autoindex, or a file that is not there. Each rule is checked here
// without the server's own helpers.
func checkResolved(t *testing.T, h *StaticHandler, realRoot, urlPath string, scripts bool) {
	t.Helper()
	f, ok := h.Resolve(urlPath, scripts)
	if !ok {
		return
	}
	if f.path != realRoot && !strings.HasPrefix(f.path, realRoot+string(filepath.Separator)) {
		t.Fatalf("%q resolved to %s, outside the root %s", urlPath, f.path, realRoot)
	}
	if real, err := filepath.EvalSymlinks(f.path); err != nil || real != f.path {
		t.Fatalf("%q resolved to %s, which is not its own real path (%s, %v)", urlPath, f.path, real, err)
	}
	rel, _ := filepath.Rel(realRoot, f.path)
	for _, seg := range strings.Split(filepath.ToSlash(rel), "/") {
		if strings.HasPrefix(seg, ".") && seg != "." && seg != ".well-known" {
			t.Fatalf("%q resolved to %s, a dotfile", urlPath, f.path)
		}
	}
	switch strings.ToLower(filepath.Ext(f.path)) {
	case ".php", ".phtml", ".phar":
		if !scripts {
			t.Fatalf("%q resolved to the script %s for a handler that cannot run it", urlPath, f.path)
		}
		if !f.script {
			t.Fatalf("%q resolved to the script %s without saying so", urlPath, f.path)
		}
	}
	if f.script && !scripts {
		t.Fatalf("%q resolved to a script for a handler that cannot run it", urlPath)
	}
	fi, err := os.Stat(f.path)
	if err != nil {
		t.Fatalf("%q resolved to %s, which is not there: %v", urlPath, f.path, err)
	}
	if f.dir != fi.IsDir() {
		t.Fatalf("%q resolved to %s: listed %v, a directory %v", urlPath, f.path, f.dir, fi.IsDir())
	}
	if f.dir && !h.autoindex {
		t.Fatalf("%q resolved to a listing without autoindex", urlPath)
	}
}

// FuzzStaticResolve: whatever the request path, the static file server
// resolves it to nothing, or to a file it may serve (checkResolved), with
// and without scripts, with and without listings.
func FuzzStaticResolve(f *testing.F) {
	root, realRoot := staticFixture(f)
	handlers := []*StaticHandler{
		NewStaticHandler(config.StaticConfig{Root: root}),
		NewStaticHandler(config.StaticConfig{Root: root, Autoindex: true, Index: []string{"index.php", "index.html"}}),
		NewStaticHandler(config.StaticConfig{Root: root + "/", Index: []string{"../outside/index.html", "index.html"}}),
	}
	for _, s := range []string{
		"/", "/a.txt", "/dir/", "/dir/b.txt", "/dir/./b.txt", "//a.txt", "/in/b.txt", "/in/", "/out/secret.txt", "/out/",
		"/old/secret.txt", "/dir/up", "/script.php", "/script.html", "/upload.PhTmL", "/dir/index.php", "/.env", "/.git/config",
		"/.well-known/acme", "/empty/", "/../outside/secret.txt", "/../www-old/secret.txt", "/dir/../../outside/secret.txt",
		"../../etc/passwd", "\\..\\outside\\secret.txt", "/a.txt\x00.php", "/%2e%2e/outside", "/dir/b.txt/..", "/.", "/..",
		"/./.env", "/dir/.././.env", "/A.TXT", "/a.txt/", "",
	} {
		f.Add(s)
	}
	f.Fuzz(func(t *testing.T, urlPath string) {
		for _, h := range handlers {
			checkResolved(t, h, realRoot, urlPath, false)
			checkResolved(t, h, realRoot, urlPath, true)
		}
	})
}
