package httppath

import "testing"

func TestCanonical(t *testing.T) {
	cases := map[string]string{
		"":                "/",
		"/":               "/",
		"/a":              "/a",
		"/a/":             "/a/",
		"//admin/x":       "/admin/x",
		"///a//b//":       "/a/b/",
		"/x/../admin/x":   "/admin/x",
		"/./admin/x":      "/admin/x",
		"/admin/./x":      "/admin/x",
		"/a/b/.":          "/a/b/",
		"/a/b/c/..":       "/a/b/",
		"/..":             "/",
		"/../../etc":      "/etc",
		"/a/..":           "/",
		"/./":             "/",
		"/a/.../b":        "/a/.../b",
		"/a/..b/c":        "/a/..b/c",
		"/admin;x/x":      "/admin;x/x",
		"/a/..;/b":        "/a/..;/b",
		"/ADMIN":          "/ADMIN",
		"*":               "*",
		"example.com:443": "example.com:443",
	}
	for in, want := range cases {
		if got := Canonical(in); got != want {
			t.Errorf("Canonical(%q) = %q, want %q", in, got, want)
		}
	}
}

func TestCanonical_FastPathKeepsString(t *testing.T) {
	p := "/static/css/site.css"
	if got := Canonical(p); got != p {
		t.Fatalf("Canonical(%q) = %q", p, got)
	}
	if n := testing.AllocsPerRun(100, func() { Canonical(p) }); n != 0 {
		t.Fatalf("canonical path allocates %v times", n)
	}
}

func TestWithoutParams(t *testing.T) {
	cases := map[string]string{
		"/admin;x/x":     "/admin/x",
		"/admin;x":       "/admin",
		"/x/..;/admin/x": "/admin/x",
		"/;x/admin":      "/admin",
		"/a;b=c;d/e;f/":  "/a/e/",
		"/plain/path":    "/plain/path",
	}
	for in, want := range cases {
		if got := WithoutParams(in); got != want {
			t.Errorf("WithoutParams(%q) = %q, want %q", in, got, want)
		}
	}
}
