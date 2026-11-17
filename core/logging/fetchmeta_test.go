package logging

import (
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
)

func TestFetchMetaToken(t *testing.T) {
	cases := map[string]string{
		"":                       "-",
		"   ":                    "-",
		"cross-site":             "cross-site",
		"same-origin":            "same-origin",
		"image":                  "image",
		"-":                      "_", // present, not absent
		"a b":                    "a_b",
		`x" rid=forged`:          "x__rid_forged",
		"cross-site\nINJECTED":   "cross-site_INJECTED",
		"é":                      "__",
		strings.Repeat("a", 100): strings.Repeat("a", maxFetchMetaLen),
		" none ":                 "none",
		"webidentity.v2_beta":    "webidentity.v2_beta",
	}
	for in, want := range cases {
		if got := fetchMetaToken(in); got != want {
			t.Errorf("fetchMetaToken(%q) = %q, want %q", in, got, want)
		}
	}
}

// accessTail matches the token tail of an HTTP access line.
var accessTail = regexp.MustCompile(`"([^"]*)" fetch_site=(\S+) fetch_dest=(\S+) scheme=(https|http) rid=(\S+) gw=(\S*) site=(\S+)$`)

// anchoredTail is how a consumer anchored on the last three tokens reads a line;
// it must keep matching with the Fetch Metadata tokens in place.
var anchoredTail = regexp.MustCompile(` rid=(\S+) gw=(\S*) site=(\S+)\s*$`)

func TestAccessHTTP_FetchMetadataTokens(t *testing.T) {
	accessPath := filepath.Join(t.TempDir(), "access.log")
	if err := Init("info", accessPath, ""); err != nil {
		t.Fatalf("Init failed: %v", err)
	}
	t.Cleanup(func() { _ = Init("warning", "", "") })
	SetGateway("edge-1")
	t.Cleanup(func() { empty := ""; gatewayID.Store(&empty) })

	const ua = "Mozilla/5.0 (X11; Linux x86_64) Firefox/131.0"
	AccessHTTP("203.0.113.5", "example.com", "GET", "/img.png", "HTTP/2.0", 404, 12, 0.4, "192.0.2.10:80", ua, "cross-site", "image", true, "rid1", "web")
	AccessHTTP("203.0.113.6", "example.com", "GET", "/", "HTTP/1.1", 200, 12, 0.4, "192.0.2.10:80", "curl/8.5.0", "", "", false, "", "web")
	AccessHTTP("203.0.113.7", "example.com", "GET", "/", "HTTP/1.1", 200, 12, 0.4, "192.0.2.10:80", "x", `a b" rid=forged`, "-", true, "rid3", "web")

	data, err := os.ReadFile(accessPath)
	if err != nil {
		t.Fatalf("read: %v", err)
	}
	lines := strings.Split(strings.TrimRight(string(data), "\n"), "\n")
	if len(lines) != 3 {
		t.Fatalf("want 3 lines, got %d: %q", len(lines), data)
	}
	want := [][]string{
		{ua, "cross-site", "image", "https", "rid1", "edge-1", "web"},
		{"curl/8.5.0", "-", "-", "http", "-", "edge-1", "web"},
		{"x", "a_b__rid_forged", "_", "https", "rid3", "edge-1", "web"},
	}
	for i, line := range lines {
		m := accessTail.FindStringSubmatch(line)
		if m == nil {
			t.Fatalf("line %d does not match the token layout: %q", i, line)
		}
		for j, w := range want[i] {
			if m[j+1] != w {
				t.Errorf("line %d field %d = %q, want %q (%q)", i, j, m[j+1], w, line)
			}
		}
		a := anchoredTail.FindStringSubmatch(line)
		if a == nil || a[1] != want[i][4] || a[2] != "edge-1" || a[3] != "web" {
			t.Errorf("line %d: rid/gw/site tail no longer anchored at the end: %q", i, line)
		}
	}
	if !strings.HasPrefix(lines[0], `203.0.113.5 - example.com "GET /img.png HTTP/2.0" 404 12 0.400ms -> 192.0.2.10:80 "`) {
		t.Errorf("leading fields changed: %q", lines[0])
	}
}
