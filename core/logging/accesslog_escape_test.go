package logging

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// TestAccessHTTP_QuotedFieldsEscaped (Low): a '"' or '\' in the path or the
// User-Agent is written as \x22 / \x5C, so it cannot close its quoted field
// and forge the fields after it; control characters keep their existing
// escapes; an empty backend is "-".
func TestAccessHTTP_QuotedFieldsEscaped(t *testing.T) {
	f := filepath.Join(t.TempDir(), "a.log")
	if err := Init("info", f, ""); err != nil {
		t.Fatal(err)
	}
	defer Init("info", "", "")
	SetGateway("gw1")
	AccessHTTP("1.2.3.4", "h", "GET", `/x" 200 1 1.0ms -> fake "ua\`, "HTTP/1.1", 404, 1, 1.0, "", "ua\" rid=x site=y \\ \n", "", "", false, "", "s")
	b, _ := os.ReadFile(f)
	line := strings.TrimRight(string(b), "\n")
	want := `1.2.3.4 - h "GET /x\x22 200 1 1.0ms -> fake \x22ua\x5C HTTP/1.1" 404 1 1.000ms -> - "ua\x22 rid=x site=y \x5C \n" fetch_site=- fetch_dest=- scheme=http rid=- gw=gw1 site=s`
	if line != want {
		t.Fatalf("line\n got %s\nwant %s", line, want)
	}
}
