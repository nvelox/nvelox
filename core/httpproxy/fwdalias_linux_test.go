//go:build linux

package httpproxy

import (
	"bufio"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/textproto"
	"strings"
	"testing"
	"time"

	"nvelox/config"
)

// A forwarding header spelled with an underscore is the same variable as
// the real one to a backend that hands headers to its application as
// variables. It does not reach the backend, on either path and from
// trusted peers as well; a header with an underscore that is no
// forwarding header does.
func TestForwardingHeadersWithUnderscoresDoNotReachTheBackend(t *testing.T) {
	aliases := []string{"X_Forwarded_For", "x-forwarded_for", "X-Real_IP", "X_REAL_IP", "X_Forwarded-Proto", "Forwarded_", "X_Forwarded_Host",
		"CF_Connecting_IP", "True_Client_IP", "X_Original_URL", "X_Forwarded_Port"}
	notOne := map[string]bool{"Forwarded_": true} // "Forwarded-" is no header nvelox knows
	for _, trusted := range []bool{false, true} {
		for _, fast := range []bool{false, true} {
			t.Run(fmt.Sprintf("trusted peer %v, loops %v", trusted, fast), func(t *testing.T) {
				be := newRawBackend(t)
				l := &ListenerConfig{Name: "site", Addr: "127.0.0.1:0", Protocol: "http"}
				if trusted {
					l.TrustedProxies = []string{"127.0.0.0/8"}
				}
				quietLog(t)
				addr := startTestGroup(t, fastTestSite(l, &config.Backend{Servers: []string{be.addr()}}), fast)
				c, err := net.Dial("tcp", addr)
				if err != nil {
					t.Fatal(err)
				}
				defer c.Close()
				c.SetDeadline(time.Now().Add(10 * time.Second))
				var req strings.Builder
				req.WriteString("GET /alias HTTP/1.1\r\nHost: x\r\nX-Forwarded-For: 198.51.100.7\r\nX_Custom_Header: stays\r\n")
				for _, name := range aliases {
					req.WriteString(name + ": 203.0.113.66\r\n")
				}
				req.WriteString("\r\n")
				if _, err := io.WriteString(c, req.String()); err != nil {
					t.Fatal(err)
				}
				resp, err := http.ReadResponse(bufio.NewReader(c), nil)
				if err != nil {
					t.Fatal(err)
				}
				io.Copy(io.Discard, resp.Body)
				if resp.StatusCode != 200 {
					t.Fatalf("status %d", resp.StatusCode)
				}
				last := be.last()
				if last == nil {
					t.Fatal("the backend got no request")
				}
				got := last.Header
				for _, name := range aliases {
					v, there := got[textproto.CanonicalMIMEHeaderKey(name)]
					if there != notOne[name] {
						t.Errorf("%s at the backend: %v (%q), want %v", name, there, v, notOne[name])
					}
				}
				if v := got.Get("X_Custom_Header"); v != "stays" {
					t.Errorf("X_Custom_Header at the backend: %q, want it as it was sent", v)
				}
				// The real ones are nvelox's own.
				wantXFF := "127.0.0.1"
				if trusted {
					wantXFF = "198.51.100.7, 127.0.0.1"
				}
				if v := strings.Join(got.Values("X-Forwarded-For"), ", "); v != wantXFF {
					t.Errorf("X-Forwarded-For at the backend: %q, want %q", v, wantXFF)
				}
				for name, v := range got {
					if strings.Contains(strings.Join(v, ","), "203.0.113.66") && name != textproto.CanonicalMIMEHeaderKey("Forwarded_") {
						t.Errorf("the alias's value reached the backend in %s: %q", name, v)
					}
				}
			})
		}
	}
}

// forwardingAlias: only names that have an underscore, and are a
// forwarding header with a hyphen in its place.
func TestForwardingAlias(t *testing.T) {
	for name, want := range map[string]bool{
		"X_Forwarded_For":        true,
		"x_forwarded-for":        true,
		"X-Real_IP":              true,
		"Forwarded":              false, // the header itself
		"X-Forwarded-For":        false,
		"X_Forwarded_Proto":      true,
		"X_Forwarded_Host":       true,
		"X_Forwarded_Prefix":     true,
		"CF_Connecting_IP":       true,
		"X_Custom":               false,
		"X_Forwarded_For_":       false,
		"_Forwarded":             false,
		"Forwarded_":             false,
		strings.Repeat("X_", 40): false,
	} {
		if got := forwardingAlias([]byte(name)); got != want {
			t.Errorf("%q: %v, want %v", name, got, want)
		}
	}
}
