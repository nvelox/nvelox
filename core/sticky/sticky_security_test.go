package sticky

import (
	"crypto/sha256"
	"encoding/hex"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// TestKeyFromCookie_OnlyTokens (M7): the cookie value is accepted only in
// the exact shape ServerToToken produces.
func TestKeyFromCookie_OnlyTokens(t *testing.T) {
	good := ServerToToken("10.0.0.1:80")
	for v, want := range map[string]string{
		good:                       good,
		strings.ToUpper(good):      "",
		good + "0":                 "",
		good[:15]:                  "",
		strings.Repeat("a", 60000): "",
		"zzzzzzzzzzzzzzzz":         "",
	} {
		r := httptest.NewRequest("GET", "/", nil)
		r.AddCookie(&http.Cookie{Name: "SRV", Value: v})
		if got := KeyFromCookie(r, "SRV"); got != want {
			t.Errorf("KeyFromCookie(%.20q) = %q, want %q", v, got, want)
		}
	}
}

func TestKeyFromHeader_HashedAndCapped(t *testing.T) {
	r := httptest.NewRequest("GET", "/", nil)
	r.Header.Set("X-Session", "abc")
	sum := sha256.Sum256([]byte("abc"))
	if got := KeyFromHeader(r, "X-Session"); got != hex.EncodeToString(sum[:]) {
		t.Errorf("KeyFromHeader = %q, want the SHA-256 of the value", got)
	}
	r.Header.Set("X-Session", strings.Repeat("x", 257)) // over the 256-byte cap
	if got := KeyFromHeader(r, "X-Session"); got != "" {
		t.Errorf("over-long header value gave key %q", got)
	}
	r.Header.Del("X-Session")
	if got := KeyFromHeader(r, "X-Session"); got != "" {
		t.Errorf("absent header gave key %q", got)
	}
}
