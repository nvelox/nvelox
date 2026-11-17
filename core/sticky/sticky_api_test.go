package sticky

import (
	"net/http"
	"testing"
)

func TestServerForToken(t *testing.T) {
	servers := []string{"10.0.0.1:80", "10.0.0.2:80"}
	if got := ServerForToken(ServerToToken("10.0.0.2:80"), servers); got != "10.0.0.2:80" {
		t.Errorf("ServerForToken = %q", got)
	}
	if got := ServerForToken(ServerToToken("10.0.0.9:80"), servers); got != "" {
		t.Errorf("token of a server outside the pool resolved to %q", got)
	}
	if got := ServerForToken("not-a-token", servers); got != "" {
		t.Errorf("malformed token resolved to %q", got)
	}
}

func TestNewCookie_Attributes(t *testing.T) {
	c := NewCookie("SRV", "10.0.0.1:80", true)
	if c.Value != ServerToToken("10.0.0.1:80") || !c.HttpOnly || !c.Secure || c.SameSite != http.SameSiteLaxMode || c.Path != "/" {
		t.Errorf("cookie %+v", c)
	}
	if NewCookie("SRV", "10.0.0.1:80", false).Secure {
		t.Error("Secure set on a plain-HTTP cookie")
	}
}
