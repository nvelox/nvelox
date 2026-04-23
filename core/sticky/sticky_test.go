package sticky

import (
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

func TestStore_SetGet(t *testing.T) {
	s := NewStore(1 * time.Hour)
	defer s.Stop()

	s.Set("key1", "server1")
	if got := s.Get("key1"); got != "server1" {
		t.Errorf("expected server1, got %s", got)
	}
}

func TestStore_Missing(t *testing.T) {
	s := NewStore(1 * time.Hour)
	defer s.Stop()

	if got := s.Get("missing"); got != "" {
		t.Errorf("expected empty, got %s", got)
	}
}

func TestStore_Expiry(t *testing.T) {
	s := NewStore(100 * time.Millisecond)
	defer s.Stop()

	s.Set("key", "server")

	if s.Get("key") == "" {
		t.Error("expected session before expiry")
	}

	time.Sleep(200 * time.Millisecond)

	if s.Get("key") != "" {
		t.Error("expected empty after expiry")
	}
}

func TestStore_Refresh(t *testing.T) {
	s := NewStore(200 * time.Millisecond)
	defer s.Stop()

	s.Set("key", "server")
	time.Sleep(100 * time.Millisecond)
	s.Get("key") // refresh

	time.Sleep(150 * time.Millisecond)
	if s.Get("key") == "" {
		t.Error("expected session alive after refresh")
	}
}

func TestKeyFromCookie(t *testing.T) {
	r := httptest.NewRequest("GET", "/", nil)
	r.AddCookie(&http.Cookie{Name: "SRV", Value: "abc123"})

	if got := KeyFromCookie(r, "SRV"); got != "abc123" {
		t.Errorf("expected abc123, got %s", got)
	}
	if got := KeyFromCookie(r, "MISSING"); got != "" {
		t.Errorf("expected empty for missing cookie, got %s", got)
	}
}

func TestKeyFromIPHash(t *testing.T) {
	r := httptest.NewRequest("GET", "/", nil)
	r.RemoteAddr = "192.168.1.1:12345"

	key1 := KeyFromIPHash(r)
	key2 := KeyFromIPHash(r)

	if key1 == "" {
		t.Error("expected non-empty hash")
	}
	if key1 != key2 {
		t.Error("expected same hash for same IP")
	}

	r.RemoteAddr = "192.168.1.2:12345"
	key3 := KeyFromIPHash(r)
	if key1 == key3 {
		t.Error("expected different hash for different IP")
	}
}

func TestServerToToken(t *testing.T) {
	t1 := ServerToToken("10.0.0.1:80")
	t2 := ServerToToken("10.0.0.2:80")

	if t1 == t2 {
		t.Error("expected different tokens for different servers")
	}
	if len(t1) != 16 {
		t.Errorf("expected 16 char token, got %d", len(t1))
	}
}
