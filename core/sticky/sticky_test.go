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

// TestEvictOldestLocked_PrefersOldest ensures eviction removes the entries
// with the smallest lastSeen rather than random map-iteration order.
// Without this, an attacker filling the table with fresh sessions could
// DoS legitimate users by evicting their still-active sessions at random.
func TestEvictOldestLocked_PrefersOldest(t *testing.T) {
	s := NewStore(1 * time.Hour)
	defer s.Stop()

	// Insert 5 sessions with monotonically advancing lastSeen.
	// We manipulate lastSeen directly to avoid sleeping.
	s.mu.Lock()
	base := time.Now()
	for i, k := range []string{"a", "b", "c", "d", "e"} {
		s.sessions[k] = &session{
			server:   "srv-" + k,
			lastSeen: base.Add(time.Duration(i) * time.Second),
		}
	}
	s.evictOldestLocked(2)
	s.mu.Unlock()

	// a and b should be gone (oldest); c, d, e should remain.
	if s.Get("a") != "" || s.Get("b") != "" {
		t.Error("expected oldest entries (a,b) to be evicted")
	}
	if s.Get("c") == "" || s.Get("d") == "" || s.Get("e") == "" {
		t.Error("expected newer entries (c,d,e) to survive eviction")
	}
}

// TestEvictOldestLocked_EmptyAndBounds checks the edge cases.
func TestEvictOldestLocked_EmptyAndBounds(t *testing.T) {
	s := NewStore(1 * time.Hour)
	defer s.Stop()

	// Empty store: no panic.
	s.mu.Lock()
	s.evictOldestLocked(5)
	s.mu.Unlock()

	s.Set("k1", "v1")
	// n > map size: must clear the whole map, not panic.
	s.mu.Lock()
	s.evictOldestLocked(100)
	s.mu.Unlock()
	if s.Len() != 0 {
		t.Errorf("expected 0 sessions after oversized evict, got %d", s.Len())
	}

	// n <= 0: no-op.
	s.Set("k2", "v2")
	s.mu.Lock()
	s.evictOldestLocked(0)
	s.mu.Unlock()
	if s.Len() != 1 {
		t.Errorf("n=0 must be a no-op, got %d sessions", s.Len())
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
