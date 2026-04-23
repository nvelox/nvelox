package scripting

import (
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"

	"nvelox/core/logging"
)

func init() {
	logging.Init("debug", "", "")
}

func TestLuaPool_GetPut(t *testing.T) {
	pool := NewLuaPool()

	L := pool.Get()
	if L == nil {
		t.Fatal("expected Lua state")
	}
	pool.Put(L)

	L2 := pool.Get()
	if L2 == nil {
		t.Fatal("expected Lua state from pool")
	}
	pool.Put(L2)
}

func TestRunRequestScript_GetSetHeader(t *testing.T) {
	tmpDir := t.TempDir()
	script := filepath.Join(tmpDir, "test.lua")
	os.WriteFile(script, []byte(`
		local val = nvelox.get_header("X-Test")
		nvelox.set_header("X-Result", val .. "-modified")
	`), 0644)

	pool := NewLuaPool()
	r := httptest.NewRequest("GET", "/", nil)
	r.Header.Set("X-Test", "hello")

	ctx := &RequestContext{Request: r}
	err := RunRequestScript(pool, script, ctx)
	if err != nil {
		t.Fatalf("script error: %v", err)
	}

	if r.Header.Get("X-Result") != "hello-modified" {
		t.Errorf("expected X-Result=hello-modified, got %s", r.Header.Get("X-Result"))
	}
}

func TestRunRequestScript_GetPath(t *testing.T) {
	tmpDir := t.TempDir()
	script := filepath.Join(tmpDir, "path.lua")
	os.WriteFile(script, []byte(`
		local path = nvelox.get_path()
		nvelox.set_header("X-Path", path)
	`), 0644)

	pool := NewLuaPool()
	r := httptest.NewRequest("GET", "/api/users", nil)

	ctx := &RequestContext{Request: r}
	RunRequestScript(pool, script, ctx)

	if r.Header.Get("X-Path") != "/api/users" {
		t.Errorf("expected /api/users, got %s", r.Header.Get("X-Path"))
	}
}

func TestRunRequestScript_Deny(t *testing.T) {
	tmpDir := t.TempDir()
	script := filepath.Join(tmpDir, "deny.lua")
	os.WriteFile(script, []byte(`
		local ip = nvelox.get_client_ip()
		if ip == "192.168.1.1" then
			nvelox.deny(403, "blocked")
		end
	`), 0644)

	pool := NewLuaPool()
	r := httptest.NewRequest("GET", "/", nil)
	r.RemoteAddr = "192.168.1.1:1234"

	ctx := &RequestContext{Request: r}
	RunRequestScript(pool, script, ctx)

	if !ctx.Denied {
		t.Error("expected request to be denied")
	}
	if ctx.DenyStatus != 403 {
		t.Errorf("expected 403, got %d", ctx.DenyStatus)
	}
}

func TestRunRequestScript_SetBackend(t *testing.T) {
	tmpDir := t.TempDir()
	script := filepath.Join(tmpDir, "backend.lua")
	os.WriteFile(script, []byte(`
		local host = nvelox.get_host()
		if host == "special.com" then
			nvelox.set_backend("special-pool")
		end
	`), 0644)

	pool := NewLuaPool()
	r := httptest.NewRequest("GET", "/", nil)
	r.Host = "special.com"

	ctx := &RequestContext{Request: r}
	RunRequestScript(pool, script, ctx)

	if ctx.BackendOverride != "special-pool" {
		t.Errorf("expected special-pool, got %s", ctx.BackendOverride)
	}
}

func TestRunRequestScript_Log(t *testing.T) {
	tmpDir := t.TempDir()
	script := filepath.Join(tmpDir, "log.lua")
	os.WriteFile(script, []byte(`
		nvelox.log("test message from lua")
	`), 0644)

	pool := NewLuaPool()
	r := httptest.NewRequest("GET", "/", nil)

	ctx := &RequestContext{Request: r}
	err := RunRequestScript(pool, script, ctx)
	if err != nil {
		t.Fatalf("script error: %v", err)
	}
	// Test passes if no panic (log message goes to stderr)
}

func TestRunRequestScript_SetPath(t *testing.T) {
	tmpDir := t.TempDir()
	script := filepath.Join(tmpDir, "rewrite.lua")
	os.WriteFile(script, []byte(`
		nvelox.set_path("/rewritten")
	`), 0644)

	pool := NewLuaPool()
	r := httptest.NewRequest("GET", "/original", nil)

	ctx := &RequestContext{Request: r}
	RunRequestScript(pool, script, ctx)

	if r.URL.Path != "/rewritten" {
		t.Errorf("expected /rewritten, got %s", r.URL.Path)
	}
}

func TestRunRequestScript_InvalidScript(t *testing.T) {
	tmpDir := t.TempDir()
	script := filepath.Join(tmpDir, "bad.lua")
	os.WriteFile(script, []byte(`this is not valid lua!!!`), 0644)

	pool := NewLuaPool()
	r := httptest.NewRequest("GET", "/", nil)

	ctx := &RequestContext{Request: r}
	err := RunRequestScript(pool, script, ctx)
	if err == nil {
		t.Error("expected error for invalid Lua script")
	}
}

func TestLoadScript_Valid(t *testing.T) {
	tmpDir := t.TempDir()
	script := filepath.Join(tmpDir, "valid.lua")
	os.WriteFile(script, []byte(`local x = 1 + 1`), 0644)

	pool := NewLuaPool()
	err := pool.LoadScript(script)
	if err != nil {
		t.Errorf("expected no error, got: %v", err)
	}
}

func TestLoadScript_Invalid(t *testing.T) {
	tmpDir := t.TempDir()
	script := filepath.Join(tmpDir, "bad.lua")
	os.WriteFile(script, []byte(`function(`), 0644)

	pool := NewLuaPool()
	err := pool.LoadScript(script)
	if err == nil {
		t.Error("expected error for invalid script")
	}
}
