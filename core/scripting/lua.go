package scripting

import (
	"context"
	"fmt"
	"net"
	"net/http"
	"sync"
	"time"

	"nvelox/core/logging"

	lua "github.com/yuin/gopher-lua"
)

// LuaPool manages a pool of pre-loaded Lua VMs for script execution.
type LuaPool struct {
	pool sync.Pool
	scripts map[string]string // path -> source code
	mu      sync.RWMutex
}

// NewLuaPool creates a sandboxed Lua VM pool.
// Only safe libraries are loaded (string, table, math). The os, io, debug,
// and package modules are NOT available — preventing arbitrary code execution.
func NewLuaPool() *LuaPool {
	return &LuaPool{
		scripts: make(map[string]string),
		pool: sync.Pool{
			New: func() interface{} {
				L := lua.NewState(lua.Options{SkipOpenLibs: true})
				// Only load safe libraries
				lua.OpenBase(L)
				lua.OpenString(L)
				lua.OpenTable(L)
				lua.OpenMath(L)
				// Disable dangerous base functions
				L.SetGlobal("dofile", lua.LNil)
				L.SetGlobal("loadfile", lua.LNil)
				L.SetGlobal("load", lua.LNil)
				L.SetGlobal("rawget", lua.LNil)
				L.SetGlobal("rawset", lua.LNil)
				return L
			},
		},
	}
}

// LoadScript pre-compiles and caches a Lua script from file.
func (p *LuaPool) LoadScript(path string) error {
	p.mu.Lock()
	defer p.mu.Unlock()

	// Verify it compiles
	L := lua.NewState()
	defer L.Close()
	if _, err := L.LoadFile(path); err != nil {
		return fmt.Errorf("lua compile error: %v", err)
	}

	p.scripts[path] = path
	return nil
}

// Get returns a Lua VM from the pool.
func (p *LuaPool) Get() *lua.LState {
	return p.pool.Get().(*lua.LState)
}

// Put returns a Lua VM to the pool.
func (p *LuaPool) Put(L *lua.LState) {
	p.pool.Put(L)
}

// RequestContext holds the request state exposed to Lua scripts.
type RequestContext struct {
	Request     *http.Request
	Writer      http.ResponseWriter
	Denied      bool
	DenyStatus  int
	DenyMessage string
	BackendOverride string
}

// RunRequestScript executes a Lua request script with the given context.
// MaxScriptDuration is the maximum time a Lua script can run before being killed.
const MaxScriptDuration = 5 * time.Second

func RunRequestScript(pool *LuaPool, scriptPath string, ctx *RequestContext) error {
	L := pool.Get()
	defer pool.Put(L)

	// Register the nvelox API module
	registerAPI(L, ctx)

	// Set execution timeout via context
	lctx, cancel := context.WithTimeout(context.Background(), MaxScriptDuration)
	defer cancel()
	L.SetContext(lctx)
	defer L.RemoveContext()

	if err := L.DoFile(scriptPath); err != nil {
		logging.Error("[LUA] Script error in %s: %v", scriptPath, err)
		return err
	}

	return nil
}

// RunResponseScript executes a Lua response script.
func RunResponseScript(pool *LuaPool, scriptPath string, resp *http.Response, r *http.Request) error {
	L := pool.Get()
	defer pool.Put(L)

	// Register response API
	mod := L.NewTable()

	L.SetField(mod, "get_status", L.NewFunction(func(L *lua.LState) int {
		L.Push(lua.LNumber(resp.StatusCode))
		return 1
	}))

	L.SetField(mod, "get_header", L.NewFunction(func(L *lua.LState) int {
		name := L.CheckString(1)
		L.Push(lua.LString(resp.Header.Get(name)))
		return 1
	}))

	L.SetField(mod, "set_header", L.NewFunction(func(L *lua.LState) int {
		name := L.CheckString(1)
		value := L.CheckString(2)
		resp.Header.Set(name, value)
		return 0
	}))

	L.SetField(mod, "log", L.NewFunction(func(L *lua.LState) int {
		msg := L.CheckString(1)
		logging.Info("[LUA] %s", msg)
		return 0
	}))

	L.SetGlobal("nvelox", mod)

	// Set execution timeout
	lctx, cancel := context.WithTimeout(context.Background(), MaxScriptDuration)
	defer cancel()
	L.SetContext(lctx)
	defer L.RemoveContext()

	if err := L.DoFile(scriptPath); err != nil {
		logging.Error("[LUA] Response script error in %s: %v", scriptPath, err)
		return err
	}

	return nil
}

func registerAPI(L *lua.LState, ctx *RequestContext) {
	mod := L.NewTable()

	// nvelox.get_header(name) -> string
	L.SetField(mod, "get_header", L.NewFunction(func(L *lua.LState) int {
		name := L.CheckString(1)
		L.Push(lua.LString(ctx.Request.Header.Get(name)))
		return 1
	}))

	// nvelox.set_header(name, value)
	L.SetField(mod, "set_header", L.NewFunction(func(L *lua.LState) int {
		name := L.CheckString(1)
		value := L.CheckString(2)
		ctx.Request.Header.Set(name, value)
		return 0
	}))

	// nvelox.get_path() -> string
	L.SetField(mod, "get_path", L.NewFunction(func(L *lua.LState) int {
		L.Push(lua.LString(ctx.Request.URL.Path))
		return 1
	}))

	// nvelox.set_path(path)
	L.SetField(mod, "set_path", L.NewFunction(func(L *lua.LState) int {
		path := L.CheckString(1)
		ctx.Request.URL.Path = path
		return 0
	}))

	// nvelox.get_method() -> string
	L.SetField(mod, "get_method", L.NewFunction(func(L *lua.LState) int {
		L.Push(lua.LString(ctx.Request.Method))
		return 1
	}))

	// nvelox.get_client_ip() -> string
	L.SetField(mod, "get_client_ip", L.NewFunction(func(L *lua.LState) int {
		host, _, _ := net.SplitHostPort(ctx.Request.RemoteAddr)
		L.Push(lua.LString(host))
		return 1
	}))

	// nvelox.get_host() -> string
	L.SetField(mod, "get_host", L.NewFunction(func(L *lua.LState) int {
		L.Push(lua.LString(ctx.Request.Host))
		return 1
	}))

	// nvelox.get_query(name) -> string
	L.SetField(mod, "get_query", L.NewFunction(func(L *lua.LState) int {
		name := L.CheckString(1)
		L.Push(lua.LString(ctx.Request.URL.Query().Get(name)))
		return 1
	}))

	// nvelox.deny(status, message)
	L.SetField(mod, "deny", L.NewFunction(func(L *lua.LState) int {
		status := L.CheckInt(1)
		msg := L.OptString(2, "Forbidden")
		ctx.Denied = true
		ctx.DenyStatus = status
		ctx.DenyMessage = msg
		return 0
	}))

	// nvelox.set_backend(name)
	L.SetField(mod, "set_backend", L.NewFunction(func(L *lua.LState) int {
		name := L.CheckString(1)
		ctx.BackendOverride = name
		return 0
	}))

	// nvelox.log(message)
	L.SetField(mod, "log", L.NewFunction(func(L *lua.LState) int {
		msg := L.CheckString(1)
		logging.Info("[LUA] %s", msg)
		return 0
	}))

	L.SetGlobal("nvelox", mod)
}
