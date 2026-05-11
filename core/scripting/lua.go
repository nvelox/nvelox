package scripting

import (
	"context"
	"fmt"
	"net"
	"net/http"
	"runtime"
	"sync"
	"time"

	"nvelox/core/logging"

	lua "github.com/yuin/gopher-lua"
)

// Script resource limits. gopher-lua doesn't expose a memory-cap hook, so we
// enforce bounds at two layers:
//  1. Replace allocation-amplifying stdlib functions (string.rep) with
//     capped variants — single call bounded.
//  2. Sample the process heap while the script runs; if HeapAlloc grows by
//     more than MaxScriptMemoryGrowth during execution, cancel the context.
const (
	MaxScriptDuration     = 5 * time.Second
	MaxStringRepOutput    = 1 << 20 // 1 MiB cap on string.rep output
	MaxScriptMemoryGrowth = 64 << 20 // 64 MiB heap growth budget per script
	MemoryPollInterval    = 50 * time.Millisecond
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
				installResourceGuards(L)
				return L
			},
		},
	}
}

// installResourceGuards replaces stdlib functions that can amplify small
// inputs into large heap allocations. The 5s timeout alone doesn't help
// against a single O(1)-to-gigabyte call like string.rep(" ", 2^30).
func installResourceGuards(L *lua.LState) {
	strTable := L.GetGlobal("string")
	if strTable == lua.LNil {
		return
	}
	// string.rep(s, n [, sep]) — bound total output to MaxStringRepOutput.
	L.SetField(strTable, "rep", L.NewFunction(func(L *lua.LState) int {
		s := L.CheckString(1)
		n := L.CheckInt(2)
		sep := L.OptString(3, "")
		if n <= 0 {
			L.Push(lua.LString(""))
			return 1
		}
		// Output size = n*len(s) + (n-1)*len(sep). Guard before allocating.
		total := int64(n) * int64(len(s))
		if n > 1 {
			total += int64(n-1) * int64(len(sep))
		}
		if total < 0 || total > int64(MaxStringRepOutput) {
			L.RaiseError("string.rep: output size %d exceeds %d-byte cap", total, MaxStringRepOutput)
			return 0
		}
		// Build the output manually (avoid re-calling the original rep which
		// we've already replaced; just do the repetition in Go).
		buf := make([]byte, 0, int(total))
		for i := 0; i < n; i++ {
			if i > 0 && sep != "" {
				buf = append(buf, sep...)
			}
			buf = append(buf, s...)
		}
		L.Push(lua.LString(string(buf)))
		return 1
	}))
}

// runWithMemoryGuard runs fn on the given state inside a goroutine while a
// second goroutine samples heap growth. If the script runs past the time
// budget OR grows the process heap by more than MaxScriptMemoryGrowth, the
// context is cancelled (gopher-lua checks context on each VM step and
// aborts with an error).
func runWithMemoryGuard(L *lua.LState, fn func() error) error {
	ctx, cancel := context.WithTimeout(context.Background(), MaxScriptDuration)
	defer cancel()
	L.SetContext(ctx)
	defer L.RemoveContext()

	var startMem runtime.MemStats
	runtime.ReadMemStats(&startMem)

	done := make(chan error, 1)
	go func() {
		done <- fn()
	}()

	ticker := time.NewTicker(MemoryPollInterval)
	defer ticker.Stop()

	for {
		select {
		case err := <-done:
			return err
		case <-ticker.C:
			var now runtime.MemStats
			runtime.ReadMemStats(&now)
			// HeapAlloc is monotonic between GC cycles; compare to start.
			// Process-wide measurement means a concurrent goroutine could
			// trigger this — but the budget (64 MiB) is generous enough
			// that false positives on an idle server are unlikely, and
			// a legitimate script doesn't allocate anywhere near that.
			if now.HeapAlloc > startMem.HeapAlloc &&
				now.HeapAlloc-startMem.HeapAlloc > MaxScriptMemoryGrowth {
				cancel()
				<-done // wait for the goroutine to observe cancellation
				return fmt.Errorf("script cancelled: heap growth exceeded %d bytes", MaxScriptMemoryGrowth)
			}
		}
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

// RunRequestScript executes a Lua request script with the given context,
// enforcing both a duration limit (via context) and a heap-growth budget.
func RunRequestScript(pool *LuaPool, scriptPath string, ctx *RequestContext) error {
	L := pool.Get()
	defer pool.Put(L)

	// Register the nvelox API module
	registerAPI(L, ctx)

	err := runWithMemoryGuard(L, func() error {
		return L.DoFile(scriptPath)
	})
	if err != nil {
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

	err := runWithMemoryGuard(L, func() error {
		return L.DoFile(scriptPath)
	})
	if err != nil {
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
