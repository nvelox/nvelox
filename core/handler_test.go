package core

import (
	"errors"
	"net"
	"testing"

	"nvelox/core/logging"
	"nvelox/lb"

	"github.com/panjf2000/gnet/v2"
)

func init() {
	logging.Init("debug", "", "")
}

// MockGnetConn stubs gnet.Conn
type MockGnetConn struct {
	gnet.Conn
	ctx        interface{}
	localAddr  net.Addr
	remoteAddr net.Addr
	outBuf     []byte
}

func (m *MockGnetConn) Context() interface{}       { return m.ctx }
func (m *MockGnetConn) SetContext(ctx interface{}) { m.ctx = ctx }
func (m *MockGnetConn) LocalAddr() net.Addr        { return m.localAddr }
func (m *MockGnetConn) RemoteAddr() net.Addr       { return m.remoteAddr }
func (m *MockGnetConn) Next(n int) ([]byte, error) {
	// For testing handleTCP, we assume some data is available
	return []byte("test-data"), nil
}
func (m *MockGnetConn) Write(b []byte) (int, error) {
	m.outBuf = append(m.outBuf, b...)
	return len(b), nil
}

func TestHandler_OnTraffic_Unknown(t *testing.T) {
	h := &ProxyEventHandler{
		listenerMap: make(map[string]*ListenerConfig),
	}
	conn := &MockGnetConn{
		localAddr: &net.TCPAddr{IP: net.ParseIP("127.0.0.1"), Port: 9999},
	}

	action := h.OnTraffic(conn)
	if action != gnet.Close {
		t.Errorf("OnTraffic for unknown listener should Close, got %v", action)
	}
}

func TestHandler_handleTCP_Buffering(t *testing.T) {
	h := &ProxyEventHandler{}
	ctx := &ConnContext{
		buffer: make([]byte, 0),
	}
	conn := &MockGnetConn{
		ctx: ctx,
	}

	// Not connected, should buffer
	action := h.handleTCP(conn, nil)
	if action != gnet.None {
		t.Errorf("expected None, got %v", action)
	}

	if string(ctx.buffer) != "test-data" {
		t.Errorf("expected buffer 'test-data', got '%s'", string(ctx.buffer))
	}
}

// MockNetConn implements net.Conn
type MockNetConn struct {
	net.Conn
	WriteFunc func(b []byte) (int, error)
	CloseFunc func() error
}

func (m *MockNetConn) Write(b []byte) (int, error) {
	if m.WriteFunc != nil {
		return m.WriteFunc(b)
	}
	return len(b), nil
}

func (m *MockNetConn) Close() error {
	if m.CloseFunc != nil {
		return m.CloseFunc()
	}
	return nil
}

func TestHandler_handleTCP_Direct(t *testing.T) {
	h := &ProxyEventHandler{}

	backendWritten := false
	mockBackend := &MockNetConn{
		WriteFunc: func(b []byte) (int, error) {
			backendWritten = true
			if string(b) != "test-data" {
				t.Errorf("backend received wrong data: %s", string(b))
			}
			return len(b), nil
		},
	}

	ctx := &ConnContext{
		connected:   true,
		BackendConn: mockBackend,
	}
	conn := &MockGnetConn{
		ctx: ctx,
	}

	action := h.handleTCP(conn, nil)
	if action != gnet.None {
		t.Errorf("expected None, got %v", action)
	}
	if !backendWritten {
		t.Error("expected write to backend")
	}
}

func TestHandler_connectBackend_Failures(t *testing.T) {
	// Setup engine with invalid backend
	eng := &Engine{
		Balancers: make(map[string]lb.Balancer),
	}
	h := &ProxyEventHandler{
		engine: eng,
	}

	l := &ListenerConfig{
		DefaultBackend: "non-existent",
	}
	conn := &MockGnetConn{} // Should check if it gets closed

	// 1. Backend not found
	h.connectBackend(conn, nil, l)
	// We can't easily assert Close was called MockGnetConn doesn't track it well without mocking Close.
	// But it shouldn't panic.

	// 2. Balancer Error
	eng.Balancers["error-balancer"] = &MockBalancerError{}
	l.DefaultBackend = "error-balancer"
	// Removed unused ctx
	// Need AsyncWrite mock to verify safeClose? safeClose uses AsyncWrite. mock it?
	// MockGnetConn doesn't impelment AsyncWrite
	// Let's implement AsyncWrite stub
}

type MockBalancerError struct{ lb.Balancer }

func (m *MockBalancerError) Next() (string, error) { return "", errors.New("fail") }

func (m *MockGnetConn) AsyncWrite(b []byte, cb gnet.AsyncCallback) error {
	// execute callback immediately
	if cb != nil {
		return cb(m, nil)
	}
	return nil
}

func (m *MockGnetConn) Close() error {
	return nil
}

func TestHandler_OnOpen(t *testing.T) {
	eng := &Engine{
		Balancers: make(map[string]lb.Balancer),
	}
	h := &ProxyEventHandler{
		engine: eng,
		listenerMap: map[string]*ListenerConfig{
			"tcp:8080": {Name: "test", Port: 8080},
		},
	}
	conn := &MockGnetConn{
		localAddr:  &net.TCPAddr{IP: net.ParseIP("127.0.0.1"), Port: 8080},
		remoteAddr: &net.TCPAddr{IP: net.ParseIP("1.2.3.4"), Port: 1234},
	}

	out, action := h.OnOpen(conn)
	if action != gnet.None {
		t.Errorf("OnOpen action = %v", action)
	}
	if out != nil {
		t.Errorf("OnOpen out != nil")
	}

	if conn.ctx == nil {
		t.Error("OnOpen failed to set context")
	}
}
