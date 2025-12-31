package core

import (
	"net"
	"testing"

	"github.com/panjf2000/gnet/v2"
)

// MockConn implements minimal gnet.Conn interface for testing
type MockConn struct {
	gnet.Conn
	localAddr net.Addr
}

func (m *MockConn) LocalAddr() net.Addr {
	return m.localAddr
}

func TestGetListenerConfig(t *testing.T) {
	// Setup Handler with pre-populated map
	// The map key format is "proto:port"
	handler := &ProxyEventHandler{
		listenerMap: map[string]*ListenerConfig{
			"tcp:8080": {Name: "tcp-8080", Protocol: "tcp", Port: 8080},
			"udp:8080": {Name: "udp-8080", Protocol: "udp", Port: 8080},
			"tcp:9090": {Name: "tcp-9090", Protocol: "tcp", Port: 9090},
		},
	}

	tests := []struct {
		name     string
		addr     net.Addr
		wantName string // Empty if nil expected
	}{
		{
			name:     "TCP 8080",
			addr:     &net.TCPAddr{IP: net.ParseIP("127.0.0.1"), Port: 8080},
			wantName: "tcp-8080",
		},
		{
			name:     "UDP 8080",
			addr:     &net.UDPAddr{IP: net.ParseIP("127.0.0.1"), Port: 8080},
			wantName: "udp-8080",
		},
		{
			name:     "TCP 9090",
			addr:     &net.TCPAddr{IP: net.ParseIP("0.0.0.0"), Port: 9090},
			wantName: "tcp-9090",
		},
		{
			name:     "UDP 9090 (Not Configured)",
			addr:     &net.UDPAddr{IP: net.ParseIP("127.0.0.1"), Port: 9090},
			wantName: "",
		},
		{
			name:     "TCP 8081 (Not Configured)",
			addr:     &net.TCPAddr{IP: net.ParseIP("127.0.0.1"), Port: 8081},
			wantName: "",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			conn := &MockConn{localAddr: tt.addr}
			got := handler.getListenerConfig(conn)

			if tt.wantName == "" {
				if got != nil {
					t.Errorf("getListenerConfig() = %v, want nil", got.Name)
				}
			} else {
				if got == nil {
					t.Errorf("getListenerConfig() = nil, want %v", tt.wantName)
				} else if got.Name != tt.wantName {
					t.Errorf("getListenerConfig() = %v, want %v", got.Name, tt.wantName)
				}
			}
		})
	}
}
