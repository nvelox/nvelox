package sni

import (
	"crypto/tls"
	"io"
	"net"
	"strings"
	"time"

	"nvelox/config"
	"nvelox/core/logging"
)

// Router routes TLS connections based on SNI without terminating TLS.
type Router struct {
	routes []route
}

type route struct {
	pattern string // exact hostname or *.example.com
	backend string
}

// NewRouter creates an SNI router from config.
func NewRouter(routes []config.SNIRoute) *Router {
	compiled := make([]route, len(routes))
	for i, r := range routes {
		compiled[i] = route{
			pattern: strings.ToLower(r.ServerName),
			backend: r.Backend,
		}
	}
	return &Router{routes: compiled}
}

// Match returns the backend name for the given SNI server name.
func (r *Router) Match(serverName string) string {
	serverName = strings.ToLower(serverName)
	for _, route := range r.routes {
		if route.pattern == serverName {
			return route.backend
		}
		// Wildcard: *.example.com matches sub.example.com
		if strings.HasPrefix(route.pattern, "*.") {
			suffix := route.pattern[1:] // .example.com
			if strings.HasSuffix(serverName, suffix) && strings.Count(serverName, ".") == strings.Count(suffix, ".") {
				return route.backend
			}
		}
	}
	return ""
}

// ParseClientHello reads a TLS ClientHello from the connection and extracts the SNI.
// Returns the server name and the raw bytes read (to be replayed to the backend).
func ParseClientHello(conn net.Conn) (string, []byte, error) {
	// Read enough for TLS record header + ClientHello
	// TLS record: 5 bytes header + up to 16KB payload
	buf := make([]byte, 16384)
	conn.SetReadDeadline(time.Now().Add(5 * time.Second))
	n, err := conn.Read(buf)
	conn.SetReadDeadline(time.Time{})
	if err != nil {
		return "", nil, err
	}
	data := buf[:n]

	// Use Go's tls package to parse the ClientHello
	var serverName string
	tlsConfig := &tls.Config{
		GetConfigForClient: func(hello *tls.ClientHelloInfo) (*tls.Config, error) {
			serverName = hello.ServerName
			return nil, nil // we don't actually complete the handshake
		},
	}

	// We need to extract SNI from the raw bytes
	// Simple approach: parse TLS record manually for SNI extension
	serverName = extractSNI(data)

	_ = tlsConfig // unused, manual parsing instead

	return serverName, data, nil
}

// extractSNI extracts the SNI from a TLS ClientHello message.
func extractSNI(data []byte) string {
	// TLS record header: type(1) + version(2) + length(2)
	if len(data) < 5 {
		return ""
	}
	if data[0] != 0x16 { // handshake
		return ""
	}
	recordLen := int(data[3])<<8 | int(data[4])
	if len(data) < 5+recordLen {
		return ""
	}

	handshake := data[5 : 5+recordLen]
	if len(handshake) < 4 {
		return ""
	}
	if handshake[0] != 0x01 { // client hello
		return ""
	}

	hsLen := int(handshake[1])<<16 | int(handshake[2])<<8 | int(handshake[3])
	if len(handshake) < 4+hsLen {
		return ""
	}
	hello := handshake[4 : 4+hsLen]

	// Skip: version(2) + random(32) + session_id_len(1) + session_id
	if len(hello) < 35 {
		return ""
	}
	pos := 34
	sessIDLen := int(hello[pos])
	pos += 1 + sessIDLen

	// Skip cipher suites
	if pos+2 > len(hello) {
		return ""
	}
	csLen := int(hello[pos])<<8 | int(hello[pos+1])
	pos += 2 + csLen

	// Skip compression methods
	if pos+1 > len(hello) {
		return ""
	}
	cmLen := int(hello[pos])
	pos += 1 + cmLen

	// Extensions
	if pos+2 > len(hello) {
		return ""
	}
	extLen := int(hello[pos])<<8 | int(hello[pos+1])
	pos += 2

	extEnd := pos + extLen
	if extEnd > len(hello) {
		extEnd = len(hello)
	}

	for pos+4 <= extEnd {
		extType := int(hello[pos])<<8 | int(hello[pos+1])
		extDataLen := int(hello[pos+2])<<8 | int(hello[pos+3])
		pos += 4

		if extType == 0 { // SNI extension
			if pos+2 > extEnd {
				break
			}
			sniListLen := int(hello[pos])<<8 | int(hello[pos+1])
			sniPos := pos + 2
			sniEnd := sniPos + sniListLen
			if sniEnd > extEnd {
				sniEnd = extEnd
			}

			for sniPos+3 <= sniEnd {
				nameType := hello[sniPos]
				nameLen := int(hello[sniPos+1])<<8 | int(hello[sniPos+2])
				sniPos += 3

				if nameType == 0 && sniPos+nameLen <= sniEnd { // hostname
					return string(hello[sniPos : sniPos+nameLen])
				}
				sniPos += nameLen
			}
		}

		pos += extDataLen
	}

	return ""
}

// HandleSNIConnection handles a TLS passthrough connection by peeking at the SNI,
// routing to the backend, and relaying all data bidirectionally.
func HandleSNIConnection(clientConn net.Conn, backendAddr string, initialData []byte) {
	defer clientConn.Close()

	backendConn, err := net.DialTimeout("tcp", backendAddr, 10*time.Second)
	if err != nil {
		logging.Error("[SNI] Backend dial failed for %s: %v", backendAddr, err)
		return
	}
	defer backendConn.Close()

	// Send the initial ClientHello data to backend
	if _, err := backendConn.Write(initialData); err != nil {
		logging.Error("[SNI] Failed to write initial data: %v", err)
		return
	}

	// Bidirectional relay
	done := make(chan struct{})
	go func() {
		io.Copy(clientConn, backendConn)
		close(done)
	}()
	io.Copy(backendConn, clientConn)
	<-done
}
