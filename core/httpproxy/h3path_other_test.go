//go:build !linux

package httpproxy

import "testing"

// quicGoPath: the test is about the quic-go server of HTTP/3. Without
// event loops it is the only one there is.
func quicGoPath(t *testing.T) {}

// onBothH3Servers runs a test of HTTP/3 against each of its servers: here
// the one.
func onBothH3Servers(t *testing.T, test func(t *testing.T)) { test(t) }
