//go:build linux

package httpproxy

import (
	"bytes"
	"context"
	"net"
	"net/http"
	"testing"
	"time"

	"github.com/nvelox/ngx/h3"
	"github.com/quic-go/quic-go"

	"nvelox/config"
)

// A connection that serves nothing is closed when its idle time is over,
// whatever its client leaves open in the transport: a stream it never
// sent a request on (a stream's number opens every lower one), or a
// stream whose answer it never acknowledges. And a client that is still
// taking an answer gets all of it.

// h3IdleTimes are the times of the listeners of these tests.
func h3IdleTimes(l *ListenerConfig) {
	l.Timeouts = config.TimeoutConfig{ReadHeader: "300ms", Idle: "600ms"}
}

// h3Awake opens a QUIC connection over pc that keeps the transport awake
// with a PING ten times a second and speaks HTTP/3 as far as the test
// writes it (its control stream with an empty SETTINGS frame is sent).
func h3Awake(t *testing.T, pc net.PacketConn, addr string, pki *caPKI, conf *quic.Config) *quic.Conn {
	t.Helper()
	raddr, err := net.ResolveUDPAddr("udp", addr)
	if err != nil {
		t.Fatal(err)
	}
	if conf == nil {
		conf = &quic.Config{}
	}
	conf.KeepAlivePeriod, conf.MaxIdleTimeout = 100*time.Millisecond, 30*time.Second
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	tr := &quic.Transport{Conn: pc}
	t.Cleanup(func() { tr.Close() })
	conn, err := tr.Dial(ctx, raddr, h3ClientTLS(pki), conf)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { conn.CloseWithError(0, "") })
	ctrl, err := conn.OpenUniStream()
	if err != nil {
		t.Fatal(err)
	}
	ctrl.Write([]byte{h3.StreamControl, h3.FrameSettings, 0})
	return conn
}

func h3ClientSocket(t *testing.T) net.PacketConn {
	t.Helper()
	pc, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { pc.Close() })
	return pc
}

// An answer after which the connection is done (its backend said so) is
// read to its end by the client, also when that end comes by itself, the
// last of the answer's bytes having been acknowledged before; then the
// connection closes.
func TestH3Loops_EndOfTheLastAnswerIsDelivered(t *testing.T) {
	page := bytes.Repeat([]byte("z"), 64<<10)
	addr, _, pki := startH3Loops(t, func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Connection", "close") // the connection is done after this answer
		w.Write(page)
		w.(http.Flusher).Flush()
		time.Sleep(300 * time.Millisecond) // the client has all of it; then it ends
	}, h3IdleTimes)
	quietLog(t)
	conn := h3Awake(t, h3ClientSocket(t), addr, pki, nil)
	for i := 0; i < 3 && conn.Context().Err() == nil; i++ {
		str, err := conn.OpenStream()
		if err != nil {
			t.Fatal(err)
		}
		str.SetDeadline(time.Now().Add(10 * time.Second))
		str.Write(h3HeadersFrame(h3GetFields...))
		str.Close()
		var pending, body []byte
		if status := h3Answer(t, str, &pending, &body); status != "200" || !bytes.Equal(body, page) {
			t.Fatalf("answer %d: status %q, %d of %d bytes; the stream did not come to its end", i+1, status, len(body), len(page))
		}
		if i == 0 {
			// It was the connection's last: no request after it is served.
			if code := connCode(t, conn); code != int64(h3.ErrNoError) {
				t.Errorf("the connection ended with %#x, want H3_NO_ERROR", code)
			}
		}
	}
}
