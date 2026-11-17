//go:build linux

package httpproxy

// QUIC on the event loops. The transport itself is ngx/quic, which does no
// I/O: this file gives it sockets, a clock and timers.
//
// A server has one UDP socket per loop, all bound to its address with
// SO_REUSEPORT. The kernel gives the datagrams of one client address to one
// of those sockets, always the same one, so a connection lives on one loop:
// its socket's. Only that loop's goroutine touches it, as with the TCP
// connections of the fast path, and nothing is locked.
//
// A pass of a loop reads what its sockets hold (recvmmsg) and hands every
// datagram to its connection. At the end of the pass each connection that
// was touched is asked for what it has to send, which leaves in as few
// system calls as there are batches (sendmmsg), and its timer is set to
// what it waits for next.
//
// A client's first packet is taken on trust while few handshakes are
// running: the handshake itself proves the address. Once more of them than
// quicRetryAfter are unproven, a new client is first sent back with a
// token (a Retry packet, which costs no state and is shorter than what it
// answers) and is served when it returns with it, from the same address.
//
// A handshake runs on a goroutine of its own (runHandshake): its
// cryptography, a signature above all, takes a good part of a millisecond,
// which a loop cannot spend per new client while it serves the others.
// The loop passes the connection's datagrams to that goroutine and takes
// the connection over when the handshake is complete.
//
// A client's address can change under it (a NAT that maps its flow anew),
// and a client can move on purpose (another network). Its datagrams then
// come from an address the connection does not send to, and may reach
// another loop's socket, which passes them on to the loop that has the
// connection (passOn). What they hold is served; the connection sends to
// the new address once the client has answered a challenge sent there
// (recvOther), and never before: a datagram with a made-up source address
// moves no connection. For a move on purpose a client needs connection IDs
// it has not used yet: it is given spare ones when the handshake is
// complete, and a new one for each it gives back (syncCIDs).
//
// A server whose listener trusts UDP relays (h3relay.go) takes a datagram
// from one only with the relay's signed header, which names the client the
// relay's socket stands for. The header is taken off before anything else
// looks at the datagram (incoming); the connection's peer is the relay's
// socket, where its answers go, and its client is the one the relay named.
//
// Still to come: nothing is answered to a datagram of a connection that is
// gone (no stateless reset).

import (
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/binary"
	"fmt"
	"net"
	"net/netip"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"time"
	"unsafe"

	"nvelox/config"
	"nvelox/core/logging"
	"nvelox/proxy"

	"github.com/nvelox/ngx"
	"github.com/nvelox/ngx/quic"
	"golang.org/x/sys/unix"
)

const (
	quicBatch    = 64                   // datagrams per recvmmsg and per sendmmsg call
	quicRecvSize = 2048                 // room for a received datagram, and what clients are told is the largest they may send
	quicSendSize = quic.MaxDatagramSize // room for a datagram to send
	quicRounds   = 16                   // receive batches per readiness pass: a busy socket gives way to the loop's other work
	quicCtlSize  = 64                   // room for the control message that names the local address of a datagram

	// quicHandshakeQueue is how many datagrams wait for a handshake's
	// goroutine; more are dropped, and the client sends them again.
	quicHandshakeQueue = 16
)

// quicMaxHandshakes bounds, on each loop, the connections whose handshake
// is not complete: every one holds TLS state for a client that has not
// proven its address yet. Past it, the first packets of new clients are
// dropped; a client sends them again. quicHandshakeTimeout is how long a
// handshake may take. Variables for the tests only.
var (
	quicMaxHandshakes    = 4096
	quicHandshakeTimeout = 10 * time.Second
)

// quicRetryAfter is how many handshakes of a server may run with a client
// whose address is not proven before new clients are asked to prove
// theirs first (a Retry), and quicTokenAge how long such a client has to
// come back. The first is the number the quic-go server uses. A variable
// for the tests only.
var quicRetryAfter = 128

const quicTokenAge = 10 * time.Second

// quicPaths is how many other addresses of its client a connection looks
// at, at a time: each is sent a challenge, a full-size datagram, so a
// connection whose packets are copied and sent on from made-up addresses
// challenges no more of them than that; quicPathIdle is how long nothing
// must have come from one of them before it gives way to a new one. Both
// are the quic-go server's.
const (
	quicPaths    = 3
	quicPathIdle = 5 * time.Second
)

var quicNameSize = uint32(unsafe.Sizeof(unix.RawSockaddrInet6{}))

// quicSendMemory is how much the QUIC connections of the process may hold
// together that their clients have not acknowledged. Past it a connection
// holds little more than a few packets at a time (ngx/quic, the send
// buffer): clients that ask for much and take nothing do not get to fill
// the machine. The same amount again is what the connections may be
// granted together beyond their first receive windows (ngx/quic, the
// receive windows): clients that upload to backends which take nothing do
// not get to fill it either.
func quicSendMemory() int64 { return sendMemoryOf(machineMemory(), memoryLimits()) }

// sendMemoryOf is an eighth of the memory a process may use: the
// machine's (total), or the lowest of its control groups' limits when
// that is lower; and 64 MiB at the least.
func sendMemoryOf(total int64, limits []int64) int64 {
	for _, l := range limits {
		if l > 0 && l < total {
			total = l
		}
	}
	return max(total/8, 64<<20)
}

// machineMemory is the machine's memory (8 GiB when it cannot be told).
func machineMemory() int64 {
	var si unix.Sysinfo_t
	if unix.Sysinfo(&si) == nil && si.Totalram > 0 {
		return int64(si.Totalram) * int64(si.Unit)
	}
	return 8 << 30
}

// memoryLimits returns the memory limits of the control groups the
// process is in: its own group's and those of every group above it (a
// service's MemoryMax, a container's limit), as far as they are set.
func memoryLimits() []int64 {
	var limits []int64
	read := func(file string) {
		b, err := os.ReadFile(file)
		if err != nil {
			return
		}
		if v, err := strconv.ParseInt(strings.TrimSpace(string(b)), 10, 64); err == nil && v > 0 {
			limits = append(limits, v) // "max" does not parse: no limit
		}
	}
	if b, err := os.ReadFile("/proc/self/cgroup"); err == nil {
		for _, line := range strings.Split(string(b), "\n") {
			group, ok := strings.CutPrefix(line, "0::") // version 2
			if !ok {
				continue
			}
			for group != "" && group != "/" && group != "." {
				read(filepath.Join("/sys/fs/cgroup", group, "memory.max"))
				group = filepath.Dir(group)
			}
		}
	}
	read("/sys/fs/cgroup/memory.max")                   // a container's own (version 2)
	read("/sys/fs/cgroup/memory/memory.limit_in_bytes") // version 1
	return limits
}

// quicMemoryOnce: the first server that binds gives the transport its two
// totals as the limits in use have them (a process whose engine gave none:
// the defaults).
var quicMemoryOnce sync.Once

// applyHTTP3Memory gives the QUIC transport the two totals of l
// (server.http3.max_send_memory and max_receive_memory), at once and for
// every connection.
func applyHTTP3Memory(l *config.HTTP3Limits) { setQUICMemory(l) }

// setQUICMemory sets the transport's two totals to those of l, each at
// quicSendMemory where l names none.
func setQUICMemory(l *config.HTTP3Limits) {
	send, receive := l.MaxSendMemory, l.MaxReceiveMemory
	if send <= 0 || receive <= 0 {
		share := quicSendMemory()
		if send <= 0 {
			send = share
		}
		if receive <= 0 {
			receive = share
		}
	}
	quic.SetSendMemory(send)
	quic.SetReceiveMemory(receive)
}

// quicApp is the protocol spoken on the connections of a QUIC server on the
// loops: HTTP/3, or a test's. Its methods, and those of what it returns,
// run on the connection's loop.
type quicApp interface {
	// open is called when the handshake of c is complete, before anything
	// arrives on its streams. What it returns is told about them.
	open(c *qconn) qconnHandler
}

// qconnHandler is told what happens on one connection (quic.Handler, for
// that connection).
type qconnHandler interface {
	streamData(id uint64, data []byte, fin bool)
	streamReset(id uint64, code uint64)
	streamStop(id uint64, code uint64)
	streamWritable(id uint64)
	// inputDone: a datagram of the connection, or its timer, has been
	// dealt with (what it brought was told through the methods above).
	inputDone()
	// moved: the client is at another address now (qconn.client and
	// qconn.local give the new ones).
	moved()
	// closed: the connection is over. err is why (nil when this side
	// closed it without an error).
	closed(err error)
}

// quicLoop is a loop's scratch for QUIC, shared by its sockets: the receive
// batch, the datagrams to send in this pass and the connections to send
// for. Loop goroutine only.
type quicLoop struct {
	l *ngx.Loop

	rmsgs  [quicBatch]ngx.Mmsghdr
	riov   [quicBatch]unix.Iovec
	rnames [quicBatch]unix.RawSockaddrInet6
	rctl   [quicBatch][quicCtlSize]byte
	rbuf   []byte

	// The send batch, all of it for the socket sfd.
	smsgs  [quicBatch]ngx.Mmsghdr
	siov   [quicBatch]unix.Iovec
	snames [quicBatch]unix.RawSockaddrInet6
	sctl   [quicBatch][quicCtlSize]byte
	sbuf   []byte
	sn     int
	sfd    int

	active *qconn // the connections to send for, through qconn.anext
	endIdx int
}

// quicLoopOf returns the QUIC scratch of fl's loop, made on first use.
func quicLoopOf(fl *fastLoop) *quicLoop {
	if fl.quic != nil {
		return fl.quic
	}
	ql := &quicLoop{l: fl.l, sfd: -1}
	ql.rbuf = make([]byte, quicBatch*quicRecvSize)
	ql.sbuf = make([]byte, quicBatch*quicSendSize)
	for i := range ql.rmsgs {
		ql.riov[i].Base = &ql.rbuf[i*quicRecvSize]
		ql.riov[i].SetLen(quicRecvSize)
		m := &ql.rmsgs[i]
		m.Hdr.Iov = &ql.riov[i]
		m.Hdr.SetIovlen(1)
		m.Hdr.Name = (*byte)(unsafe.Pointer(&ql.rnames[i]))
		m.Hdr.Namelen = quicNameSize
		m.Hdr.Control = &ql.rctl[i][0]
		m.Hdr.SetControllen(quicCtlSize)

		ql.siov[i].Base = &ql.sbuf[i*quicSendSize]
		s := &ql.smsgs[i]
		s.Hdr.Iov = &ql.siov[i]
		s.Hdr.SetIovlen(1)
		s.Hdr.Name = (*byte)(unsafe.Pointer(&ql.snames[i]))
	}
	ql.endIdx = fl.l.OnIterationEnd(ql.flush)
	fl.quic = ql
	return ql
}

// flush ends a pass: every connection that was touched sends what it has
// and sets its timer.
func (ql *quicLoop) flush() {
	now := ql.l.Now()
	for ql.active != nil {
		c := ql.active
		ql.active = c.anext
		c.anext, c.queued = nil, false
		c.flush(now)
	}
	ql.write()
}

// write sends the batch. A datagram the socket does not take is dropped:
// to its connection that is a packet lost on the way.
func (ql *quicLoop) write() {
	for off := 0; off < ql.sn; {
		n, errno := ngx.Sendmmsg(ql.sfd, ql.smsgs[off:ql.sn])
		off += n
		switch {
		case errno == 0:
			if n == 0 {
				off = ql.sn
			}
		case errno == unix.EINTR:
		case errno == unix.EAGAIN:
			off = ql.sn // the socket's buffer is full: the rest of the pass is dropped
		default:
			off++ // this one cannot be sent (its address, say): the next ones may
		}
	}
	ql.sn = 0
}

// quicServer is a QUIC listener on the event loops.
type quicServer struct {
	app   quicApp
	cfg   quic.Config
	group *ngx.Group
	local *net.UDPAddr
	// wild: bound to every local address. The address a client sent to is
	// then taken from each first datagram, and answers leave from it.
	wild    bool
	socks   []*quicSock // by loop id
	started atomic.Bool
	closing atomic.Bool
	conns   atomic.Int64 // open connections, handshakes included
	retries atomic.Int64 // clients sent back to prove their address
	moves   atomic.Int64 // connections that followed their client to another address
	passed  atomic.Int64 // datagrams passed on to the loop of their connection
	// owners: the loop of every connection, by its connection ID. A loop
	// asks it only for a datagram that names none of its own connections.
	ownersMu sync.RWMutex
	owners   map[[quic.CIDLen]byte]*quicSock
	// trust, when set, gives the UDP relays the server's listener trusts
	// as they are now (a reload changes them); refused is told of a
	// relay's datagram that is dropped, and why.
	trust   func() *proxy.Trust
	refused func(relay net.Addr, reason string, cause error)
	// The Retry tokens: sealed with a key made when the server binds (a
	// token is only good for seconds, so none outlives a restart), and how
	// many unproven handshakes a loop runs before it asks.
	tokens     cipher.AEAD
	retryAfter int
	// The handshakes' goroutines: hsStop ends them, hsWG waits for them.
	hsStop chan struct{}
	hsWG   sync.WaitGroup
}

// bindQUIC binds addr once per loop for a server of app's protocol. cfg's
// TLS and Params are the connections'; how much a connection may hold to
// send and how far its receive windows grow are server.http3's, as it is
// when the connection opens (quicSock.config). Nothing is read from the
// sockets before serve.
func bindQUIC(addr string, cfg quic.Config, app quicApp) (*quicServer, error) {
	host, _, err := net.SplitHostPort(addr)
	if err != nil {
		return nil, fmt.Errorf("listen udp %s: %w", addr, err)
	}
	qs := &quicServer{app: app, cfg: cfg, group: ngx.Default(), hsStop: make(chan struct{}),
		owners: map[[quic.CIDLen]byte]*quicSock{}}
	var key [32]byte
	rand.Read(key[:])
	block, err := aes.NewCipher(key[:])
	if err != nil {
		return nil, err
	}
	if qs.tokens, err = cipher.NewGCM(block); err != nil {
		return nil, err
	}
	if n := len(qs.group.Loops()); quicRetryAfter > 0 {
		qs.retryAfter = max(1, quicRetryAfter/n)
	}
	qs.cfg.Handler = quicEvents{}
	qs.cfg.Params.MaxUDPPayloadSize = quicRecvSize
	quicMemoryOnce.Do(func() { setQUICMemory(http3Limits()) })
	loops := qs.group.Loops()
	qs.socks = make([]*quicSock, len(loops))
	bind := addr
	asked, least := int(http3Limits().SocketBuffer), 0
	if asked <= 0 {
		asked = config.DefaultHTTP3SocketBuffer // limits that were not resolved from a config
	}
	for i, l := range loops {
		fd, local, got, err := quicListenFD(bind, asked)
		if err != nil {
			qs.closeSockets()
			return nil, err
		}
		if i == 0 || got < least {
			least = got
		}
		if qs.local == nil {
			// The others share the port this one got (":0" in the tests).
			qs.local = local
			qs.wild = local.IP == nil || local.IP.IsUnspecified()
			bind = net.JoinHostPort(host, strconv.Itoa(local.Port))
		}
		if qs.wild {
			// Either fails on a socket of the other family, which then has
			// no use for it.
			_ = unix.SetsockoptInt(fd, unix.IPPROTO_IP, unix.IP_PKTINFO, 1)
			_ = unix.SetsockoptInt(fd, unix.IPPROTO_IPV6, unix.IPV6_RECVPKTINFO, 1)
		}
		qs.socks[l.ID()] = &quicSock{qs: qs, l: l, fd: fd,
			byID: make(map[[quic.CIDLen]byte]*qconn), early: make(map[string]*qconn)}
	}
	if w := quicBufferWarning(qs.local.String(), asked, least); w != "" {
		logging.Warn("%s", w)
	}
	return qs, nil
}

// quicListenFD binds a UDP socket to addr the way net.ListenPacket does (a
// wildcard address gives one socket for IPv4 and IPv6), sharing its port
// (SO_REUSEPORT), and returns it detached from the Go runtime,
// non-blocking. It asks for a receive and a send buffer of buffer bytes;
// the third result is the receive buffer the socket has, as the kernel
// reports it (socketBuffer).
func quicListenFD(addr string, buffer int) (int, *net.UDPAddr, int, error) {
	lc := net.ListenConfig{Control: func(_, _ string, c syscall.RawConn) error {
		var serr error
		if err := c.Control(func(fd uintptr) {
			serr = unix.SetsockoptInt(int(fd), unix.SOL_SOCKET, unix.SO_REUSEPORT, 1)
		}); err != nil {
			return err
		}
		return serr
	}}
	pc, err := lc.ListenPacket(context.Background(), "udp", addr)
	if err != nil {
		return -1, nil, 0, err
	}
	local, _ := pc.LocalAddr().(*net.UDPAddr)
	if local == nil {
		pc.Close()
		return -1, nil, 0, fmt.Errorf("listen udp %s: no local address", addr)
	}
	fd, err := ngx.DetachPacketConn(pc)
	if err != nil {
		return -1, nil, 0, err
	}
	// The buffers server.http3.socket_buffer asks for; and a datagram is
	// never fragmented on its way out (QUIC forbids it). The option of the
	// other family fails and is not needed.
	got := quicSocketBuffer(fd, unix.SO_RCVBUF, unix.SO_RCVBUFFORCE, buffer)
	quicSocketBuffer(fd, unix.SO_SNDBUF, unix.SO_SNDBUFFORCE, buffer)
	_ = unix.SetsockoptInt(fd, unix.IPPROTO_IP, unix.IP_MTU_DISCOVER, unix.IP_PMTUDISC_DO)
	_ = unix.SetsockoptInt(fd, unix.IPPROTO_IPV6, unix.IPV6_MTU_DISCOVER, unix.IPV6_PMTUDISC_DO)
	return fd, local, got, nil
}

// quicSocketBuffer asks the kernel for a buffer of size bytes on the socket
// fd (opt: SO_RCVBUF or SO_SNDBUF; force: its forced form) and returns
// what the socket has then, as the kernel reports it: twice what it
// granted. A variable so that a test can stand in for the kernel.
var quicSocketBuffer = socketBuffer

func socketBuffer(fd, opt, force, size int) int {
	return askBuffer(size,
		func(forced bool) error {
			if forced {
				return unix.SetsockoptInt(fd, unix.SOL_SOCKET, force, size)
			}
			return unix.SetsockoptInt(fd, unix.SOL_SOCKET, opt, size)
		},
		func() int {
			n, _ := unix.GetsockoptInt(fd, unix.SOL_SOCKET, opt)
			return n
		})
}

// askBuffer is the order a socket buffer is asked for in, the quic-go
// server's: the plain request, which the kernel cuts to its limit
// (net.core.rmem_max, wmem_max); then, only if the socket has less than
// was asked for, the forced one, which the kernel grants to a process
// with CAP_NET_ADMIN and refuses to any other. It returns what the socket
// has in the end (get: twice what was granted).
func askBuffer(size int, set func(forced bool) error, get func() int) int {
	_ = set(false)
	got := get()
	if got < 2*size && set(true) == nil {
		got = get()
	}
	return got
}

// quicBufferWarning is the startup warning of a QUIC listener whose
// sockets have a smaller receive buffer than server.http3.socket_buffer
// asks for: "" when they have it. got is what the kernel reports for the
// smallest of them, twice what it granted.
func quicBufferWarning(addr string, asked, got int) string {
	if got >= 2*asked {
		return ""
	}
	return fmt.Sprintf("[HTTP/3] %s: the UDP sockets have a receive buffer of %d KiB, not the %d KiB server.http3.socket_buffer asks for. "+
		"The kernel grants up to net.core.rmem_max, and all of it to a process started with CAP_NET_ADMIN. "+
		"In a small buffer a fast client's datagrams are dropped before nvelox reads them, which slows uploads down", addr, got/2>>10, asked>>10)
}

// serve starts reading the sockets, each on its loop.
func (qs *quicServer) serve() {
	if qs.closing.Load() || !qs.started.CompareAndSwap(false, true) {
		return
	}
	var wg sync.WaitGroup
	for _, s := range qs.socks {
		wg.Add(1)
		s.l.Post(func() {
			defer wg.Done()
			if qs.closing.Load() {
				return
			}
			s.ql = quicLoopOf(fastLoopOf(s.l))
			reg, err := s.l.RegisterRead(s.fd, s)
			if err != nil {
				logging.Error("[HTTP3] %s on loop %d: %v", qs.local, s.l.ID(), err)
				return
			}
			s.reg, s.on = reg, true
		})
	}
	wg.Wait()
}

// stop ends the server: its connections are closed with code (the peers
// are told once) and its sockets given back.
func (qs *quicServer) stop(code uint64, reason string) {
	if !qs.closing.CompareAndSwap(false, true) {
		return
	}
	if qs.started.Load() {
		// No loop begins a handshake after this pass of it (closing is
		// set); then the handshakes' goroutines end, each giving its
		// connection back to its loop before the loop is told to let go
		// of everything.
		var wg sync.WaitGroup
		for _, s := range qs.socks {
			wg.Add(1)
			s.l.Post(wg.Done)
		}
		wg.Wait()
		close(qs.hsStop)
		qs.hsWG.Wait()
		for _, s := range qs.socks {
			wg.Add(1)
			s.l.Post(func() {
				defer wg.Done()
				now := s.l.Now()
				for s.head != nil {
					c := s.head
					if !c.handshaking {
						c.q.Close(now, code, reason)
						c.flush(now) // the close goes into the batch
					}
					if !c.gone {
						c.q.Abandon()
						c.remove()
					}
				}
				if s.ql != nil {
					s.ql.write()
				}
				if s.on {
					s.l.Unregister(s.fd, s.reg)
					s.on = false
				}
			})
		}
		wg.Wait()
	}
	qs.closeSockets()
}

func (qs *quicServer) closeSockets() {
	for _, s := range qs.socks {
		if s != nil && s.fd >= 0 {
			unix.Close(s.fd)
			s.fd = -1
		}
	}
}

// quicSock is one loop's socket of a server, with its connections.
type quicSock struct {
	qs  *quicServer
	l   *ngx.Loop
	ql  *quicLoop
	fd  int
	reg ngx.Reg
	on  bool

	// The connections: by the connection ID this server gave them, and,
	// while a handshake runs, by the one the client made up for its first
	// packets.
	byID       map[[quic.CIDLen]byte]*qconn
	early      map[string]*qconn
	handshakes int
	unproven   int // of them: with a client whose address is not proven yet
	head       *qconn
	// relays: the client each trusted relay socket that sends to this
	// socket stands for (the kernel gives one relay socket's datagrams to
	// one of the server's sockets, always the same).
	relays h3Pins
	// cfg is the configuration of the connections this socket opens: the
	// server's, with the limits of server.http3 as they were at lim.
	cfg *quic.Config
	lim *config.HTTP3Limits
}

// config returns the configuration of a connection opened now: the
// server's, with the limits server.http3 has at this moment. A reload
// that changes them changes them for the connections opened after it; a
// connection keeps the configuration it was opened with.
func (s *quicSock) config() *quic.Config {
	if lim := http3Limits(); lim != s.lim {
		cfg := s.qs.cfg
		cfg.MaxSendBuffer = lim.MaxSendBuffer
		cfg.MaxStreamWindow, cfg.MaxConnWindow = uint64(lim.MaxStreamReceiveWindow), uint64(lim.MaxConnectionReceiveWindow)
		s.cfg, s.lim = &cfg, lim
	}
	return s.cfg
}

// OnEvent reads the socket: batches of datagrams while it has a full one,
// at most quicRounds per pass.
func (s *quicSock) OnEvent(uint32) {
	defer func() {
		if r := recover(); r != nil {
			logLoopPanic("QUIC socket "+s.qs.local.String(), r)
		}
	}()
	ql := s.ql
	for round := 0; round < quicRounds; round++ {
		n, errno := ngx.Recvmmsg(s.fd, ql.rmsgs[:])
		if errno != 0 || n == 0 {
			return
		}
		now := s.l.Now()
		for i := 0; i < n; i++ {
			m := &ql.rmsgs[i]
			namelen, ctllen, flags := m.Hdr.Namelen, int(m.Hdr.Controllen), m.Hdr.Flags
			m.Hdr.Namelen = quicNameSize
			m.Hdr.SetControllen(quicCtlSize)
			if flags&unix.MSG_TRUNC != 0 || ctllen > quicCtlSize {
				continue // longer than any datagram this server allows
			}
			s.incoming(now, &ql.rnames[i], namelen, ql.rctl[i][:ctllen], ql.rbuf[i*quicRecvSize:i*quicRecvSize+int(m.Len)])
		}
		if n < quicBatch {
			return
		}
	}
}

// incoming takes a datagram off the socket. One from a relay the listener
// trusts must begin with the relay's signed header: it is checked and
// taken off, and the client it names goes with the datagram; what does
// not pass is dropped and counted, and nothing else sees it.
func (s *quicSock) incoming(now int64, name *unix.RawSockaddrInet6, namelen uint32, ctl, d []byte) {
	var client netip.AddrPort
	if trust := s.qs.trust; trust != nil {
		if tr := trust(); tr.Enabled() {
			from, ok := sockaddrAddrPort(name)
			if !ok {
				return
			}
			if trustsAddr(tr, from.Addr()) {
				payload, named, reason, cause := h3RelayHeader(tr, d)
				if reason == "" {
					reason, cause = s.relays.pin(from, named, now)
				}
				if reason != "" {
					s.qs.refused(net.UDPAddrFromAddrPort(from), reason, cause)
					return
				}
				d, client = payload, named
			}
		}
	}
	s.datagram(now, name, namelen, ctl, d, client)
}

// datagram hands d to its connection, which a client's first packet opens.
// client is set for a datagram that came through a trusted relay: the
// client the relay named.
func (s *quicSock) datagram(now int64, name *unix.RawSockaddrInet6, namelen uint32, ctl, d []byte, client netip.AddrPort) {
	if len(d) == 0 {
		return
	}
	var c *qconn
	if d[0]&0x80 == 0 {
		// A short header: the connection ID follows the first byte.
		if len(d) < 1+quic.CIDLen {
			return
		}
		if c = s.byID[[quic.CIDLen]byte(d[1:1+quic.CIDLen])]; c == nil {
			s.passOn(name, namelen, ctl, d, client)
			return
		}
	} else {
		h, err := quic.ParseHeader(d, quic.CIDLen)
		if err == quic.ErrVersion {
			s.versionNegotiation(&h, name, namelen, ctl, len(d))
			return
		}
		if err != nil {
			return
		}
		if len(h.DCID) == quic.CIDLen {
			c = s.byID[[quic.CIDLen]byte(h.DCID)]
		}
		if c == nil {
			c = s.early[string(h.DCID)]
		}
		if c == nil {
			if h.Type != quic.PacketInitial || len(d) < quic.MinInitialSize {
				return
			}
			// A token of this server's proves the client's address. Any
			// other token (one an earlier server gave the client, say) is
			// as good as none.
			odcid, proven := s.qs.openToken(h.Token, h.DCID, name, time.Now())
			if !proven && s.unproven >= s.qs.retryAfter {
				s.retry(&h, name, namelen, ctl)
				return
			}
			if c = s.accept(now, &h, name, namelen, ctl, odcid, client); c == nil {
				return
			}
		}
	}
	if !sameSockaddr(&c.name, name) {
		c.recvOther(now, name, namelen, ctl, d, client)
		return
	}
	if client != c.relayed {
		// The relay's socket stands for another client than the one this
		// connection began with (or stopped, or began, being a relay's).
		if s.qs.refused != nil {
			s.qs.refused(net.UDPAddrFromAddrPort(c.peer), h3RelayClientChanged, errH3RelayClientChanged)
		}
		return
	}
	c.recv(now, d)
}

// owner returns the socket, and so the loop, of the connection with the
// connection ID cid: nil when there is none.
func (qs *quicServer) owner(cid [quic.CIDLen]byte) *quicSock {
	qs.ownersMu.RLock()
	o := qs.owners[cid]
	qs.ownersMu.RUnlock()
	return o
}

// passOn hands a datagram that names a connection of another loop to that
// loop. The kernel picks a socket by the client's address, so a client
// whose address has changed may reach any of the server's sockets. Only
// what names a connection that exists is passed on: anything else is
// dropped here, at the price of a look-up.
func (s *quicSock) passOn(name *unix.RawSockaddrInet6, namelen uint32, ctl, d []byte, client netip.AddrPort) {
	o := s.qs.owner([quic.CIDLen]byte(d[1 : 1+quic.CIDLen]))
	if o == nil || o == s {
		return
	}
	s.qs.passed.Add(1)
	from, data := *name, append([]byte(nil), d...)
	var c [quicCtlSize]byte
	n := copy(c[:], ctl)
	o.l.Post(func() { o.datagram(o.l.Now(), &from, namelen, c[:n], data, client) })
}

// The token of a Retry packet: a nonce, then, sealed, when it was made and
// the Destination Connection ID of the client's first packet. It is bound
// to the connection ID the client was told to come back to and to the
// client's address: it opens for nothing else.
const quicTokenNonce = 12

func tokenBinding(dst []byte, cid []byte, name *unix.RawSockaddrInet6) []byte {
	dst = append(dst, cid...)
	if name.Family == unix.AF_INET {
		sa4 := (*unix.RawSockaddrInet4)(unsafe.Pointer(name))
		dst = append(dst, 4)
		dst = append(dst, sa4.Addr[:]...)
	} else {
		dst = append(dst, 6)
		dst = append(dst, name.Addr[:]...)
	}
	p := (*[2]byte)(unsafe.Pointer(&name.Port))
	return append(dst, p[0], p[1])
}

// sealToken makes, at the time at, the token for a client at name whose
// first packet was sent to odcid and who is to come back to cid. nonce is
// random.
func (qs *quicServer) sealToken(nonce, odcid, cid []byte, name *unix.RawSockaddrInet6, at time.Time) []byte {
	var plain [8 + quic.MaxCIDLen]byte
	binary.BigEndian.PutUint64(plain[:], uint64(at.UnixNano()))
	n := 8 + copy(plain[8:], odcid)
	var bind [quic.MaxCIDLen + 19]byte
	token := append(make([]byte, 0, quicTokenNonce+n+16), nonce...)
	return qs.tokens.Seal(token, nonce, plain[:n], tokenBinding(bind[:0], cid, name))
}

// openToken reports whether token is one of this server's, made for a
// client at name that was told to come back to cid, and still fresh at
// the time at. It returns what the client's first packet was sent to.
func (qs *quicServer) openToken(token, cid []byte, name *unix.RawSockaddrInet6, at time.Time) (odcid []byte, ok bool) {
	if len(token) < quicTokenNonce+8+16 || len(token) > quicTokenNonce+8+quic.MaxCIDLen+16 {
		return nil, false
	}
	var bind [quic.MaxCIDLen + 19]byte
	plain, err := qs.tokens.Open(nil, token[:quicTokenNonce], token[quicTokenNonce:], tokenBinding(bind[:0], cid, name))
	if err != nil {
		return nil, false
	}
	age := at.UnixNano() - int64(binary.BigEndian.Uint64(plain))
	if age < 0 || age > int64(quicTokenAge) {
		return nil, false
	}
	return plain[8:], true
}

// retry sends a client back to prove its address: with a token, to a new
// connection ID. Nothing is kept for it.
func (s *quicSock) retry(h *quic.Header, name *unix.RawSockaddrInet6, namelen uint32, ctl []byte) {
	var rnd [quic.CIDLen + quicTokenNonce + 1]byte
	rand.Read(rnd[:])
	cid := rnd[:quic.CIDLen]
	cid[0] = byte(s.l.ID())
	token := s.qs.sealToken(rnd[quic.CIDLen:quic.CIDLen+quicTokenNonce], h.DCID, cid, name, time.Now())
	var buf [160]byte
	pkt := quic.AppendRetry(buf[:0], rnd[len(rnd)-1], h.DCID, h.SCID, cid, token)
	var reply [quicCtlSize]byte
	n := 0
	if s.qs.wild {
		n, _ = replyControl(&reply, ctl)
	}
	// Counted before it leaves: whoever sees the packet finds it counted.
	s.qs.retries.Add(1)
	s.sendNow(name, namelen, reply[:n], pkt)
}

// accept opens the connection of a client's first Initial packet. odcid
// is set for a client that came back with a Retry's token: what its very
// first packet was sent to.
func (s *quicSock) accept(now int64, h *quic.Header, name *unix.RawSockaddrInet6, namelen uint32, ctl []byte, odcid []byte, client netip.AddrPort) *qconn {
	qs := s.qs
	peer, ok := sockaddrAddrPort(name)
	if !ok || qs.closing.Load() || s.handshakes >= quicMaxHandshakes {
		return nil
	}
	c := &qconn{s: s, name: *name, namelen: namelen, peer: peer, relayed: client}
	if qs.wild {
		c.ctllen, c.local = replyControl(&c.ctl, ctl)
	} else if a, ok := netip.AddrFromSlice(qs.local.IP); ok {
		c.local = a.Unmap()
	}
	// The connection ID: its first byte names the loop, the rest is
	// random. The stateless reset token is random too, for now.
	var token [16]byte
	var q *quic.Conn
	var err error
	cfg := s.config() // with the limits server.http3 has now
	if odcid != nil {
		// The ID the Retry gave the client is the connection's.
		if len(h.DCID) != quic.CIDLen || qs.owner([quic.CIDLen]byte(h.DCID)) != nil {
			return nil
		}
		copy(c.cid[:], h.DCID)
		rand.Read(token[:])
		q, err = quic.AcceptRetried(cfg, now, odcid, c.cid[:], h.SCID, token[:])
	} else {
		c.cid, token = s.newCID()
		q, err = quic.Accept(cfg, now, h.DCID, h.SCID, c.cid[:], token[:])
	}
	if err != nil {
		return nil
	}
	q.Data = c
	c.q = q
	c.timer.F = c
	c.handshaking = true
	c.hsBy = now + int64(quicHandshakeTimeout)
	c.register(c.cid)
	if odcid == nil {
		// Until the client has this server's ID, its packets name the one
		// it made up; and its address is not proven yet.
		c.odcid = string(h.DCID)
		s.early[c.odcid] = c
		c.unproven = true
		s.unproven++
	}
	s.handshakes++
	c.lnext = s.head
	if s.head != nil {
		s.head.lprev = c
	}
	s.head = c
	qs.conns.Add(1)
	c.hs = &qhandshake{in: make(chan []byte, quicHandshakeQueue)}
	qs.hsWG.Add(1)
	go c.runHandshake()
	return c
}

// newCID makes up a connection ID for a connection of this socket's, with
// its stateless reset token: the first byte names the loop, the rest is
// random, and no connection of the server has it.
func (s *quicSock) newCID() (cid [quic.CIDLen]byte, token [16]byte) {
	for {
		var rnd [quic.CIDLen + 16]byte
		rand.Read(rnd[:])
		copy(cid[:], rnd[:quic.CIDLen])
		copy(token[:], rnd[quic.CIDLen:])
		cid[0] = byte(s.l.ID())
		if s.qs.owner(cid) == nil {
			return cid, token
		}
	}
}

// register puts a connection ID of c's on the books, unregister takes it
// off (if it is still c's).
func (c *qconn) register(cid [quic.CIDLen]byte) {
	s := c.s
	s.byID[cid] = c
	s.qs.ownersMu.Lock()
	s.qs.owners[cid] = s
	s.qs.ownersMu.Unlock()
}

func (c *qconn) unregister(cid [quic.CIDLen]byte) {
	s := c.s
	if s.byID[cid] != c {
		return
	}
	delete(s.byID, cid)
	s.qs.ownersMu.Lock()
	delete(s.qs.owners, cid)
	s.qs.ownersMu.Unlock()
}

// syncCIDs follows the connection IDs of an established connection: the
// ones the client gave back are taken off the books, and the client is
// given new ones for as many as it may hold.
func (c *qconn) syncCIDs() {
	for {
		cid, ok := c.q.RetiredCID()
		if !ok {
			break
		}
		c.unregister(cid)
		for i := range c.more {
			if c.more[i] == cid {
				c.more = append(c.more[:i], c.more[i+1:]...)
				break
			}
		}
	}
	for n := c.q.WantCIDs(); n > 0; n-- {
		cid, token := c.s.newCID()
		if !c.q.AddCID(cid[:], token[:]) {
			break
		}
		c.register(cid)
		c.more = append(c.more, cid)
	}
}

// qhandshake is a connection's handshake while a goroutine runs it: the
// connection's datagrams, copied, from its loop.
type qhandshake struct {
	in chan []byte
}

// runHandshake runs the connection's handshake, on its own goroutine,
// which alone touches the connection until it gives it back to the loop:
// complete, failed, or given up.
func (c *qconn) runHandshake() {
	s := c.s
	qs := s.qs
	defer qs.hsWG.Done()
	hs := c.hs
	var rest []byte
	defer func() {
		if r := recover(); r != nil {
			logLoopPanic("QUIC handshake with "+c.peer.String(), r)
			func() {
				defer func() { _ = recover() }()
				c.q.Abandon()
			}()
		}
		s.l.Post(func() { c.adopt(hs, rest) })
	}()
	buf := make([]byte, quicSendSize)
	t := time.NewTimer(time.Hour)
	defer t.Stop()
	for {
		now := ngx.Clock()
		for {
			n := c.q.Send(now, buf)
			if n == 0 {
				break
			}
			s.sendNow(&c.name, c.namelen, c.ctl[:c.ctllen], buf[:n])
		}
		if c.q.Closed() || c.q.Established() {
			return
		}
		d := c.q.Deadline()
		if d == 0 || c.hsBy < d {
			d = c.hsBy
		}
		t.Reset(time.Duration(max(d-now, 0)))
		select {
		case dgram := <-hs.in:
			panicProbe("quic-handshake")
			rest = c.q.RecvHandshake(ngx.Clock(), dgram)
		case <-t.C:
			if now = ngx.Clock(); now >= c.hsBy {
				// It took too long: dropped without a word, the client
				// may never have been at the address the packets named.
				c.q.Abandon()
				return
			}
			c.q.OnTimer(now)
		case <-qs.hsStop:
			c.q.Abandon()
			return
		}
	}
}

// adopt takes the connection back from its handshake's goroutine (loop):
// what followed the packet that completed the handshake, and the
// datagrams that came since, are the loop's to serve.
func (c *qconn) adopt(hs *qhandshake, rest []byte) {
	c.hs = nil
	if c.gone {
		return
	}
	defer c.recoverPanic()
	now := c.s.l.Now()
	if len(rest) > 0 {
		c.q.Recv(now, rest)
	}
	for more := true; more; {
		select {
		case d := <-hs.in:
			c.q.Recv(now, d)
		default:
			more = false
		}
	}
	c.after()
}

// versionNegotiation answers a first flight in a version this server does
// not speak with the one it does. Only what is long enough to be a first
// flight is answered, so the answer is never longer than what it answers.
func (s *quicSock) versionNegotiation(h *quic.Header, name *unix.RawSockaddrInet6, namelen uint32, ctl []byte, size int) {
	if size < quic.MinInitialSize {
		return
	}
	var rnd [1]byte
	rand.Read(rnd[:])
	var buf [7 + 2*255 + 4]byte
	pkt := quic.AppendVersionNegotiation(buf[:0], rnd[0], h.DCID, h.SCID)
	var reply [quicCtlSize]byte
	n := 0
	if s.qs.wild {
		n, _ = replyControl(&reply, ctl)
	}
	s.sendNow(name, namelen, reply[:n], pkt)
}

// sendNow sends one datagram outside the pass's batch (answers that belong
// to no connection).
func (s *quicSock) sendNow(name *unix.RawSockaddrInet6, namelen uint32, ctl, d []byte) {
	to := *name
	var iov unix.Iovec
	iov.Base = &d[0]
	iov.SetLen(len(d))
	var m [1]ngx.Mmsghdr
	m[0].Hdr.Name = (*byte)(unsafe.Pointer(&to))
	m[0].Hdr.Namelen = namelen
	m[0].Hdr.Iov = &iov
	m[0].Hdr.SetIovlen(1)
	if len(ctl) > 0 {
		m[0].Hdr.Control = &ctl[0]
		m[0].Hdr.SetControllen(len(ctl))
	}
	ngx.Sendmmsg(s.fd, m[:])
}

// qconn is a QUIC connection on its loop.
type qconn struct {
	s *quicSock
	q *quic.Conn
	h qconnHandler

	// cid is the connection ID the handshake gave the client, more the
	// ones it was given since (syncCIDs).
	cid   [quic.CIDLen]byte
	more  [][quic.CIDLen]byte
	odcid string
	// The address the connection's datagrams come from and go to, and the
	// local one they were sent to. relayed is set when that address is a
	// trusted relay's socket: the client the relay named, whose connection
	// this is (client).
	peer    netip.AddrPort
	relayed netip.AddrPort
	local   netip.Addr
	name    unix.RawSockaddrInet6
	namelen uint32
	// The control message that makes answers leave from that local
	// address (a socket bound to every address).
	ctl    [quicCtlSize]byte
	ctllen int
	// paths: other addresses the client's packets have come from, each
	// asked to prove itself (nil for nearly every connection).
	paths []qpath

	timer ngx.Timer
	// hs is set while the handshake's goroutine has the connection: the
	// loop then touches none of it but hs.
	hs          *qhandshake
	hsBy        int64 // when a handshake still running is given up
	handshaking bool
	unproven    bool // counted among its socket's unproven handshakes
	opened      bool // the application was told of the connection
	queued      bool // in the loop's list of connections to send for
	gone        bool

	anext        *qconn
	lprev, lnext *qconn
}

// client returns whose connection this is: the peer itself, or the client
// a trusted relay named when the peer is that relay's socket.
func (c *qconn) client() netip.AddrPort {
	if c.relayed.IsValid() {
		return c.relayed
	}
	return c.peer
}

// recv takes a datagram for the connection.
func (c *qconn) recv(now int64, d []byte) {
	if hs := c.hs; hs != nil {
		// Its handshake's goroutine has the connection. A full queue is a
		// client sending faster than a handshake goes: dropped.
		select {
		case hs.in <- append([]byte(nil), d...):
		default:
		}
		return
	}
	defer c.recoverPanic()
	c.q.Recv(now, d)
	if c.paths != nil {
		c.pathAnswered()
	}
	c.after()
}

// qpath is another address the packets of a connection's client have come
// from: where it is, the challenge it was sent, and what is known of it.
type qpath struct {
	name    unix.RawSockaddrInet6
	namelen uint32
	ctl     [quicCtlSize]byte
	ctllen  int
	peer    netip.AddrPort
	local   netip.Addr

	challenge [8]byte
	askedAt   int64 // when the challenge was sent
	asked     uint  // how many were
	lastAt    int64 // when a datagram last came from it
	validated bool  // the client answered the challenge: it receives there
	used      bool  // the client sent more than probes from it
	// cid is the client's connection ID that packets to this address name
	// (quic.Conn.PathCID): -1 for the one the connection uses.
	cid int64
	// relayed: the address is a trusted relay's socket, and this is the
	// client it named.
	relayed netip.AddrPort
}

// recvOther takes a datagram that names the connection and came from
// another address than the one the connection sends to. What it holds is
// served, if it is the connection's; the connection goes on sending where
// it did until the client has proven that it receives at the new address.
func (c *qconn) recvOther(now int64, name *unix.RawSockaddrInet6, namelen uint32, ctl, d []byte, client netip.AddrPort) {
	if c.hs != nil || c.handshaking {
		return // a handshake is completed from the address it began at
	}
	defer c.recoverPanic()
	info := c.q.RecvFrom(now, d)
	if !info.Packets {
		return // nothing of the connection's in it: anyone can name a connection
	}
	c.pathAnswered()
	c.otherAddress(now, name, namelen, ctl, &info, client)
	c.after()
}

// pathAnswered notes a challenge the client has answered: the address it
// was sent to is one the client receives at.
func (c *qconn) pathAnswered() {
	data, ok := c.q.PathResponse()
	if !ok {
		return
	}
	for i := range c.paths {
		if p := &c.paths[i]; p.challenge == data {
			p.validated = true
		}
	}
}

// otherAddress follows up a datagram of the connection that came from
// name, an address the connection does not send to. The address is
// challenged the first time, and again when its answer is overdue; a
// challenge of the client's own is answered on that path; and once the
// client has answered and its newest packet came from there with more than
// probes, the connection moves to it.
func (c *qconn) otherAddress(now int64, name *unix.RawSockaddrInet6, namelen uint32, ctl []byte, info *quic.PathInfo, client netip.AddrPort) {
	var p *qpath
	for i := range c.paths {
		if sameSockaddr(&c.paths[i].name, name) {
			p = &c.paths[i]
			break
		}
	}
	var challenge, response *[8]byte
	switch {
	case p == nil:
		if p = c.addPath(now, name, namelen, ctl, info.OtherCID); p == nil {
			return
		}
		challenge = &p.challenge
	case !p.validated && now-p.askedAt >= c.q.ProbeTimeout()<<min(p.asked-1, 6):
		// The challenge or its answer was lost: asked again, with new
		// data, each time after twice as long.
		rand.Read(p.challenge[:])
		p.askedAt = now
		p.asked++
		challenge = &p.challenge
	}
	p.lastAt = now
	p.relayed = client
	p.used = p.used || info.NonProbing
	if info.HasChallenge {
		response = &info.Challenge
	}
	if challenge != nil || response != nil {
		var buf [quicSendSize]byte
		if n := c.q.AppendProbe(buf[:], challenge, response, p.cid); n > 0 {
			c.s.sendNow(&p.name, p.namelen, p.ctl[:p.ctllen], buf[:n])
		}
	}
	if p.validated && p.used && info.Newest {
		c.moveTo(now, p)
	}
}

// addPath notes name as another address of the connection's client, with
// the challenge to send it. With quicPaths of them on the books, the one
// nothing came from for the longest time gives way, if that is
// quicPathIdle or more; else the new address is not looked at for now.
// otherCID: the client is there on purpose, and is answered with a
// connection ID of its own that was not used before; when it has none to
// spare the address is not looked at either.
func (c *qconn) addPath(now int64, name *unix.RawSockaddrInet6, namelen uint32, ctl []byte, otherCID bool) *qpath {
	peer, ok := sockaddrAddrPort(name)
	if !ok {
		return nil
	}
	var p *qpath
	if len(c.paths) >= quicPaths {
		p = &c.paths[0]
		for i := range c.paths {
			if c.paths[i].lastAt < p.lastAt {
				p = &c.paths[i]
			}
		}
		if now-p.lastAt < int64(quicPathIdle) {
			return nil
		}
	}
	cid, ok := c.q.PathCID(otherCID)
	if !ok {
		return nil
	}
	if p == nil {
		c.paths = append(c.paths, qpath{})
		p = &c.paths[len(c.paths)-1]
	} else {
		c.q.DropPathCID(p.cid)
		*p = qpath{}
	}
	p.cid = cid
	p.name, p.namelen, p.peer, p.local = *name, namelen, peer, c.local
	if c.s.qs.wild {
		p.ctllen, p.local = replyControl(&p.ctl, ctl)
	}
	rand.Read(p.challenge[:])
	p.askedAt, p.asked = now, 1
	return p
}

// moveTo makes p the address the connection sends to: the client is there
// now. The other addresses are forgotten (packets that still come from one
// have it looked at anew).
func (c *qconn) moveTo(now int64, p *qpath) {
	c.name, c.namelen, c.ctl, c.ctllen, c.peer, c.local = p.name, p.namelen, p.ctl, p.ctllen, p.peer, p.local
	c.relayed = p.relayed
	cid := p.cid
	for i := range c.paths {
		if o := &c.paths[i]; o != p {
			c.q.DropPathCID(o.cid)
		}
	}
	c.paths = nil
	c.q.Migrated(now, cid)
	c.s.qs.moves.Add(1)
	if h := c.h; h != nil {
		h.moved()
	}
}

// after follows whatever may have changed the connection: a datagram, its
// timer. The application learns of a completed handshake, and the
// connection is looked at when the pass ends.
func (c *qconn) after() {
	if c.unproven && c.q.AddressValidated() {
		c.unproven = false
		c.s.unproven--
	}
	if c.handshaking && c.q.Established() {
		c.handshaking = false
		c.s.handshakes--
		delete(c.s.early, c.odcid)
		c.syncCIDs()
		c.handler()
	} else if c.q.CIDsChanged() {
		c.syncCIDs()
	}
	if h := c.h; h != nil && !c.gone {
		h.inputDone()
	}
	c.wake()
}

// handler returns what handles the connection's streams, asked from the
// application the first time: when the handshake completes, or already at
// the first stream event, which can come in the same datagram.
func (c *qconn) handler() qconnHandler {
	if !c.opened && !c.gone {
		c.opened = true
		c.h = c.s.qs.app.open(c)
	}
	return c.h
}

// wake has the connection looked at when the pass ends: what it has to
// send leaves, and its timer is set again. Whatever changes a connection
// ends with it, the application's writes to its streams included.
func (c *qconn) wake() {
	if c.queued || c.gone {
		return
	}
	c.queued = true
	ql := c.s.ql
	c.anext = ql.active
	ql.active = c
	ql.l.RequestIterationEnd(ql.endIdx)
}

// flush puts what the connection has to send into the pass's batch, then
// sets its timer, or lets go of a connection that is over.
func (c *qconn) flush(now int64) {
	defer c.recoverPanic()
	if c.gone {
		return
	}
	ql := c.s.ql
	for {
		if ql.sn == quicBatch || (ql.sn > 0 && ql.sfd != c.s.fd) {
			ql.write()
		}
		i := ql.sn
		n := c.q.Send(now, ql.sbuf[i*quicSendSize:(i+1)*quicSendSize])
		if n == 0 {
			break
		}
		ql.sfd = c.s.fd
		ql.siov[i].SetLen(n)
		ql.snames[i] = c.name
		m := &ql.smsgs[i]
		m.Hdr.Namelen = c.namelen
		if c.ctllen > 0 {
			ql.sctl[i] = c.ctl
			m.Hdr.Control = &ql.sctl[i][0]
			m.Hdr.SetControllen(c.ctllen)
		} else {
			m.Hdr.Control = nil
			m.Hdr.SetControllen(0)
		}
		ql.sn++
	}
	if c.q.Closed() {
		c.remove()
		return
	}
	d := c.q.Deadline()
	if c.handshaking && (d == 0 || c.hsBy < d) {
		d = c.hsBy
	}
	if d == 0 {
		c.s.l.Stop(&c.timer)
	} else {
		c.s.l.ArmAt(&c.timer, d)
	}
}

// OnTimer: what the connection waited for is due.
func (c *qconn) OnTimer() {
	defer c.recoverPanic()
	if c.gone {
		return
	}
	now := c.s.l.Now()
	if c.handshaking && now >= c.hsBy {
		// A handshake that took too long is dropped without a word: the
		// client may never have been at the address the packets named.
		c.q.Abandon()
	} else {
		c.q.OnTimer(now)
	}
	c.after()
}

// close closes the connection with an application error code.
func (c *qconn) close(code uint64, reason string) {
	if c.gone {
		return
	}
	c.q.Close(c.s.l.Now(), code, reason)
	c.wake()
}

// closeNow closes the connection with an application error code and lets
// go of it at once: the peer is told once, and nothing waits for what it
// may still send (a server that is stopping).
func (c *qconn) closeNow(code uint64, reason string) {
	if c.gone {
		return
	}
	now := c.s.l.Now()
	if !c.handshaking {
		c.q.Close(now, code, reason)
		c.flush(now) // the close goes into the pass's batch
		c.s.ql.l.RequestIterationEnd(c.s.ql.endIdx)
	}
	if !c.gone {
		c.q.Abandon()
		c.remove()
	}
}

// remove lets go of a connection that is over. The application is told
// last, once nothing of the connection is on the books any more.
func (c *qconn) remove() {
	if c.gone {
		return
	}
	c.gone = true
	s := c.s
	s.l.Stop(&c.timer)
	c.unregister(c.cid)
	for _, cid := range c.more {
		c.unregister(cid)
	}
	c.more = nil
	if c.odcid != "" && s.early[c.odcid] == c {
		delete(s.early, c.odcid)
	}
	if c.handshaking {
		c.handshaking = false
		s.handshakes--
	}
	if c.unproven {
		c.unproven = false
		s.unproven--
	}
	if c.lprev != nil {
		c.lprev.lnext = c.lnext
	} else if s.head == c {
		s.head = c.lnext
	}
	if c.lnext != nil {
		c.lnext.lprev = c.lprev
	}
	c.lprev, c.lnext = nil, nil
	s.qs.conns.Add(-1)
	if h := c.h; h != nil {
		c.h = nil
		h.closed(c.q.Err())
	}
}

// recoverPanic ends a connection whose code panicked: that connection
// only. Its loop and the loop's other connections go on.
func (c *qconn) recoverPanic() {
	r := recover()
	if r == nil {
		return
	}
	logLoopPanic("QUIC connection from "+c.peer.String(), r)
	func() {
		defer func() { _ = recover() }()
		c.q.Abandon()
	}()
	func() {
		defer func() { _ = recover() }()
		c.remove()
	}()
	c.gone = true
	c.s.l.Stop(&c.timer)
}

// quicEvents passes the transport's stream events to the handler of the
// connection they happen on.
type quicEvents struct{}

func quicHandlerOf(q *quic.Conn) qconnHandler {
	if c, _ := q.Data.(*qconn); c != nil {
		return c.handler()
	}
	return nil
}

func (quicEvents) StreamData(q *quic.Conn, id uint64, data []byte, fin bool) {
	if h := quicHandlerOf(q); h != nil {
		h.streamData(id, data, fin)
	}
}

func (quicEvents) StreamReset(q *quic.Conn, id uint64, code uint64) {
	if h := quicHandlerOf(q); h != nil {
		h.streamReset(id, code)
	}
}

func (quicEvents) StreamStop(q *quic.Conn, id uint64, code uint64) {
	if h := quicHandlerOf(q); h != nil {
		h.streamStop(id, code)
	}
}

func (quicEvents) StreamWritable(q *quic.Conn, id uint64) {
	if h := quicHandlerOf(q); h != nil {
		h.streamWritable(id)
	}
}

// sockaddrAddrPort returns the address and port in a socket address the
// kernel filled in; an IPv4 peer of a socket for both families as IPv4.
func sockaddrAddrPort(sa *unix.RawSockaddrInet6) (netip.AddrPort, bool) {
	switch sa.Family {
	case unix.AF_INET:
		sa4 := (*unix.RawSockaddrInet4)(unsafe.Pointer(sa))
		p := (*[2]byte)(unsafe.Pointer(&sa4.Port))
		return netip.AddrPortFrom(netip.AddrFrom4(sa4.Addr), uint16(p[0])<<8|uint16(p[1])), true
	case unix.AF_INET6:
		p := (*[2]byte)(unsafe.Pointer(&sa.Port))
		return netip.AddrPortFrom(netip.AddrFrom16(sa.Addr).Unmap(), uint16(p[0])<<8|uint16(p[1])), true
	}
	return netip.AddrPort{}, false
}

// sameSockaddr reports whether two socket addresses name the same peer.
func sameSockaddr(a, b *unix.RawSockaddrInet6) bool {
	if a.Family != b.Family || a.Port != b.Port {
		return false
	}
	if a.Family == unix.AF_INET {
		return (*unix.RawSockaddrInet4)(unsafe.Pointer(a)).Addr == (*unix.RawSockaddrInet4)(unsafe.Pointer(b)).Addr
	}
	return a.Addr == b.Addr && a.Scope_id == b.Scope_id
}

// replyControl reads, from the control messages of a received datagram,
// the local address it was sent to, and writes into dst the control
// message that makes a datagram leave from that address: a server bound to
// every address must answer from the one its client spoke to. It returns
// the message's length (0 when the datagram said nothing) and the address.
func replyControl(dst *[quicCtlSize]byte, ctl []byte) (int, netip.Addr) {
	for len(ctl) >= unix.SizeofCmsghdr {
		h := (*unix.Cmsghdr)(unsafe.Pointer(&ctl[0]))
		l := int(h.Len)
		if l < unix.SizeofCmsghdr || l > len(ctl) {
			break
		}
		data := ctl[unix.CmsgLen(0):l]
		switch {
		case h.Level == unix.IPPROTO_IP && h.Type == unix.IP_PKTINFO && len(data) >= unix.SizeofInet4Pktinfo:
			in := (*unix.Inet4Pktinfo)(unsafe.Pointer(&data[0]))
			out := (*unix.Cmsghdr)(unsafe.Pointer(&dst[0]))
			out.Level, out.Type = unix.IPPROTO_IP, unix.IP_PKTINFO
			out.SetLen(unix.CmsgLen(unix.SizeofInet4Pktinfo))
			*(*unix.Inet4Pktinfo)(unsafe.Pointer(&dst[unix.CmsgLen(0)])) = unix.Inet4Pktinfo{Ifindex: in.Ifindex, Spec_dst: in.Addr}
			return unix.CmsgSpace(unix.SizeofInet4Pktinfo), netip.AddrFrom4(in.Addr)
		case h.Level == unix.IPPROTO_IPV6 && h.Type == unix.IPV6_PKTINFO && len(data) >= unix.SizeofInet6Pktinfo:
			in := (*unix.Inet6Pktinfo)(unsafe.Pointer(&data[0]))
			out := (*unix.Cmsghdr)(unsafe.Pointer(&dst[0]))
			out.Level, out.Type = unix.IPPROTO_IPV6, unix.IPV6_PKTINFO
			out.SetLen(unix.CmsgLen(unix.SizeofInet6Pktinfo))
			*(*unix.Inet6Pktinfo)(unsafe.Pointer(&dst[unix.CmsgLen(0)])) = *in
			return unix.CmsgSpace(unix.SizeofInet6Pktinfo), netip.AddrFrom16(in.Addr).Unmap()
		}
		l = (l + unix.SizeofPtr - 1) &^ (unix.SizeofPtr - 1)
		if l >= len(ctl) {
			break
		}
		ctl = ctl[l:]
	}
	return 0, netip.Addr{}
}
