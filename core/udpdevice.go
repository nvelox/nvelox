package core

import (
	"fmt"
	"net"
	"runtime"
	"strconv"
	"strings"

	"nvelox/core/logging"
)

// accept_proxy_interfaces: a UDP listener trusts a peer's PROXY header only
// on datagrams that arrived on one of the listed network interfaces. A
// datagram's destination address does not say where a packet from the network
// arrived (Linux accepts packets for any local address on any interface), so
// each listed interface gets sockets bound to it (SO_BINDTODEVICE): the kernel
// hands them only packets that arrived on that interface. Those sockets run in
// a UDP engine of their own, whose sessions are known to have arrived on a
// listed interface; a datagram claiming a relay's source address that arrives
// elsewhere lands on the listener's ordinary socket and is a direct client.
//
// The interface-bound sockets and the listener's own socket share the port
// (SO_REUSEADDR), and Linux lets any program on the machine bind a UDP port
// shared that way: the docs ask for a privileged port or a machine (container,
// VM) of nvelox's own.

// udpInterfacePlan is what planUDPInterfaces decides at startup.
type udpInterfacePlan struct {
	deviceAddrs []string          // interface-bound sockets (the interface engine)
	deviceOf    map[string]string // their local address -> interface name
	sharedPorts map[int]bool      // ports whose sockets share the port (SO_REUSEADDR)
	onDevice    map[string]bool   // listener addresses whose own socket is interface-bound
}

// planUDPInterfaces plans the sockets of every udp listener with
// accept_proxy_interfaces. A wildcard listener keeps its ordinary socket and
// gets one interface-bound socket per address of each interface (IPv6
// link-local excepted); a listener bound to one address binds its own socket
// to the interface that carries it.
func (e *Engine) planUDPInterfaces() (*udpInterfacePlan, error) {
	p := &udpInterfacePlan{deviceOf: map[string]string{}, sharedPorts: map[int]bool{}, onDevice: map[string]bool{}}
	for _, l := range e.Listeners {
		if l.Protocol != "udp" || len(l.proxyInterfaces) == 0 {
			continue
		}
		if runtime.GOOS != "linux" {
			return nil, fmt.Errorf("listener %s: accept_proxy_interfaces is supported on Linux only", l.Name)
		}
		host, portStr, err := net.SplitHostPort(l.Addr)
		if err != nil {
			return nil, fmt.Errorf("listener %s: %v", l.Name, err)
		}
		port, err := strconv.Atoi(portStr)
		if err != nil {
			return nil, fmt.Errorf("listener %s: port %q", l.Name, portStr)
		}
		bindIP := net.ParseIP(host)
		wildcard := host == "" || (bindIP != nil && bindIP.IsUnspecified())
		matched := false
		for _, name := range l.proxyInterfaces {
			ifi, err := net.InterfaceByName(name)
			if err != nil {
				return nil, fmt.Errorf("listener %s: accept_proxy_interfaces %q: %v", l.Name, name, err)
			}
			addrs, err := ifi.Addrs()
			if err != nil {
				return nil, fmt.Errorf("listener %s: accept_proxy_interfaces %q: %v", l.Name, name, err)
			}
			usable := 0
			for _, a := range addrs {
				ipn, ok := a.(*net.IPNet)
				if !ok || (ipn.IP.To4() == nil && ipn.IP.IsLinkLocalUnicast()) {
					continue
				}
				switch {
				case wildcard:
					ua := (&net.UDPAddr{IP: ipn.IP, Port: port}).String()
					p.deviceOf[ua] = name
					p.deviceAddrs = append(p.deviceAddrs, ua)
					usable++
				case ipn.IP.Equal(bindIP):
					ua := (&net.UDPAddr{IP: bindIP, Port: port}).String()
					p.deviceOf[ua] = name
					p.deviceAddrs = append(p.deviceAddrs, ua)
					p.onDevice[l.Addr] = true
					matched = true
					usable++
				}
			}
			if wildcard && usable == 0 {
				return nil, fmt.Errorf("listener %s: accept_proxy_interfaces %q has no usable address", l.Name, name)
			}
		}
		if !wildcard && !matched {
			return nil, fmt.Errorf("listener %s: binds %s, which none of accept_proxy_interfaces carries", l.Name, host)
		}
		p.sharedPorts[port] = true
		if own := trustedOwnAddresses(l.proxyTrust, localAddrs()); len(own) > 0 {
			logging.Warn("[CONFIG] WARNING: listener %s: accept_proxy_from includes this machine's own address %s; a program on this machine can send from it, and its datagram counts as arriving on the interface that has the address: keep this machine's addresses out of accept_proxy_from, or use accept_proxy_key_file", l.Name, strings.Join(own, ", "))
		}
	}
	return p, nil
}

// trustedOwnAddresses returns the addresses of this machine (addrs) that
// trust accepts PROXY headers from. A program on this machine can send from
// any of them, and Linux files a datagram to a local address under the
// interface that has the address, so interface trust cannot tell it from a
// relay's.
func trustedOwnAddresses(trust *proxyTrust, addrs []net.Addr) []string {
	var own []string
	for _, a := range addrs {
		ipn, ok := a.(*net.IPNet)
		if !ok {
			continue
		}
		if trust.trusts(&net.UDPAddr{IP: ipn.IP}) {
			own = append(own, ipn.IP.String())
		}
	}
	return own
}

// localAddrs lists this machine's interface addresses (none on error).
func localAddrs() []net.Addr {
	addrs, _ := net.InterfaceAddrs()
	return addrs
}

// listenShared is the ordinary UDP engine's socket factory: a socket on a
// port that interface-bound sockets also use shares it (SO_REUSEADDR).
func (p *udpInterfacePlan) listenShared(network string, laddr *net.UDPAddr) (*net.UDPConn, error) {
	if !p.sharedPorts[laddr.Port] {
		return net.ListenUDP(network, laddr)
	}
	return listenUDPSocket(network, laddr, "")
}

// listenDevice is the interface engine's socket factory.
func (p *udpInterfacePlan) listenDevice(network string, laddr *net.UDPAddr) (*net.UDPConn, error) {
	dev := p.deviceOf[laddr.String()]
	if dev == "" {
		return nil, fmt.Errorf("no interface planned for %s", laddr)
	}
	return listenUDPSocket(network, laddr, dev)
}
