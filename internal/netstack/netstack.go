// Package netstack is the VM's only network: a userspace TCP/IP stack
// (gVisor) attached to the VM's virtio-net device. Every TCP connection the
// guest opens is forwarded exclusively through the upstream proxy. DNS is
// answered locally with fake IPs (names are sent to the proxy unresolved).
// UDP (other than DNS), ICMP to remote hosts and IPv6 are dropped. There is
// no code path that connects anywhere except through upstream.Dialer.
//
// The L2 switch, link endpoint, vfkit transport and DHCP server come from
// containers/gvisor-tap-vsock (Apache-2.0). Its forwarders, DNS server and
// NAT are deliberately NOT used because they connect directly.
package netstack

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"net/netip"
	"strconv"
	"sync"
	"sync/atomic"
	"time"

	"github.com/containers/gvisor-tap-vsock/pkg/services/dhcp"
	"github.com/containers/gvisor-tap-vsock/pkg/tap"
	"github.com/containers/gvisor-tap-vsock/pkg/types"
	"gvisor.dev/gvisor/pkg/tcpip"
	"gvisor.dev/gvisor/pkg/tcpip/adapters/gonet"
	"gvisor.dev/gvisor/pkg/tcpip/network/arp"
	"gvisor.dev/gvisor/pkg/tcpip/network/ipv4"
	"gvisor.dev/gvisor/pkg/tcpip/stack"
	"gvisor.dev/gvisor/pkg/tcpip/transport/icmp"
	"gvisor.dev/gvisor/pkg/tcpip/transport/tcp"
	"gvisor.dev/gvisor/pkg/tcpip/transport/udp"
	"gvisor.dev/gvisor/pkg/waiter"

	"hat/internal/upstream"
)

// Defaults for the virtual network.
const (
	DefaultSubnet     = "192.168.127.0/24"
	DefaultGatewayIP  = "192.168.127.1"
	DefaultGuestIP    = "192.168.127.2"
	DefaultGatewayMAC = "5a:94:ef:e4:0c:dd"
	DefaultMTU        = 1500
)

type Config struct {
	Dialer   upstream.Dialer
	GuestMAC string
	// Optional overrides.
	Subnet, GatewayIP, GuestIP, GatewayMAC string
	MTU                                    int
	// DialTimeout bounds each upstream connection attempt.
	DialTimeout time.Duration
	Logf        func(format string, args ...any)
}

// Stats are counters for diagnostics and `hat check`.
type Stats struct {
	UpstreamOK     atomic.Uint64 // TCP connections established via upstream
	UpstreamFailed atomic.Uint64 // upstream dial failures (connection reset)
	Refused        atomic.Uint64 // refused destinations (private, unmapped fake-ip, ...)
	UDPDropped     atomic.Uint64 // non-DNS UDP flows dropped
	DNSQueries     atomic.Uint64
}

type Stack struct {
	cfg     Config
	s       *stack.Stack
	sw      *tap.Switch
	fake    *FakeIP
	gateway netip.Addr
	guest   netip.Addr
	subnet  netip.Prefix
	Stats   Stats

	// blackhole makes every new connection fail as if the upstream were
	// down (used by `hat check` to verify the kill switch end to end).
	blackhole atomic.Bool

	mu       sync.Mutex
	lastErr  error
	closed   chan struct{}
	closeOne sync.Once
}

func (c *Config) defaults() {
	if c.Subnet == "" {
		c.Subnet = DefaultSubnet
	}
	if c.GatewayIP == "" {
		c.GatewayIP = DefaultGatewayIP
	}
	if c.GuestIP == "" {
		c.GuestIP = DefaultGuestIP
	}
	if c.GatewayMAC == "" {
		c.GatewayMAC = DefaultGatewayMAC
	}
	if c.MTU == 0 {
		c.MTU = DefaultMTU
	}
	if c.DialTimeout == 0 {
		c.DialTimeout = 30 * time.Second
	}
}

// New builds the stack. Attach the VM with AcceptVfkit (or Accept).
func New(cfg Config) (*Stack, error) {
	if cfg.Dialer == nil {
		return nil, errors.New("netstack: upstream dialer is required")
	}
	if cfg.GuestMAC == "" {
		return nil, errors.New("netstack: guest MAC is required")
	}
	cfg.defaults()
	n := &Stack{cfg: cfg, fake: NewFakeIP(FakeIPRange, 0), closed: make(chan struct{})}
	var err error
	if n.subnet, err = netip.ParsePrefix(cfg.Subnet); err != nil {
		return nil, err
	}
	if n.gateway, err = netip.ParseAddr(cfg.GatewayIP); err != nil {
		return nil, err
	}
	if n.guest, err = netip.ParseAddr(cfg.GuestIP); err != nil {
		return nil, err
	}

	ipPool, err := tap.NewIPPool(cfg.Subnet)
	if err != nil {
		return nil, err
	}
	if err := ipPool.Reserve(cfg.GatewayIP, cfg.GatewayMAC); err != nil {
		return nil, err
	}
	if err := ipPool.Reserve(cfg.GuestIP, cfg.GuestMAC); err != nil {
		return nil, err
	}
	link, err := tap.NewLinkEndpoint(false, uint32(cfg.MTU), cfg.GatewayMAC, cfg.GatewayIP, nil)
	if err != nil {
		return nil, err
	}
	n.sw = tap.NewSwitch(false)
	link.Connect(n.sw)
	n.sw.Connect(link)

	s := stack.New(stack.Options{
		NetworkProtocols:   []stack.NetworkProtocolFactory{ipv4.NewProtocol, arp.NewProtocol},
		TransportProtocols: []stack.TransportProtocolFactory{tcp.NewProtocol, udp.NewProtocol, icmp.NewProtocol4},
	})
	if e := s.CreateNIC(1, link); e != nil {
		return nil, errors.New(e.String())
	}
	if e := s.AddProtocolAddress(1, tcpip.ProtocolAddress{
		Protocol:          ipv4.ProtocolNumber,
		AddressWithPrefix: tcpip.AddrFrom4(n.gateway.As4()).WithPrefix(),
	}, stack.AddressProperties{}); e != nil {
		return nil, errors.New(e.String())
	}
	// Accept packets for any destination (the guest's default route points
	// at the gateway) and reply from that destination.
	s.SetSpoofing(1, true)
	s.SetPromiscuousMode(1, true)
	sub, err := tcpip.NewSubnet(tcpip.AddrFrom4(n.subnet.Masked().Addr().As4()),
		tcpip.MaskFromBytes(net.CIDRMask(n.subnet.Bits(), 32)))
	if err != nil {
		return nil, err
	}
	s.SetRouteTable([]tcpip.Route{{Destination: sub, NIC: 1}})
	n.s = s

	tcpFwd := tcp.NewForwarder(s, 0, 1024, n.handleTCP)
	s.SetTransportProtocolHandler(tcp.ProtocolNumber, tcpFwd.HandlePacket)
	udpFwd := udp.NewForwarder(s, n.handleUDP)
	s.SetTransportProtocolHandler(udp.ProtocolNumber, udpFwd.HandlePacket)
	// No ICMP handler: echo requests to remote hosts are dropped.

	dhcpServer, err := dhcp.New(&types.Configuration{
		Subnet: cfg.Subnet, GatewayIP: cfg.GatewayIP, MTU: cfg.MTU,
	}, s, ipPool)
	if err != nil {
		return nil, fmt.Errorf("dhcp: %w", err)
	}
	go func() {
		if err := dhcpServer.Serve(); err != nil {
			n.logf("dhcp server stopped: %v", err)
		}
	}()
	return n, nil
}

func (n *Stack) logf(format string, args ...any) {
	if n.cfg.Logf != nil {
		n.cfg.Logf(format, args...)
	}
}

// AcceptVfkit attaches a VM connected through vfkit's unixgram socket. It
// blocks until the connection ends.
func (n *Stack) AcceptVfkit(ctx context.Context, conn net.Conn) error {
	return n.sw.Accept(ctx, conn, types.VfkitProtocol)
}

// Accept attaches a raw-frame datagram connection (one Ethernet frame per
// datagram, e.g. a SOCK_DGRAM socketpair).
func (n *Stack) Accept(ctx context.Context, conn net.Conn) error {
	return n.sw.Accept(ctx, conn, types.VfkitProtocol)
}

// DialGuest connects from the host to a TCP port on the guest (e.g. sshd).
// This traffic stays inside the virtual network.
func (n *Stack) DialGuest(ctx context.Context, port int) (net.Conn, error) {
	return gonet.DialContextTCP(ctx, n.s, tcpip.FullAddress{
		NIC: 1, Addr: tcpip.AddrFrom4(n.guest.As4()), Port: uint16(port),
	}, ipv4.ProtocolNumber)
}

// SetBlackhole enables or disables the kill-switch test mode.
func (n *Stack) SetBlackhole(on bool) { n.blackhole.Store(on) }

// GuestIP returns the guest's address.
func (n *Stack) GuestIP() string { return n.guest.String() }

// LastError returns the last upstream failure.
func (n *Stack) LastError() error {
	n.mu.Lock()
	defer n.mu.Unlock()
	return n.lastErr
}

// Close stops the stack.
func (n *Stack) Close() {
	n.closeOne.Do(func() {
		close(n.closed)
		n.s.Close()
	})
}

// Target resolves where a guest TCP connection should go. ok=false means
// the destination is refused.
func (n *Stack) Target(dst netip.Addr, port uint16) (string, bool) {
	p := strconv.Itoa(int(port))
	switch {
	case n.fake.Contains(dst):
		name, ok := n.fake.Lookup(dst)
		if !ok {
			return "", false // stale or guessed fake IP
		}
		return net.JoinHostPort(name, p), true
	case n.subnet.Contains(dst), upstream.IsLocalHost(dst.String()):
		return "", false // gateway, host side, private networks, metadata services
	default:
		return net.JoinHostPort(dst.String(), p), true
	}
}

func (n *Stack) handleTCP(r *tcp.ForwarderRequest) {
	id := r.ID()
	dst, _ := netip.AddrFromSlice(id.LocalAddress.AsSlice())
	dst = dst.Unmap()

	if id.LocalPort == 53 && (dst == n.gateway || !n.subnet.Contains(dst)) {
		n.serveDNSOverTCP(r)
		return
	}
	target, ok := n.Target(dst, id.LocalPort)
	if !ok {
		n.Stats.Refused.Add(1)
		n.logf("refused tcp %s:%d", dst, id.LocalPort)
		r.Complete(true) // RST
		return
	}
	var up net.Conn
	var err error
	if n.blackhole.Load() {
		err = errors.New("kill-switch test: upstream treated as unreachable")
	} else {
		ctx, cancel := context.WithTimeout(context.Background(), n.cfg.DialTimeout)
		up, err = n.cfg.Dialer.DialContext(ctx, "tcp", target)
		cancel()
	}
	if err != nil {
		n.Stats.UpstreamFailed.Add(1)
		n.mu.Lock()
		n.lastErr = err
		n.mu.Unlock()
		n.logf("%s: %v (blocked, no direct connection)", target, err)
		r.Complete(true) // RST: kill switch
		return
	}
	var wq waiter.Queue
	ep, tcpErr := r.CreateEndpoint(&wq)
	r.Complete(false)
	if tcpErr != nil {
		up.Close()
		return
	}
	n.Stats.UpstreamOK.Add(1)
	pipe(gonet.NewTCPConn(&wq, ep), up)
}

func (n *Stack) handleUDP(r *udp.ForwarderRequest) bool {
	id := r.ID()
	if id.LocalPort != 53 {
		n.Stats.UDPDropped.Add(1)
		return true // handled = dropped
	}
	var wq waiter.Queue
	ep, tcpErr := r.CreateEndpoint(&wq)
	if tcpErr != nil {
		return true
	}
	conn := gonet.NewUDPConn(&wq, ep)
	go func() {
		defer conn.Close()
		buf := make([]byte, 4096)
		for {
			conn.SetReadDeadline(time.Now().Add(30 * time.Second))
			nr, err := conn.Read(buf)
			if err != nil {
				return
			}
			n.Stats.DNSQueries.Add(1)
			resp, err := AnswerDNS(n.fake, buf[:nr])
			if err != nil {
				continue
			}
			conn.Write(resp)
		}
	}()
	return true
}

func (n *Stack) serveDNSOverTCP(r *tcp.ForwarderRequest) {
	var wq waiter.Queue
	ep, tcpErr := r.CreateEndpoint(&wq)
	r.Complete(false)
	if tcpErr != nil {
		return
	}
	c := gonet.NewTCPConn(&wq, ep)
	defer c.Close()
	for {
		c.SetDeadline(time.Now().Add(30 * time.Second))
		var l [2]byte
		if _, err := io.ReadFull(c, l[:]); err != nil {
			return
		}
		msg := make([]byte, int(l[0])<<8|int(l[1]))
		if _, err := io.ReadFull(c, msg); err != nil {
			return
		}
		n.Stats.DNSQueries.Add(1)
		resp, err := AnswerDNS(n.fake, msg)
		if err != nil {
			return
		}
		out := append([]byte{byte(len(resp) >> 8), byte(len(resp))}, resp...)
		if _, err := c.Write(out); err != nil {
			return
		}
	}
}

func pipe(a, b net.Conn) {
	var wg sync.WaitGroup
	wg.Add(2)
	cp := func(dst, src net.Conn) {
		defer wg.Done()
		io.Copy(dst, src)
		if cw, ok := dst.(interface{ CloseWrite() error }); ok {
			cw.CloseWrite()
		} else {
			dst.Close()
		}
	}
	go cp(a, b)
	go cp(b, a)
	wg.Wait()
	a.Close()
	b.Close()
}
