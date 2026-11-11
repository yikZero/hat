//go:build linux

package netstack

import (
	"bufio"
	"context"
	"io"
	"net"
	"net/netip"
	"os"
	"strings"
	"syscall"
	"testing"
	"time"

	"golang.org/x/net/dns/dnsmessage"
	"gvisor.dev/gvisor/pkg/tcpip"
	"gvisor.dev/gvisor/pkg/tcpip/adapters/gonet"
	"gvisor.dev/gvisor/pkg/tcpip/header"
	"gvisor.dev/gvisor/pkg/tcpip/link/fdbased"
	"gvisor.dev/gvisor/pkg/tcpip/network/arp"
	"gvisor.dev/gvisor/pkg/tcpip/network/ipv4"
	"gvisor.dev/gvisor/pkg/tcpip/stack"
	"gvisor.dev/gvisor/pkg/tcpip/transport/tcp"
	"gvisor.dev/gvisor/pkg/tcpip/transport/udp"

	"hat/internal/testproxy"
	"hat/internal/upstream"
)

const guestMAC = "52:54:00:12:34:56"

type env struct {
	host  *Stack
	guest *stack.Stack
	proxy *testproxy.Server
	echo  net.Listener
	port  string
}

func newEnv(t *testing.T) *env {
	t.Helper()
	e := &env{}
	e.echo = testproxy.StartEcho()
	_, e.port, _ = net.SplitHostPort(e.echo.Addr().String())
	e.proxy = testproxy.StartSOCKS5("u", "p")
	e.proxy.Resolve = func(string) string { return "127.0.0.1" } // everything -> echo server
	d, err := upstream.New("socks5://u:p@" + e.proxy.Addr())
	if err != nil {
		t.Fatal(err)
	}
	e.host, err = New(Config{Dialer: d, GuestMAC: guestMAC, DialTimeout: 3 * time.Second})
	if err != nil {
		t.Fatal(err)
	}
	fds, err := syscall.Socketpair(syscall.AF_UNIX, syscall.SOCK_DGRAM, 0)
	if err != nil {
		t.Fatal(err)
	}
	hostConn, err := net.FileConn(os.NewFile(uintptr(fds[0]), "host"))
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	go e.host.Accept(ctx, hostConn)

	// Guest: a second gVisor stack on the other end of the socketpair.
	g := stack.New(stack.Options{
		NetworkProtocols:   []stack.NetworkProtocolFactory{ipv4.NewProtocol, arp.NewProtocol},
		TransportProtocols: []stack.TransportProtocolFactory{tcp.NewProtocol, udp.NewProtocol},
	})
	mac, _ := tcpip.ParseMACAddress(guestMAC)
	link, err := fdbased.New(&fdbased.Options{FDs: []int{fds[1]}, MTU: 1500, EthernetHeader: true, Address: mac})
	if err != nil {
		t.Fatal(err)
	}
	if e := g.CreateNIC(1, link); e != nil {
		t.Fatal(e)
	}
	g.AddProtocolAddress(1, tcpip.ProtocolAddress{Protocol: ipv4.ProtocolNumber,
		AddressWithPrefix: tcpip.AddressWithPrefix{Address: tcpip.AddrFrom4([4]byte{192, 168, 127, 2}), PrefixLen: 24}},
		stack.AddressProperties{})
	g.SetRouteTable([]tcpip.Route{{Destination: header.IPv4EmptySubnet,
		Gateway: tcpip.AddrFrom4([4]byte{192, 168, 127, 1}), NIC: 1}})
	e.guest = g
	t.Cleanup(func() {
		cancel()
		g.Close()
		e.host.Close()
		e.proxy.Close()
		e.echo.Close()
	})
	return e
}

func (e *env) dialTCP(ip string, port string) (net.Conn, error) {
	addr := netip.MustParseAddr(ip)
	p, _ := net.LookupPort("tcp", port)
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	return gonet.DialContextTCP(ctx, e.guest, tcpip.FullAddress{NIC: 1, Addr: tcpip.AddrFrom4(addr.As4()), Port: uint16(p)}, ipv4.ProtocolNumber)
}

func (e *env) resolve(t *testing.T, server, name string) netip.Addr {
	t.Helper()
	srv := netip.MustParseAddr(server)
	c, err := gonet.DialUDP(e.guest, nil, &tcpip.FullAddress{NIC: 1, Addr: tcpip.AddrFrom4(srv.As4()), Port: 53}, ipv4.ProtocolNumber)
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	q := dnsmessage.Message{Header: dnsmessage.Header{ID: 1, RecursionDesired: true},
		Questions: []dnsmessage.Question{{Name: dnsmessage.MustNewName(name + "."), Type: dnsmessage.TypeA, Class: dnsmessage.ClassINET}}}
	b, _ := q.Pack()
	c.Write(b)
	c.SetReadDeadline(time.Now().Add(3 * time.Second))
	buf := make([]byte, 1500)
	n, err := c.Read(buf)
	if err != nil {
		t.Fatalf("dns via %s: %v", server, err)
	}
	var m dnsmessage.Message
	if err := m.Unpack(buf[:n]); err != nil || len(m.Answers) != 1 {
		t.Fatalf("bad dns reply %v %+v", err, m)
	}
	return netip.AddrFrom4(m.Answers[0].Body.(*dnsmessage.AResource).A)
}

func roundTrip(t *testing.T, c net.Conn) string {
	t.Helper()
	defer c.Close()
	io.WriteString(c, "hi\n")
	c.SetReadDeadline(time.Now().Add(5 * time.Second))
	line, err := bufio.NewReader(c).ReadString('\n')
	if err != nil {
		t.Fatal(err)
	}
	return strings.TrimSpace(line)
}

func TestGuestTCPByNameGoesThroughProxy(t *testing.T) {
	e := newEnv(t)
	ip := e.resolve(t, DefaultGatewayIP, "site.test")
	if !FakeIPRange.Contains(ip) {
		t.Fatalf("expected fake ip, got %v", ip)
	}
	c, err := e.dialTCP(ip.String(), e.port)
	if err != nil {
		t.Fatal(err)
	}
	if got := roundTrip(t, c); got != "hello:hi" {
		t.Fatalf("got %q", got)
	}
	if tg := e.proxy.Targets(); len(tg) != 1 || tg[0] != "site.test:"+e.port {
		t.Fatalf("proxy saw %v (hostname must be passed unresolved)", tg)
	}
}

func TestDNSToAnyServerAnsweredLocally(t *testing.T) {
	e := newEnv(t)
	ip := e.resolve(t, "8.8.8.8", "example.org")
	if !FakeIPRange.Contains(ip) {
		t.Fatalf("got %v", ip)
	}
	if len(e.proxy.Targets()) != 0 {
		t.Fatal("DNS went to the proxy")
	}
}

func TestLiteralPublicIPViaProxy(t *testing.T) {
	e := newEnv(t)
	c, err := e.dialTCP("203.0.113.5", e.port)
	if err != nil {
		t.Fatal(err)
	}
	if got := roundTrip(t, c); got != "hello:hi" {
		t.Fatalf("got %q", got)
	}
	if tg := e.proxy.Targets(); len(tg) != 1 || tg[0] != "203.0.113.5:"+e.port {
		t.Fatalf("proxy saw %v", tg)
	}
}

func TestRefusedDestinations(t *testing.T) {
	e := newEnv(t)
	for _, ip := range []string{"10.0.0.1", "127.0.0.1", "169.254.169.254", "192.168.127.1", "198.18.200.200", "100.64.0.1"} {
		if c, err := e.dialTCP(ip, "80"); err == nil {
			c.Close()
			t.Errorf("%s: connection allowed", ip)
		}
	}
	if len(e.proxy.Targets()) != 0 {
		t.Fatalf("refused destinations reached proxy: %v", e.proxy.Targets())
	}
	if e.host.Stats.Refused.Load() == 0 {
		t.Fatal("refusals not counted")
	}
}

func TestUDPDropped(t *testing.T) {
	e := newEnv(t)
	c, err := gonet.DialUDP(e.guest, nil, &tcpip.FullAddress{NIC: 1, Addr: tcpip.AddrFrom4([4]byte{1, 1, 1, 1}), Port: 443}, ipv4.ProtocolNumber)
	if err != nil {
		t.Fatal(err)
	}
	c.Write([]byte("quic?"))
	c.SetReadDeadline(time.Now().Add(500 * time.Millisecond))
	if _, err := c.Read(make([]byte, 10)); err == nil {
		t.Fatal("got a UDP reply")
	}
	c.Close()
	deadline := time.Now().Add(2 * time.Second)
	for e.host.Stats.UDPDropped.Load() == 0 && time.Now().Before(deadline) {
		time.Sleep(10 * time.Millisecond)
	}
	if e.host.Stats.UDPDropped.Load() == 0 {
		t.Fatal("UDP not dropped")
	}
}

func TestKillSwitch(t *testing.T) {
	e := newEnv(t)
	e.proxy.Close() // upstream goes away
	ip := e.resolve(t, DefaultGatewayIP, "site.test")
	if c, err := e.dialTCP(ip.String(), e.port); err == nil {
		c.SetReadDeadline(time.Now().Add(2 * time.Second))
		if _, rerr := c.Read(make([]byte, 1)); rerr == nil {
			t.Fatal("connection worked without upstream")
		}
		c.Close()
	}
	if e.host.Stats.UpstreamFailed.Load() == 0 || e.host.LastError() == nil {
		t.Fatal("upstream failure not recorded")
	}
}

func TestDialGuest(t *testing.T) {
	e := newEnv(t)
	ln, err := gonet.ListenTCP(e.guest, tcpip.FullAddress{NIC: 1, Port: 22}, ipv4.ProtocolNumber)
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	go func() {
		c, err := ln.Accept()
		if err != nil {
			return
		}
		io.WriteString(c, "SSH-2.0-test\r\n")
		c.Close()
	}()
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	c, err := e.host.DialGuest(ctx, 22)
	if err != nil {
		t.Fatal(err)
	}
	line, _ := bufio.NewReader(c).ReadString('\n')
	c.Close()
	if !strings.HasPrefix(line, "SSH-2.0-test") {
		t.Fatalf("got %q", line)
	}
}

func TestBlackhole(t *testing.T) {
	e := newEnv(t)
	e.host.SetBlackhole(true)
	if c, err := e.dialTCP("203.0.113.5", e.port); err == nil {
		c.Close()
		t.Fatal("connected in blackhole mode")
	}
	if len(e.proxy.Targets()) != 0 {
		t.Fatal("blackhole reached upstream")
	}
	e.host.SetBlackhole(false)
	c, err := e.dialTCP("203.0.113.5", e.port)
	if err != nil {
		t.Fatal(err)
	}
	roundTrip(t, c)
}
