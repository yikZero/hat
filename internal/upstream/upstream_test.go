package upstream

import (
	"bufio"
	"context"
	"io"
	"net"
	"strings"
	"testing"
	"time"

	"hat/internal/testproxy"
)

func roundTrip(t *testing.T, d Dialer, target string) string {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	c, err := d.DialContext(ctx, "tcp", target)
	if err != nil {
		t.Fatalf("dial %s: %v", target, err)
	}
	defer c.Close()
	io.WriteString(c, "ping\n")
	line, err := bufio.NewReader(c).ReadString('\n')
	if err != nil {
		t.Fatal(err)
	}
	return strings.TrimSpace(line)
}

func TestSOCKS5HostnamePassedUnresolved(t *testing.T) {
	echo := testproxy.StartEcho()
	defer echo.Close()
	srv := testproxy.StartSOCKS5("alice", "s3cret")
	defer srv.Close()
	srv.Resolve = func(h string) string {
		if h == "example.invalid" {
			return "127.0.0.1"
		}
		return h
	}
	_, port, _ := net.SplitHostPort(echo.Addr().String())
	d, err := New("socks5://alice:s3cret@" + srv.Addr())
	if err != nil {
		t.Fatal(err)
	}
	if got := roundTrip(t, d, "example.invalid:"+port); got != "hello:ping" {
		t.Fatalf("got %q", got)
	}
	if tg := srv.Targets(); len(tg) != 1 || tg[0] != "example.invalid:"+port {
		t.Fatalf("proxy saw targets %v; hostname must reach proxy unresolved", tg)
	}
}

func TestSOCKS5BadPassword(t *testing.T) {
	srv := testproxy.StartSOCKS5("alice", "s3cret")
	defer srv.Close()
	d, _ := New("socks5://alice:wrong@" + srv.Addr())
	if _, err := d.DialContext(context.Background(), "tcp", "example.com:80"); err == nil {
		t.Fatal("expected auth failure")
	}
}

func TestHTTPConnect(t *testing.T) {
	echo := testproxy.StartEcho()
	defer echo.Close()
	srv := testproxy.StartHTTP("bob", "pw")
	defer srv.Close()
	srv.Resolve = func(string) string { return "127.0.0.1" }
	_, port, _ := net.SplitHostPort(echo.Addr().String())
	d, err := New("http://bob:pw@" + srv.Addr())
	if err != nil {
		t.Fatal(err)
	}
	if got := roundTrip(t, d, "api.example.invalid:"+port); got != "hello:ping" {
		t.Fatalf("got %q", got)
	}
	bad, _ := New("http://bob:nope@" + srv.Addr())
	if _, err := bad.DialContext(context.Background(), "tcp", "x.invalid:1"); err == nil {
		t.Fatal("expected 407 failure")
	}
}

func TestProxyDownFailsClosed(t *testing.T) {
	l, _ := net.Listen("tcp", "127.0.0.1:0")
	addr := l.Addr().String()
	l.Close() // nothing listening any more
	for _, scheme := range []string{"socks5", "http"} {
		d, _ := New(scheme + "://" + addr)
		ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
		_, err := d.DialContext(ctx, "tcp", "example.com:443")
		cancel()
		if err == nil || !strings.Contains(err.Error(), "unreachable") {
			t.Fatalf("%s: expected unreachable error, got %v", scheme, err)
		}
	}
}

func TestRejectsUDPAndBadURLs(t *testing.T) {
	d, _ := New("socks5://127.0.0.1:1")
	if _, err := d.DialContext(context.Background(), "udp", "1.1.1.1:53"); err != ErrUnsupportedNetwork {
		t.Fatalf("got %v", err)
	}
	for _, u := range []string{"", "socks5://host", "ftp://h:1", "direct://"} {
		if _, err := New(u); err == nil {
			t.Fatalf("expected error for %q", u)
		}
	}
	if r := Redact("socks5://u:topsecret@h:1"); strings.Contains(r, "topsecret") {
		t.Fatalf("password not redacted: %s", r)
	}
}
