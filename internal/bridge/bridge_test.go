package bridge

import (
	"bufio"
	"context"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"golang.org/x/net/proxy"

	"hat/internal/testproxy"
	"hat/internal/upstream"
)

func setup(t *testing.T, scheme string) (*Bridge, *testproxy.Server) {
	t.Helper()
	var up *testproxy.Server
	if scheme == "socks5" {
		up = testproxy.StartSOCKS5("u", "p")
	} else {
		up = testproxy.StartHTTP("u", "p")
	}
	up.Resolve = func(h string) string {
		if strings.HasSuffix(h, ".test") {
			return "127.0.0.1"
		}
		return "192.0.2.1" // TEST-NET: unroutable
	}
	d, err := upstream.New(scheme + "://u:p@" + up.Addr())
	if err != nil {
		t.Fatal(err)
	}
	b := &Bridge{Dialer: d}
	if err := b.Start(""); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { b.Close(); up.Close() })
	return b, up
}

func TestSOCKSClientThroughBridge(t *testing.T) {
	for _, scheme := range []string{"socks5", "http"} {
		t.Run(scheme, func(t *testing.T) {
			b, up := setup(t, scheme)
			echo := testproxy.StartEcho()
			defer echo.Close()
			_, port, _ := net.SplitHostPort(echo.Addr().String())
			d, _ := proxy.SOCKS5("tcp", b.Addr(), nil, nil)
			c, err := d.(proxy.ContextDialer).DialContext(context.Background(), "tcp", "echo.test:"+port)
			if err != nil {
				t.Fatal(err)
			}
			io.WriteString(c, "hi\n")
			line, _ := bufio.NewReader(c).ReadString('\n')
			c.Close()
			if line != "hello:hi\n" {
				t.Fatalf("got %q", line)
			}
			if tg := up.Targets(); len(tg) != 1 || tg[0] != "echo.test:"+port {
				t.Fatalf("upstream targets %v", tg)
			}
		})
	}
}

func TestHTTPClientThroughBridge(t *testing.T) {
	b, up := setup(t, "socks5")
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		io.WriteString(w, "ok "+r.URL.Path)
	}))
	defer ts.Close()
	_, port, _ := net.SplitHostPort(strings.TrimPrefix(ts.URL, "http://"))
	pu, _ := url.Parse("http://" + b.Addr())
	cl := &http.Client{Transport: &http.Transport{Proxy: http.ProxyURL(pu)}, Timeout: 5 * time.Second}

	// plain HTTP (absolute-URI) request
	resp, err := cl.Get("http://site.test:" + port + "/a")
	if err != nil {
		t.Fatal(err)
	}
	body, _ := io.ReadAll(resp.Body)
	resp.Body.Close()
	if string(body) != "ok /a" {
		t.Fatalf("got %q", body)
	}
	// CONNECT tunnel (raw)
	c, _ := net.Dial("tcp", b.Addr())
	io.WriteString(c, "CONNECT site.test:"+port+" HTTP/1.1\r\nHost: site.test:"+port+"\r\n\r\n")
	br := bufio.NewReader(c)
	r, err := http.ReadResponse(br, nil)
	if err != nil || r.StatusCode != 200 {
		t.Fatalf("connect: %v %v", r, err)
	}
	io.WriteString(c, "GET /b HTTP/1.1\r\nHost: site.test\r\n\r\n")
	r2, err := http.ReadResponse(br, nil)
	if err != nil {
		t.Fatal(err)
	}
	b2, _ := io.ReadAll(io.LimitReader(r2.Body, 5))
	if string(b2) != "ok /b" {
		t.Fatalf("got %q", b2)
	}
	c.Close()
	for _, tg := range up.Targets() {
		if !strings.HasPrefix(tg, "site.test:") {
			t.Fatalf("unexpected upstream target %s", tg)
		}
	}
}

func TestBlocksLocalDestinations(t *testing.T) {
	b, up := setup(t, "socks5")
	pu, _ := url.Parse("http://" + b.Addr())
	cl := &http.Client{Transport: &http.Transport{Proxy: http.ProxyURL(pu)}, Timeout: 5 * time.Second}
	for _, target := range []string{"http://127.0.0.1:9/", "http://localhost:9/", "http://[::1]:9/",
		"http://10.0.0.1/", "http://169.254.169.254/latest/meta-data", "http://printer.local/"} {
		resp, err := cl.Get(target)
		if err != nil {
			t.Fatalf("%s: %v", target, err)
		}
		resp.Body.Close()
		if resp.StatusCode != http.StatusForbidden {
			t.Fatalf("%s: status %d, want 403", target, resp.StatusCode)
		}
	}
	if n := len(up.Targets()); n != 0 {
		t.Fatalf("blocked requests reached upstream: %v", up.Targets())
	}
}

func TestUpstreamDownFailsClosed(t *testing.T) {
	l, _ := net.Listen("tcp", "127.0.0.1:0")
	dead := l.Addr().String()
	l.Close()
	d, _ := upstream.New("socks5://" + dead)
	b := &Bridge{Dialer: d}
	b.Start("")
	defer b.Close()
	pu, _ := url.Parse("http://" + b.Addr())
	cl := &http.Client{Transport: &http.Transport{Proxy: http.ProxyURL(pu)}, Timeout: 5 * time.Second}
	resp, err := cl.Get("http://example.com/")
	if err != nil {
		t.Fatal(err)
	}
	body, _ := io.ReadAll(resp.Body)
	resp.Body.Close()
	if resp.StatusCode != http.StatusBadGateway || !strings.Contains(string(body), "no direct connection") {
		t.Fatalf("status %d body %q", resp.StatusCode, body)
	}
	if n, err := b.LastError(); n == 0 || err == nil {
		t.Fatal("failure not recorded")
	}
}

func TestSOCKSRejectsUDPAssociate(t *testing.T) {
	b, _ := setup(t, "socks5")
	c, _ := net.Dial("tcp", b.Addr())
	defer c.Close()
	c.Write([]byte{5, 1, 0})
	var r [2]byte
	io.ReadFull(c, r[:])
	c.Write([]byte{5, 3, 0, 1, 0, 0, 0, 0, 0, 0})
	var rep [10]byte
	io.ReadFull(c, rep[:])
	if rep[1] != 0x07 {
		t.Fatalf("reply %x, want command-not-supported", rep[1])
	}
}

func TestBridgeCredentials(t *testing.T) {
	up := testproxy.StartSOCKS5("", "")
	defer up.Close()
	up.Resolve = func(string) string { return "127.0.0.1" }
	d, _ := upstream.New("socks5://" + up.Addr())
	b := &Bridge{Dialer: d, User: "hat", Pass: RandomToken()}
	b.Start("")
	defer b.Close()
	echo := testproxy.StartEcho()
	defer echo.Close()
	_, port, _ := net.SplitHostPort(echo.Addr().String())

	// no credentials -> refused (SOCKS and HTTP)
	nd, _ := proxy.SOCKS5("tcp", b.Addr(), nil, nil)
	if _, err := nd.Dial("tcp", "e.test:"+port); err == nil {
		t.Fatal("SOCKS without auth accepted")
	}
	pu, _ := url.Parse("http://" + b.Addr())
	cl := &http.Client{Transport: &http.Transport{Proxy: http.ProxyURL(pu)}}
	resp, err := cl.Get("http://e.test:" + port + "/")
	if err != nil || resp.StatusCode != http.StatusProxyAuthRequired {
		t.Fatalf("HTTP without auth: %v %v", resp, err)
	}
	resp.Body.Close()
	// with credentials -> works
	ad, _ := proxy.SOCKS5("tcp", b.Addr(), &proxy.Auth{User: "hat", Password: b.Pass}, nil)
	c, err := ad.Dial("tcp", "e.test:"+port)
	if err != nil {
		t.Fatal(err)
	}
	io.WriteString(c, "x\n")
	line, _ := bufio.NewReader(c).ReadString('\n')
	c.Close()
	if line != "hello:x\n" {
		t.Fatalf("got %q", line)
	}
	pu2, _ := url.Parse("http://hat:" + b.Pass + "@" + b.Addr())
	cl2 := &http.Client{Transport: &http.Transport{Proxy: http.ProxyURL(pu2)}}
	if _, err := cl2.Get("http://e.test:" + port + "/"); err != nil {
		t.Fatal(err)
	}
	if len(up.Targets()) != 2 {
		t.Fatalf("targets %v", up.Targets())
	}
}
