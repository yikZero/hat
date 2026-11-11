// Package bridge implements the lite-mode local proxy. It listens on
// 127.0.0.1, speaks both SOCKS5 and HTTP (CONNECT and absolute-URI
// requests) on the same port, requires no authentication, and forwards
// every connection exclusively through the upstream Dialer. It never dials
// anything itself.
package bridge

import (
	"bufio"
	"context"
	"crypto/rand"
	"crypto/subtle"
	"encoding/base64"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"strconv"
	"strings"
	"sync"
	"time"

	"hat/internal/upstream"
)

type Bridge struct {
	Dialer upstream.Dialer
	// AllowPrivate permits destinations on loopback / private / link-local
	// addresses (forwarded to the upstream proxy). Off by default so the
	// sandboxed program cannot use the proxy to reach local services.
	AllowPrivate bool
	// User/Pass, when set, are required from clients (SOCKS5 user/pass or
	// HTTP Proxy-Authorization Basic). Use random per-run values so other
	// local processes cannot borrow the bridge.
	User, Pass string
	// Logf receives one line per refused or failed connection. May be nil.
	Logf func(format string, args ...any)

	ln     net.Listener
	httpLn *chanListener
	srv    *http.Server
	wg     sync.WaitGroup

	mu       sync.Mutex
	failures int
	lastErr  error
}

// Start listens on 127.0.0.1:0 (or addr if non-empty) and serves in the
// background.
func (b *Bridge) Start(addr string) error {
	if addr == "" {
		addr = "127.0.0.1:0"
	}
	ln, err := net.Listen("tcp", addr)
	if err != nil {
		return err
	}
	b.ln = ln
	b.httpLn = newChanListener(ln.Addr())
	tr := &http.Transport{
		Proxy:                 nil,
		DialContext:           b.dial,
		ForceAttemptHTTP2:     false,
		MaxIdleConns:          32,
		IdleConnTimeout:       60 * time.Second,
		TLSHandshakeTimeout:   15 * time.Second,
		ResponseHeaderTimeout: 0,
	}
	b.srv = &http.Server{Handler: &httpHandler{b: b, tr: tr}, ReadHeaderTimeout: 30 * time.Second}
	b.wg.Add(2)
	go func() { defer b.wg.Done(); b.srv.Serve(b.httpLn) }()
	go b.acceptLoop()
	return nil
}

// Addr returns the listening address, e.g. 127.0.0.1:53211.
func (b *Bridge) Addr() string { return b.ln.Addr().String() }

// Port returns the listening port.
func (b *Bridge) Port() int { return b.ln.Addr().(*net.TCPAddr).Port }

func (b *Bridge) Close() error {
	err := b.ln.Close()
	b.httpLn.Close()
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	b.srv.Shutdown(ctx)
	cancel()
	b.wg.Wait()
	return err
}

// LastError returns the most recent upstream failure, if any, and the
// number of failures so far.
func (b *Bridge) LastError() (int, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.failures, b.lastErr
}

func (b *Bridge) logf(format string, args ...any) {
	if b.Logf != nil {
		b.Logf(format, args...)
	}
}

// ErrBlockedDestination is returned for refused local/private targets.
var ErrBlockedDestination = errors.New("destination is a local/private address (blocked)")

// dial validates the destination and connects through the upstream.
func (b *Bridge) dial(ctx context.Context, network, address string) (net.Conn, error) {
	host, _, err := net.SplitHostPort(address)
	if err != nil {
		return nil, err
	}
	if !b.AllowPrivate && IsLocalDestination(host) {
		b.logf("refused %s: %v", address, ErrBlockedDestination)
		return nil, ErrBlockedDestination
	}
	c, err := b.Dialer.DialContext(ctx, "tcp", address)
	if err != nil {
		b.mu.Lock()
		b.failures++
		b.lastErr = err
		b.mu.Unlock()
		b.logf("%s: %v", address, err)
		return nil, err
	}
	return c, nil
}

// IsLocalDestination reports whether host is local/private (blocked).
func IsLocalDestination(host string) bool { return upstream.IsLocalHost(host) }

func (b *Bridge) acceptLoop() {
	defer b.wg.Done()
	for {
		c, err := b.ln.Accept()
		if err != nil {
			return
		}
		go b.handle(c)
	}
}

func (b *Bridge) handle(c net.Conn) {
	br := bufio.NewReader(c)
	c.SetReadDeadline(time.Now().Add(30 * time.Second))
	first, err := br.Peek(1)
	if err != nil {
		c.Close()
		return
	}
	c.SetReadDeadline(time.Time{})
	pc := &peekedConn{Conn: c, r: br}
	if first[0] == 0x05 {
		b.serveSOCKS(pc)
		return
	}
	if !b.httpLn.push(pc) {
		c.Close()
	}
}

// ---------------------------------------------------------------- SOCKS5

func (b *Bridge) serveSOCKS(c net.Conn) {
	defer c.Close()
	c.SetDeadline(time.Now().Add(30 * time.Second))
	var hdr [2]byte
	if _, err := io.ReadFull(c, hdr[:]); err != nil {
		return
	}
	methods := make([]byte, hdr[1])
	if _, err := io.ReadFull(c, methods); err != nil {
		return
	}
	want := byte(0x00)
	if b.User != "" {
		want = 0x02
	}
	offered := false
	for _, m := range methods {
		if m == want {
			offered = true
		}
	}
	if !offered {
		c.Write([]byte{0x05, 0xff})
		return
	}
	c.Write([]byte{0x05, want})
	if want == 0x02 {
		var v [2]byte
		if _, err := io.ReadFull(c, v[:]); err != nil {
			return
		}
		u := make([]byte, v[1])
		if _, err := io.ReadFull(c, u); err != nil {
			return
		}
		var pl [1]byte
		if _, err := io.ReadFull(c, pl[:]); err != nil {
			return
		}
		pw := make([]byte, pl[0])
		if _, err := io.ReadFull(c, pw); err != nil {
			return
		}
		if !b.credsOK(string(u), string(pw)) {
			c.Write([]byte{0x01, 0x01})
			b.logf("rejected SOCKS5 client with wrong credentials")
			return
		}
		c.Write([]byte{0x01, 0x00})
	}
	var req [4]byte
	if _, err := io.ReadFull(c, req[:]); err != nil {
		return
	}
	var host string
	switch req[3] {
	case 0x01:
		ip := make([]byte, 4)
		if _, err := io.ReadFull(c, ip); err != nil {
			return
		}
		host = net.IP(ip).String()
	case 0x04:
		ip := make([]byte, 16)
		if _, err := io.ReadFull(c, ip); err != nil {
			return
		}
		host = net.IP(ip).String()
	case 0x03:
		var l [1]byte
		if _, err := io.ReadFull(c, l[:]); err != nil {
			return
		}
		name := make([]byte, l[0])
		if _, err := io.ReadFull(c, name); err != nil {
			return
		}
		host = string(name)
	default:
		socksReply(c, 0x08)
		return
	}
	var pb [2]byte
	if _, err := io.ReadFull(c, pb[:]); err != nil {
		return
	}
	if req[1] != 0x01 { // only CONNECT; UDP ASSOCIATE / BIND are refused
		socksReply(c, 0x07)
		return
	}
	target := net.JoinHostPort(host, strconv.Itoa(int(binary.BigEndian.Uint16(pb[:]))))
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	up, err := b.dial(ctx, "tcp", target)
	cancel()
	if err != nil {
		code := byte(0x01)
		if errors.Is(err, ErrBlockedDestination) {
			code = 0x02
		}
		socksReply(c, code)
		return
	}
	defer up.Close()
	socksReply(c, 0x00)
	c.SetDeadline(time.Time{})
	pipe(c, up)
}

func socksReply(c net.Conn, code byte) {
	c.Write([]byte{0x05, code, 0x00, 0x01, 0, 0, 0, 0, 0, 0})
}

// ---------------------------------------------------------------- HTTP

type httpHandler struct {
	b  *Bridge
	tr *http.Transport
}

var hopHeaders = []string{"Connection", "Proxy-Connection", "Keep-Alive", "Proxy-Authenticate",
	"Proxy-Authorization", "Te", "Trailer", "Transfer-Encoding", "Upgrade"}

func (h *httpHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if h.b.User != "" {
		u, p, ok := parseBasic(r.Header.Get("Proxy-Authorization"))
		if !ok || !h.b.credsOK(u, p) {
			w.Header().Set("Proxy-Authenticate", `Basic realm="`+App+`"`)
			http.Error(w, "proxy authentication required", http.StatusProxyAuthRequired)
			return
		}
	}
	if r.Method == http.MethodConnect {
		h.connect(w, r)
		return
	}
	if r.URL.Scheme != "http" || r.URL.Host == "" {
		http.Error(w, App+" bridge: only proxy requests are accepted", http.StatusBadRequest)
		return
	}
	out := r.Clone(r.Context())
	out.RequestURI = ""
	for _, k := range hopHeaders {
		out.Header.Del(k)
	}
	if c := r.Header.Get("Connection"); c != "" {
		for _, f := range strings.Split(c, ",") {
			out.Header.Del(strings.TrimSpace(f))
		}
	}
	resp, err := h.tr.RoundTrip(out)
	if err != nil {
		writeProxyError(w, err)
		return
	}
	defer resp.Body.Close()
	for _, k := range hopHeaders {
		resp.Header.Del(k)
	}
	for k, vs := range resp.Header {
		for _, v := range vs {
			w.Header().Add(k, v)
		}
	}
	w.WriteHeader(resp.StatusCode)
	io.Copy(w, resp.Body)
}

func (h *httpHandler) connect(w http.ResponseWriter, r *http.Request) {
	target := r.Host
	if _, _, err := net.SplitHostPort(target); err != nil {
		http.Error(w, "bad CONNECT target", http.StatusBadRequest)
		return
	}
	up, err := h.b.dial(r.Context(), "tcp", target)
	if err != nil {
		writeProxyError(w, err)
		return
	}
	hj, ok := w.(http.Hijacker)
	if !ok {
		up.Close()
		http.Error(w, "hijack unsupported", http.StatusInternalServerError)
		return
	}
	c, brw, err := hj.Hijack()
	if err != nil {
		up.Close()
		return
	}
	defer c.Close()
	defer up.Close()
	io.WriteString(c, "HTTP/1.1 200 Connection established\r\n\r\n")
	if n := brw.Reader.Buffered(); n > 0 {
		buf, _ := brw.Reader.Peek(n)
		up.Write(buf)
	}
	pipe(c, up)
}

// App is used in user-facing error text.
var App = "hat"

func writeProxyError(w http.ResponseWriter, err error) {
	code := http.StatusBadGateway
	if errors.Is(err, ErrBlockedDestination) {
		code = http.StatusForbidden
	}
	http.Error(w, fmt.Sprintf("%s: %v (no direct connection was attempted)", App, err), code)
}

// ---------------------------------------------------------------- plumbing

func (b *Bridge) credsOK(u, p string) bool {
	return subtle.ConstantTimeCompare([]byte(u), []byte(b.User)) == 1 &&
		subtle.ConstantTimeCompare([]byte(p), []byte(b.Pass)) == 1
}

func parseBasic(h string) (string, string, bool) {
	const prefix = "Basic "
	if len(h) < len(prefix) || !strings.EqualFold(h[:len(prefix)], prefix) {
		return "", "", false
	}
	dec, err := base64.StdEncoding.DecodeString(h[len(prefix):])
	if err != nil {
		return "", "", false
	}
	u, p, ok := strings.Cut(string(dec), ":")
	return u, p, ok
}

// RandomToken returns a random URL-safe credential.
func RandomToken() string {
	b := make([]byte, 18)
	rand.Read(b)
	return base64.RawURLEncoding.EncodeToString(b)
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
}

type peekedConn struct {
	net.Conn
	r *bufio.Reader
}

func (p *peekedConn) Read(b []byte) (int, error) { return p.r.Read(b) }

func (p *peekedConn) CloseWrite() error {
	if cw, ok := p.Conn.(interface{ CloseWrite() error }); ok {
		return cw.CloseWrite()
	}
	return nil
}

type chanListener struct {
	addr   net.Addr
	ch     chan net.Conn
	once   sync.Once
	closed chan struct{}
}

func newChanListener(addr net.Addr) *chanListener {
	return &chanListener{addr: addr, ch: make(chan net.Conn), closed: make(chan struct{})}
}

func (l *chanListener) push(c net.Conn) bool {
	select {
	case l.ch <- c:
		return true
	case <-l.closed:
		return false
	}
}

func (l *chanListener) Accept() (net.Conn, error) {
	select {
	case c := <-l.ch:
		return c, nil
	case <-l.closed:
		return nil, net.ErrClosed
	}
}

func (l *chanListener) Close() error {
	l.once.Do(func() { close(l.closed) })
	return nil
}

func (l *chanListener) Addr() net.Addr { return l.addr }
