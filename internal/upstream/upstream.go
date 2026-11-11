// Package upstream dials TCP connections through the profile's upstream proxy.
//
// This is the ONLY place in the program that opens a direct network
// connection, and it only ever connects to the configured proxy server
// itself. Every other component must obtain connections through a Dialer
// returned by New. There is deliberately no "direct" dialer.
package upstream

import (
	"bufio"
	"context"
	"encoding/base64"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/netip"
	"net/url"
	"strconv"
	"strings"
	"time"
)

// Dialer opens TCP connections to host:port through the upstream proxy.
// host may be a domain name; it is passed to the proxy unresolved so that
// name resolution happens on the proxy side (socks5h semantics).
type Dialer interface {
	DialContext(ctx context.Context, network, address string) (net.Conn, error)
	// String returns a redacted description of the upstream (no password).
	String() string
}

// ErrUnsupportedNetwork is returned for anything other than TCP.
var ErrUnsupportedNetwork = errors.New("upstream: only tcp is supported")

// New parses a proxy URL such as
//
//	socks5://user:pass@host:1080
//	socks5h://host:1080
//	http://user:pass@host:8080
//
// and returns a Dialer for it.
func New(raw string) (Dialer, error) {
	u, err := url.Parse(raw)
	if err != nil {
		return nil, fmt.Errorf("upstream: invalid proxy URL: %w", err)
	}
	if u.Host == "" || u.Port() == "" {
		return nil, fmt.Errorf("upstream: proxy URL must include host and port: %s", Redact(raw))
	}
	base := &base{server: u.Host, timeout: 15 * time.Second}
	if u.User != nil {
		base.user = u.User.Username()
		base.pass, _ = u.User.Password()
	}
	switch u.Scheme {
	case "socks5", "socks5h":
		return &socks5Dialer{base}, nil
	case "http":
		return &httpDialer{base}, nil
	default:
		return nil, fmt.Errorf("upstream: unsupported proxy scheme %q (use socks5:// or http://)", u.Scheme)
	}
}

// Redact removes the password from a proxy URL for display.
func Redact(raw string) string {
	u, err := url.Parse(raw)
	if err != nil {
		return "<invalid proxy URL>"
	}
	if u.User != nil {
		if _, ok := u.User.Password(); ok {
			u.User = url.UserPassword(u.User.Username(), "xxxxx")
		}
	}
	return u.String()
}

type base struct {
	server     string
	user, pass string
	timeout    time.Duration
}

func (b *base) dialServer(ctx context.Context) (net.Conn, error) {
	d := net.Dialer{Timeout: b.timeout, KeepAlive: 30 * time.Second}
	c, err := d.DialContext(ctx, "tcp", b.server)
	if err != nil {
		return nil, fmt.Errorf("upstream proxy %s unreachable: %w", b.server, err)
	}
	return c, nil
}

// withDeadline applies the context deadline (or the default timeout) to the
// handshake and returns a func that clears it.
func (b *base) withDeadline(ctx context.Context, c net.Conn) func() {
	dl, ok := ctx.Deadline()
	if !ok {
		dl = time.Now().Add(b.timeout)
	}
	_ = c.SetDeadline(dl)
	stop := context.AfterFunc(ctx, func() { _ = c.SetDeadline(time.Unix(1, 0)) })
	return func() {
		stop()
		_ = c.SetDeadline(time.Time{})
	}
}

// ---------------------------------------------------------------- SOCKS5

type socks5Dialer struct{ *base }

func (d *socks5Dialer) String() string { return "socks5://" + d.server }

func (d *socks5Dialer) DialContext(ctx context.Context, network, address string) (net.Conn, error) {
	if network != "tcp" && network != "tcp4" && network != "tcp6" {
		return nil, ErrUnsupportedNetwork
	}
	host, portStr, err := net.SplitHostPort(address)
	if err != nil {
		return nil, err
	}
	port, err := strconv.Atoi(portStr)
	if err != nil || port <= 0 || port > 65535 {
		return nil, fmt.Errorf("upstream: bad port in %q", address)
	}
	c, err := d.dialServer(ctx)
	if err != nil {
		return nil, err
	}
	done := d.withDeadline(ctx, c)
	if err := d.handshake(c, host, port); err != nil {
		done()
		c.Close()
		return nil, err
	}
	done()
	return c, nil
}

func (d *socks5Dialer) handshake(c net.Conn, host string, port int) error {
	methods := []byte{0x00}
	if d.user != "" {
		methods = []byte{0x02}
	}
	if _, err := c.Write(append([]byte{0x05, byte(len(methods))}, methods...)); err != nil {
		return fmt.Errorf("socks5: %w", err)
	}
	var resp [2]byte
	if _, err := io.ReadFull(c, resp[:]); err != nil {
		return fmt.Errorf("socks5: reading method: %w", err)
	}
	if resp[0] != 0x05 {
		return errors.New("socks5: server is not SOCKS5")
	}
	switch resp[1] {
	case 0x00:
	case 0x02:
		if len(d.user) > 255 || len(d.pass) > 255 {
			return errors.New("socks5: username/password too long")
		}
		msg := []byte{0x01, byte(len(d.user))}
		msg = append(msg, d.user...)
		msg = append(msg, byte(len(d.pass)))
		msg = append(msg, d.pass...)
		if _, err := c.Write(msg); err != nil {
			return fmt.Errorf("socks5 auth: %w", err)
		}
		if _, err := io.ReadFull(c, resp[:]); err != nil {
			return fmt.Errorf("socks5 auth: %w", err)
		}
		if resp[1] != 0x00 {
			return errors.New("socks5: authentication rejected by proxy")
		}
	case 0xff:
		return errors.New("socks5: proxy rejected all auth methods (check username/password)")
	default:
		return fmt.Errorf("socks5: unexpected auth method 0x%02x", resp[1])
	}

	req := []byte{0x05, 0x01, 0x00}
	if ip := net.ParseIP(host); ip != nil {
		if ip4 := ip.To4(); ip4 != nil {
			req = append(req, 0x01)
			req = append(req, ip4...)
		} else {
			req = append(req, 0x04)
			req = append(req, ip.To16()...)
		}
	} else {
		if len(host) > 255 {
			return errors.New("socks5: hostname too long")
		}
		req = append(req, 0x03, byte(len(host)))
		req = append(req, host...)
	}
	req = append(req, byte(port>>8), byte(port))
	if _, err := c.Write(req); err != nil {
		return fmt.Errorf("socks5 connect: %w", err)
	}
	var hdr [4]byte
	if _, err := io.ReadFull(c, hdr[:]); err != nil {
		return fmt.Errorf("socks5 connect: %w", err)
	}
	if hdr[1] != 0x00 {
		return fmt.Errorf("socks5: connect to %s:%d failed: %s", host, port, socksReply(hdr[1]))
	}
	var skip int
	switch hdr[3] {
	case 0x01:
		skip = 4
	case 0x04:
		skip = 16
	case 0x03:
		var l [1]byte
		if _, err := io.ReadFull(c, l[:]); err != nil {
			return err
		}
		skip = int(l[0])
	default:
		return errors.New("socks5: bad address type in reply")
	}
	_, err := io.ReadFull(c, make([]byte, skip+2))
	return err
}

func socksReply(code byte) string {
	switch code {
	case 0x01:
		return "general failure"
	case 0x02:
		return "not allowed by ruleset"
	case 0x03:
		return "network unreachable"
	case 0x04:
		return "host unreachable"
	case 0x05:
		return "connection refused"
	case 0x06:
		return "TTL expired"
	case 0x07:
		return "command not supported"
	case 0x08:
		return "address type not supported"
	}
	return fmt.Sprintf("error 0x%02x", code)
}

// ---------------------------------------------------------------- HTTP CONNECT

type httpDialer struct{ *base }

func (d *httpDialer) String() string { return "http://" + d.server }

func (d *httpDialer) DialContext(ctx context.Context, network, address string) (net.Conn, error) {
	if network != "tcp" && network != "tcp4" && network != "tcp6" {
		return nil, ErrUnsupportedNetwork
	}
	if _, _, err := net.SplitHostPort(address); err != nil {
		return nil, err
	}
	c, err := d.dialServer(ctx)
	if err != nil {
		return nil, err
	}
	done := d.withDeadline(ctx, c)
	req := "CONNECT " + address + " HTTP/1.1\r\nHost: " + address + "\r\n"
	if d.user != "" {
		req += "Proxy-Authorization: Basic " + base64.StdEncoding.EncodeToString([]byte(d.user+":"+d.pass)) + "\r\n"
	}
	req += "\r\n"
	if _, err := io.WriteString(c, req); err != nil {
		done()
		c.Close()
		return nil, fmt.Errorf("http proxy: %w", err)
	}
	br := bufio.NewReader(c)
	resp, err := http.ReadResponse(br, nil)
	if err != nil {
		done()
		c.Close()
		return nil, fmt.Errorf("http proxy: %w", err)
	}
	if resp.StatusCode != http.StatusOK {
		done()
		c.Close()
		return nil, fmt.Errorf("http proxy: CONNECT %s: %s", address, resp.Status)
	}
	done()
	if br.Buffered() > 0 {
		return &bufferedConn{Conn: c, r: br}, nil
	}
	return c, nil
}

type bufferedConn struct {
	net.Conn
	r *bufio.Reader
}

func (b *bufferedConn) Read(p []byte) (int, error) { return b.r.Read(p) }

// IsLocalHost reports whether host is a loopback/private/link-local
// address or a local-only name.
func IsLocalHost(host string) bool {
	h := strings.TrimSuffix(strings.ToLower(strings.Trim(host, "[]")), ".")
	if h == "localhost" || strings.HasSuffix(h, ".localhost") || strings.HasSuffix(h, ".local") ||
		strings.HasSuffix(h, ".internal") || strings.HasSuffix(h, ".lan") || strings.HasSuffix(h, ".home.arpa") {
		return true
	}
	addr, err := netip.ParseAddr(h)
	if err != nil {
		return false
	}
	addr = addr.Unmap()
	for _, p := range localPrefixes {
		if p.Contains(addr) {
			return true
		}
	}
	return addr.IsLoopback() || addr.IsPrivate() || addr.IsLinkLocalUnicast() ||
		addr.IsLinkLocalMulticast() || addr.IsInterfaceLocalMulticast() || addr.IsMulticast() || addr.IsUnspecified()
}

var localPrefixes = []netip.Prefix{
	netip.MustParsePrefix("0.0.0.0/8"),
	netip.MustParsePrefix("100.64.0.0/10"), // CGNAT
	netip.MustParsePrefix("192.0.0.0/24"),
	netip.MustParsePrefix("198.18.0.0/15"), // benchmarking / fake-ip
	netip.MustParsePrefix("240.0.0.0/4"),
	netip.MustParsePrefix("255.255.255.255/32"),
	netip.MustParsePrefix("fc00::/7"), // ULA
	netip.MustParsePrefix("64:ff9b::/96"),
}
