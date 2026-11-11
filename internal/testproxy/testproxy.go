// Package testproxy implements a minimal SOCKS5 and HTTP CONNECT proxy for
// tests. It records every target address it was asked to connect to.
package testproxy

import (
	"bufio"
	"encoding/base64"
	"encoding/binary"
	"hat/internal/netutil"
	"io"
	"net"
	"net/http"
	"strconv"
	"strings"
	"sync"
)

type Server struct {
	Listener net.Listener
	User     string
	Pass     string
	// Resolve maps a requested host to a dialable address (for tests that
	// use fake domain names). If nil, the host is dialed as-is.
	Resolve func(host string) string

	mu      sync.Mutex
	targets []string
	wg      sync.WaitGroup
}

func (s *Server) Addr() string { return s.Listener.Addr().String() }

func (s *Server) Targets() []string {
	s.mu.Lock()
	defer s.mu.Unlock()
	return append([]string(nil), s.targets...)
}

func (s *Server) record(t string) {
	s.mu.Lock()
	s.targets = append(s.targets, t)
	s.mu.Unlock()
}

func (s *Server) Close() { s.Listener.Close(); s.wg.Wait() }

func listen() net.Listener {
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		panic(err)
	}
	return l
}

// StartSOCKS5 starts a SOCKS5 proxy. If user != "", username/password auth
// is required.
func StartSOCKS5(user, pass string) *Server {
	s := &Server{Listener: listen(), User: user, Pass: pass}
	s.wg.Add(1)
	go func() {
		defer s.wg.Done()
		for {
			c, err := s.Listener.Accept()
			if err != nil {
				return
			}
			go s.serveSOCKS(c)
		}
	}()
	return s
}

// StartHTTP starts an HTTP CONNECT proxy.
func StartHTTP(user, pass string) *Server {
	s := &Server{Listener: listen(), User: user, Pass: pass}
	s.wg.Add(1)
	go func() {
		defer s.wg.Done()
		for {
			c, err := s.Listener.Accept()
			if err != nil {
				return
			}
			go s.serveHTTP(c)
		}
	}()
	return s
}

func (s *Server) dial(host string, port int) (net.Conn, error) {
	h := host
	if s.Resolve != nil {
		h = s.Resolve(host)
	}
	return net.Dial("tcp", net.JoinHostPort(h, strconv.Itoa(port)))
}

func (s *Server) serveSOCKS(c net.Conn) {
	defer c.Close()
	var hdr [2]byte
	if _, err := io.ReadFull(c, hdr[:]); err != nil || hdr[0] != 5 {
		return
	}
	methods := make([]byte, hdr[1])
	io.ReadFull(c, methods)
	want := byte(0)
	if s.User != "" {
		want = 2
	}
	ok := false
	for _, m := range methods {
		if m == want {
			ok = true
		}
	}
	if !ok {
		c.Write([]byte{5, 0xff})
		return
	}
	c.Write([]byte{5, want})
	if want == 2 {
		var v [2]byte
		io.ReadFull(c, v[:])
		u := make([]byte, v[1])
		io.ReadFull(c, u)
		var pl [1]byte
		io.ReadFull(c, pl[:])
		p := make([]byte, pl[0])
		io.ReadFull(c, p)
		if string(u) != s.User || string(p) != s.Pass {
			c.Write([]byte{1, 1})
			return
		}
		c.Write([]byte{1, 0})
	}
	var req [4]byte
	if _, err := io.ReadFull(c, req[:]); err != nil {
		return
	}
	var host string
	switch req[3] {
	case 1:
		b := make([]byte, 4)
		io.ReadFull(c, b)
		host = net.IP(b).String()
	case 4:
		b := make([]byte, 16)
		io.ReadFull(c, b)
		host = net.IP(b).String()
	case 3:
		var l [1]byte
		io.ReadFull(c, l[:])
		b := make([]byte, l[0])
		io.ReadFull(c, b)
		host = string(b)
	}
	var pb [2]byte
	io.ReadFull(c, pb[:])
	port := int(binary.BigEndian.Uint16(pb[:]))
	s.record(net.JoinHostPort(host, strconv.Itoa(port)))
	up, err := s.dial(host, port)
	if err != nil {
		c.Write([]byte{5, 5, 0, 1, 0, 0, 0, 0, 0, 0})
		return
	}
	defer up.Close()
	c.Write([]byte{5, 0, 0, 1, 0, 0, 0, 0, 0, 0})
	netutil.Pipe(c, up)
}

func (s *Server) serveHTTP(c net.Conn) {
	defer c.Close()
	br := bufio.NewReader(c)
	req, err := http.ReadRequest(br)
	if err != nil || req.Method != http.MethodConnect {
		io.WriteString(c, "HTTP/1.1 405 Method Not Allowed\r\n\r\n")
		return
	}
	if s.User != "" {
		want := "Basic " + base64.StdEncoding.EncodeToString([]byte(s.User+":"+s.Pass))
		if req.Header.Get("Proxy-Authorization") != want {
			io.WriteString(c, "HTTP/1.1 407 Proxy Authentication Required\r\n\r\n")
			return
		}
	}
	s.record(req.Host)
	host, portStr, _ := net.SplitHostPort(req.Host)
	port, _ := strconv.Atoi(portStr)
	up, err := s.dial(host, port)
	if err != nil {
		io.WriteString(c, "HTTP/1.1 502 Bad Gateway\r\n\r\n")
		return
	}
	defer up.Close()
	io.WriteString(c, "HTTP/1.1 200 Connection established\r\n\r\n")
	if br.Buffered() > 0 {
		b, _ := br.Peek(br.Buffered())
		up.Write(b)
	}
	netutil.Pipe(c, up)
}

// StartEcho starts a TCP server that writes "hello:<first line>\n" back.
func StartEcho() net.Listener {
	l := listen()
	go func() {
		for {
			c, err := l.Accept()
			if err != nil {
				return
			}
			go func(c net.Conn) {
				defer c.Close()
				line, _ := bufio.NewReader(c).ReadString('\n')
				io.WriteString(c, "hello:"+strings.TrimSpace(line)+"\n")
			}(c)
		}
	}()
	return l
}
