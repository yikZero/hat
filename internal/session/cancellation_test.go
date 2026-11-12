package session

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"errors"
	"io"
	"net"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"golang.org/x/crypto/ssh"
)

func cancellationClient(t *testing.T) (*ssh.Client, *stalledReadConn) {
	t.Helper()
	_, key, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	signer, err := ssh.NewSignerFromKey(key)
	if err != nil {
		t.Fatal(err)
	}
	listener := testServer(t, signer.PublicKey())
	t.Cleanup(func() { listener.Close() })
	conn, err := net.Dial("tcp", listener.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	wrapped := &stalledReadConn{Conn: conn, stall: make(chan struct{}), closed: make(chan struct{})}
	client, err := Connect(wrapped, "dev", signer, filepath.Join(t.TempDir(), "known_host"))
	if err != nil {
		conn.Close()
		t.Fatal(err)
	}
	t.Cleanup(func() { client.Close() })
	return client, wrapped
}

// Simulate a frozen guest after a command starts: inbound SSH packets remain
// unread until the entire connection closes.
type stalledReadConn struct {
	net.Conn
	stall, closed chan struct{}
	once          sync.Once
}

func (c *stalledReadConn) Read(p []byte) (int, error) {
	n, err := c.Conn.Read(p)
	select {
	case <-c.stall:
		<-c.closed
		return 0, net.ErrClosed
	default:
		return n, err
	}
}

func (c *stalledReadConn) Close() error {
	c.once.Do(func() { close(c.closed) })
	return c.Conn.Close()
}

// Exercise the reported race while stdout is still being copied into Output's
// private buffer. The server cleans up yes when the SSH channel closes.
func TestOutputCancellation(t *testing.T) {
	client, _ := cancellationClient(t)
	ctx, cancel := context.WithTimeout(context.Background(), 40*time.Millisecond)
	defer cancel()
	_, err := Output(ctx, client, "exec yes cancellation")
	if !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("expected deadline error, got %v", err)
	}
	// Cancelling one session must leave a responsive SSH client usable.
	out, err := Output(context.Background(), client, "printf reusable")
	if err != nil || out != "reusable" {
		t.Fatalf("client after cancellation: out=%q err=%v", out, err)
	}
}

type gatedWriter struct {
	buf     bytes.Buffer
	first   string
	started chan struct{}
	release chan struct{}
	once    sync.Once
}

func (w *gatedWriter) Write(p []byte) (int, error) {
	w.once.Do(func() {
		w.first = string(p)
		close(w.started)
	})
	<-w.release
	return w.buf.Write(p)
}

func TestRunCancellationWaitsForOutput(t *testing.T) {
	for _, stream := range []string{"stdout", "stderr", "combined"} {
		t.Run(stream, func(t *testing.T) {
			client, _ := cancellationClient(t)
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			w := &gatedWriter{started: make(chan struct{}), release: make(chan struct{})}
			var release sync.Once
			unblock := func() { release.Do(func() { close(w.release) }) }
			defer unblock()
			r := Request{Argv: []string{"sh", "-c", "printf stdout; printf stderr >&2"},
				Stdin: strings.NewReader(""), Stdout: io.Discard, Stderr: io.Discard, NoTTY: true}
			if stream != "stderr" {
				r.Stdout = w
			}
			if stream != "stdout" {
				r.Stderr = w
			}
			type result struct {
				code int
				err  error
			}
			done := make(chan result, 1)
			go func() {
				code, err := Run(ctx, client, r)
				done <- result{code, err}
			}()
			select {
			case <-w.started:
			case <-time.After(5 * time.Second):
				t.Fatal("command never wrote output")
			}
			cancel()
			select {
			case got := <-done:
				t.Fatalf("returned before output copying finished: code=%d err=%v", got.code, got.err)
			case <-time.After(50 * time.Millisecond):
			}
			unblock()
			select {
			case got := <-done:
				if got.code != 130 || !errors.Is(got.err, context.Canceled) {
					t.Fatalf("expected cancellation, got code=%d err=%v", got.code, got.err)
				}
			case <-time.After(5 * time.Second):
				t.Fatal("cancellation did not finish after output was released")
			}
			// Cancellation may stop the command before it emits both streams.
			// The write already in progress must finish before Run returns.
			if got := w.buf.String(); !strings.Contains(got, w.first) {
				t.Fatalf("output %q missing in-flight write %q", got, w.first)
			}
		})
	}
}

func TestRunCancellationWithUnresponsiveGuest(t *testing.T) {
	client, conn := cancellationClient(t)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	w := &gatedWriter{started: make(chan struct{}), release: make(chan struct{})}
	close(w.release)
	done := make(chan error, 1)
	go func() {
		code, err := Run(ctx, client, Request{Argv: []string{"sh", "-c", "printf ready; exec sleep 30"},
			Stdin: strings.NewReader(""), Stdout: w, Stderr: io.Discard, NoTTY: true})
		if code != 130 {
			err = errors.New("wrong cancellation exit code")
		}
		done <- err
	}()
	select {
	case <-w.started:
	case <-time.After(5 * time.Second):
		t.Fatal("command never wrote output")
	}
	close(conn.stall)
	cancel()
	select {
	case err := <-done:
		if !errors.Is(err, context.Canceled) {
			t.Fatalf("expected cancellation, got %v", err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("cancellation hung on an unresponsive guest")
	}
	select {
	case <-conn.closed:
	default:
		t.Fatal("unresponsive connection was not closed")
	}
}
