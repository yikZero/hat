// Package session runs commands in the guest over SSH with a native-feeling
// terminal: PTY only when stdin and stdout are terminals, window resizes,
// signal forwarding, and shell-style exit codes.
package session

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"os/signal"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"syscall"
	"time"

	"golang.org/x/crypto/ssh"
	"golang.org/x/term"

	"hat/internal/netutil"
)

// Connect performs the SSH handshake over conn. The guest host key is
// pinned in knownHostFile on first use (trust on first use).
func Connect(conn net.Conn, user string, signer ssh.Signer, knownHostFile string) (*ssh.Client, error) {
	cfg := &ssh.ClientConfig{
		User:            user,
		Auth:            []ssh.AuthMethod{ssh.PublicKeys(signer)},
		HostKeyCallback: pinHostKey(knownHostFile),
		Timeout:         20 * time.Second,
	}
	c, chans, reqs, err := ssh.NewClientConn(conn, "guest", cfg)
	if err != nil {
		return nil, err
	}
	// Reject every channel the guest tries to open (agent, X11, forwarding).
	go func() {
		for ch := range chans {
			ch.Reject(ssh.Prohibited, "not allowed by hat")
		}
	}()
	return ssh.NewClient(c, nil, reqs), nil
}

func pinHostKey(file string) ssh.HostKeyCallback {
	return func(_ string, _ net.Addr, key ssh.PublicKey) error {
		got := ssh.MarshalAuthorizedKey(key)
		want, err := os.ReadFile(file)
		if errors.Is(err, os.ErrNotExist) {
			if err := os.MkdirAll(filepath.Dir(file), 0o700); err != nil {
				return err
			}
			return os.WriteFile(file, got, 0o600)
		}
		if err != nil {
			return err
		}
		if !bytes.Equal(bytes.TrimSpace(want), bytes.TrimSpace(got)) {
			return fmt.Errorf("guest host key changed (expected key in %s); if you recreated the VM, delete that file", file)
		}
		return nil
	}
}

type Request struct {
	Argv []string
	// Dir is the working directory in the guest ("" = home).
	Dir string
	// Env is set for the command.
	Env map[string]string
	// LoginShell runs the command through `bash -l` so ~/.profile PATH
	// additions (npm -g, pipx, ...) apply.
	LoginShell bool

	Stdin          io.Reader
	Stdout, Stderr io.Writer
	// ForceTTY / NoTTY override auto-detection.
	ForceTTY, NoTTY bool
}

// Command builds the remote command string.
func Command(r Request) string {
	var b strings.Builder
	if r.Dir != "" {
		fmt.Fprintf(&b, "cd -- %s 2>/dev/null || { echo %s >&2; exit 125; }; ",
			Quote(r.Dir), Quote("hat: directory "+r.Dir+" is not available in the VM (is it shared? see: hat share add; a VM started before shares changed or before a hat update needs a restart: hat stop <profile>)"))
	}
	b.WriteString("exec env")
	keys := make([]string, 0, len(r.Env))
	for k := range r.Env {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	for _, k := range keys {
		b.WriteString(" " + Quote(k+"="+r.Env[k]))
	}
	if r.LoginShell {
		b.WriteString(` bash -lc 'exec "$0" "$@"'`)
	}
	for _, a := range r.Argv {
		b.WriteString(" " + Quote(a))
	}
	return b.String()
}

// Quote single-quotes s for POSIX sh.
func Quote(s string) string {
	if s != "" && strings.IndexFunc(s, func(r rune) bool {
		return !(r >= 'a' && r <= 'z' || r >= 'A' && r <= 'Z' || r >= '0' && r <= '9' || strings.ContainsRune("@%+=:,./-_", r))
	}) < 0 {
		return s
	}
	return "'" + strings.ReplaceAll(s, "'", `'\''`) + "'"
}

var sigNames = map[os.Signal]ssh.Signal{
	syscall.SIGINT: ssh.SIGINT, syscall.SIGTERM: ssh.SIGTERM, syscall.SIGHUP: ssh.SIGHUP,
	syscall.SIGQUIT: ssh.SIGQUIT, syscall.SIGUSR1: ssh.SIGUSR1, syscall.SIGUSR2: ssh.SIGUSR2,
}

var sigNums = map[string]int{"INT": 2, "TERM": 15, "HUP": 1, "QUIT": 3, "KILL": 9, "USR1": 10, "USR2": 12,
	"PIPE": 13, "ALRM": 14, "ABRT": 6, "SEGV": 11, "ILL": 4, "FPE": 8, "BUS": 7}

// Run executes the request and returns its exit code.
func Run(ctx context.Context, c *ssh.Client, r Request) (int, error) {
	s, err := c.NewSession()
	if err != nil {
		return 0, err
	}
	defer s.Close()
	if r.Stdin == nil {
		r.Stdin = os.Stdin
	}
	if r.Stdout == nil {
		r.Stdout = os.Stdout
	}
	if r.Stderr == nil {
		r.Stderr = os.Stderr
	}
	// x/crypto/ssh copies stdout and stderr in separate goroutines; if both
	// go to the same writer, serialize the writes (as os/exec does).
	if sameWriter(r.Stdout, r.Stderr) {
		w := &lockedWriter{w: r.Stdout}
		r.Stdout, r.Stderr = w, w
	}
	inF, inIsFile := r.Stdin.(*os.File)
	outF, outIsFile := r.Stdout.(*os.File)
	tty := r.ForceTTY || (!r.NoTTY && inIsFile && outIsFile && term.IsTerminal(int(inF.Fd())) && term.IsTerminal(int(outF.Fd())))

	sigs := make(chan os.Signal, 8)
	signal.Notify(sigs, syscall.SIGINT, syscall.SIGTERM, syscall.SIGHUP, syscall.SIGQUIT, syscall.SIGUSR1, syscall.SIGUSR2, syscall.SIGWINCH)
	defer signal.Stop(sigs)

	if tty {
		fd := int(inF.Fd())
		w, h, err := term.GetSize(int(outF.Fd()))
		if err != nil {
			w, h = 80, 24
		}
		termName := os.Getenv("TERM")
		if termName == "" {
			termName = "xterm-256color"
		}
		if err := s.RequestPty(termName, h, w, ssh.TerminalModes{ssh.ECHO: 1, ssh.TTY_OP_ISPEED: 38400, ssh.TTY_OP_OSPEED: 38400}); err != nil {
			return 0, fmt.Errorf("pty: %w", err)
		}
		if old, err := term.MakeRaw(fd); err == nil {
			defer term.Restore(fd, old)
		}
		s.Stdin, s.Stdout, s.Stderr = r.Stdin, r.Stdout, r.Stderr
	} else {
		s.Stdout, s.Stderr = r.Stdout, r.Stderr
		stdin, err := s.StdinPipe()
		if err != nil {
			return 0, err
		}
		go func() {
			io.Copy(stdin, r.Stdin)
			stdin.Close() // propagate EOF
		}()
	}

	ttyDelivers := netutil.TerminalDeliversSignals()
	if err := s.Start(Command(r)); err != nil {
		return 0, err
	}
	done := make(chan error, 1)
	go func() { done <- s.Wait() }()
	for {
		select {
		case err := <-done:
			return exitCode(err)
		case sig := <-sigs:
			if sig == syscall.SIGWINCH {
				if tty {
					if w, h, err := term.GetSize(int(outF.Fd())); err == nil {
						s.WindowChange(h, w)
					}
				}
				continue
			}
			if tty && (sig == syscall.SIGINT || sig == syscall.SIGQUIT) && ttyDelivers {
				continue // raw mode: ^C/^\ travel as bytes through the PTY
			}
			if name, ok := sigNames[sig]; ok {
				s.Signal(name)
			}
		case <-ctx.Done():
			stopSession(c, s, done)
			return 130, ctx.Err()
		}
	}
}

func exitCode(err error) (int, error) {
	if err == nil {
		return 0, nil
	}
	var ee *ssh.ExitError
	if errors.As(err, &ee) {
		if sig := ee.Signal(); sig != "" {
			if n, ok := sigNums[strings.TrimPrefix(sig, "SIG")]; ok {
				return 128 + n, nil
			}
			return 128 + 1, nil
		}
		return ee.ExitStatus(), nil
	}
	var em *ssh.ExitMissingError
	if errors.As(err, &em) {
		return 255, errors.New("connection to the VM was lost")
	}
	return 255, err
}

// Output runs a command (no TTY) and returns its stdout. Stderr is captured
// separately and included in the error if the command fails.
func Output(ctx context.Context, c *ssh.Client, script string) (string, error) {
	s, err := c.NewSession()
	if err != nil {
		return "", err
	}
	defer s.Close()
	var stdout, stderr bytes.Buffer
	s.Stdout, s.Stderr = &stdout, &stderr
	errc := make(chan error, 1)
	go func() { errc <- s.Run(script) }()
	select {
	case err := <-errc:
		if err != nil && stderr.Len() > 0 {
			err = fmt.Errorf("%w: %s", err, strings.TrimSpace(stderr.String()))
		}
		return stdout.String(), err
	case <-ctx.Done():
		stopSession(c, s, errc)
		return stdout.String(), ctx.Err()
	}
}

// stopSession joins the SSH output copies before their writers are returned to
// the caller. If the guest no longer acknowledges channel closure, close the
// connection too so cancellation does not wait indefinitely for the guest.
func stopSession(c *ssh.Client, s *ssh.Session, done <-chan error) {
	forceClose := time.AfterFunc(time.Second, func() { c.Close() })
	defer forceClose.Stop()
	s.Signal(ssh.SIGTERM)
	s.Close()
	<-done
}

type lockedWriter struct {
	mu sync.Mutex
	w  io.Writer
}

func (l *lockedWriter) Write(p []byte) (int, error) {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.w.Write(p)
}

// sameWriter reports whether a and b are the same writer (false for
// writers whose dynamic type is not comparable).
func sameWriter(a, b io.Writer) (same bool) {
	defer func() {
		if recover() != nil {
			same = false
		}
	}()
	return a == b
}
