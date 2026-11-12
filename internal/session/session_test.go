package session

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/binary"
	"net"
	"os/exec"
	"path/filepath"
	"strings"
	"syscall"
	"testing"

	"golang.org/x/crypto/ssh"
)

// testServer is a minimal SSH server that runs "exec" requests with sh -c.
func testServer(t *testing.T, clientKey ssh.PublicKey) net.Listener {
	t.Helper()
	_, hk, _ := ed25519.GenerateKey(rand.Reader)
	hs, _ := ssh.NewSignerFromKey(hk)
	cfg := &ssh.ServerConfig{PublicKeyCallback: func(_ ssh.ConnMetadata, k ssh.PublicKey) (*ssh.Permissions, error) {
		if bytes.Equal(k.Marshal(), clientKey.Marshal()) {
			return nil, nil
		}
		return nil, net.ErrClosed
	}}
	cfg.AddHostKey(hs)
	ln, _ := net.Listen("tcp", "127.0.0.1:0")
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			go func() {
				_, chans, reqs, err := ssh.NewServerConn(c, cfg)
				if err != nil {
					return
				}
				go ssh.DiscardRequests(reqs)
				for nc := range chans {
					ch, creqs, _ := nc.Accept()
					go func() {
						for req := range creqs {
							if req.Type != "exec" {
								req.Reply(false, nil)
								continue
							}
							cmdline := string(req.Payload[4:])
							req.Reply(true, nil)
							ctx, cancel := context.WithCancel(context.Background())
							defer cancel()
							go func() {
								for req := range creqs {
									req.Reply(false, nil)
								}
								cancel() // a closed channel must not leave the test command running
							}()
							cmd := exec.CommandContext(ctx, "sh", "-c", cmdline)
							cmd.Stdin, cmd.Stdout, cmd.Stderr = ch, ch, ch.Stderr()
							err := cmd.Run()
							if cmd.ProcessState == nil { // cancelled before the command started
								ch.Close()
								return
							}
							if ws, ok := cmd.ProcessState.Sys().(syscall.WaitStatus); ok && ws.Signaled() {
								p := ssh.Marshal(struct {
									Sig  string
									Core bool
									Msg  string
									Lang string
								}{"TERM", false, "", ""})
								ch.SendRequest("exit-signal", false, p)
							} else {
								code := 0
								if err != nil {
									code = cmd.ProcessState.ExitCode()
								}
								b := make([]byte, 4)
								binary.BigEndian.PutUint32(b, uint32(code))
								ch.SendRequest("exit-status", false, b)
							}
							ch.Close()
							return
						}
					}()
				}
			}()
		}
	}()
	return ln
}

func TestRunPipesEnvExitCodes(t *testing.T) {
	_, ck, _ := ed25519.GenerateKey(rand.Reader)
	signer, _ := ssh.NewSignerFromKey(ck)
	ln := testServer(t, signer.PublicKey())
	defer ln.Close()
	known := filepath.Join(t.TempDir(), "known_host")
	dial := func() *ssh.Client {
		conn, err := net.Dial("tcp", ln.Addr().String())
		if err != nil {
			t.Fatal(err)
		}
		c, err := Connect(conn, "dev", signer, known)
		if err != nil {
			t.Fatal(err)
		}
		return c
	}
	c := dial()
	defer c.Close()
	dir := t.TempDir()
	var out, errb bytes.Buffer
	code, err := Run(context.Background(), c, Request{
		Argv:  []string{"sh", "-c", `echo "$FOO|$(pwd)|$1"; cat; echo oops >&2; exit 7`, "x", "it's a test"},
		Dir:   dir,
		Env:   map[string]string{"FOO": "a b'c"},
		Stdin: strings.NewReader("piped\n"), Stdout: &out, Stderr: &errb, NoTTY: true,
	})
	if err != nil || code != 7 {
		t.Fatalf("code %d err %v stderr %q", code, err, errb.String())
	}
	if want := "a b'c|" + dir + "|it's a test\npiped\n"; out.String() != want {
		t.Fatalf("stdout %q want %q", out.String(), want)
	}
	if errb.String() != "oops\n" {
		t.Fatalf("stderr %q", errb.String())
	}
	// missing dir -> 125 with hint
	errb.Reset()
	code, _ = Run(context.Background(), c, Request{Argv: []string{"true"}, Dir: "/no/such/dir",
		Stdin: strings.NewReader(""), Stdout: &out, Stderr: &errb, NoTTY: true})
	if code != 125 || !strings.Contains(errb.String(), "hat share add") {
		t.Fatalf("code %d stderr %q", code, errb.String())
	}
	// killed by signal -> 143
	code, _ = Run(context.Background(), c, Request{Argv: []string{"sh", "-c", "kill -TERM $$"},
		Stdin: strings.NewReader(""), Stdout: &out, Stderr: &errb, NoTTY: true})
	if code != 143 {
		t.Fatalf("signal exit code %d", code)
	}
	// host key pinned: a different server key must be rejected
	c2 := dial()
	c2.Close()
	ln2 := testServer(t, signer.PublicKey())
	defer ln2.Close()
	conn, _ := net.Dial("tcp", ln2.Addr().String())
	if _, err := Connect(conn, "dev", signer, known); err == nil || !strings.Contains(err.Error(), "host key changed") {
		t.Fatalf("expected host key mismatch, got %v", err)
	}
}

func TestQuote(t *testing.T) {
	for in, want := range map[string]string{"abc": "abc", "": "''", "a b": "'a b'", "it's": `'it'\''s'`, "$HOME": "'$HOME'"} {
		if got := Quote(in); got != want {
			t.Errorf("Quote(%q) = %q, want %q", in, got, want)
		}
	}
}

// Reported from the macOS retest: x/crypto/ssh copies stdout and stderr in
// two goroutines, so passing the same buffer for both raced and could lose
// output. Run under -race (make test / CI).
func TestSharedWriterForStdoutAndStderr(t *testing.T) {
	_, ck, _ := ed25519.GenerateKey(rand.Reader)
	signer, _ := ssh.NewSignerFromKey(ck)
	ln := testServer(t, signer.PublicKey())
	defer ln.Close()
	conn, _ := net.Dial("tcp", ln.Addr().String())
	c, err := Connect(conn, "dev", signer, filepath.Join(t.TempDir(), "kh"))
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	script := `i=0; while [ $i -lt 200 ]; do echo out$i; echo err$i >&2; i=$((i+1)); done`
	for round := 0; round < 5; round++ {
		var buf bytes.Buffer
		code, err := Run(context.Background(), c, Request{Argv: []string{"sh", "-c", script},
			Stdin: strings.NewReader(""), Stdout: &buf, Stderr: &buf, NoTTY: true})
		if err != nil || code != 0 {
			t.Fatal(code, err)
		}
		for _, want := range []string{"out0\n", "out199\n", "err0\n", "err199\n"} {
			if !strings.Contains(buf.String(), want) {
				t.Fatalf("round %d: lost %q (got %d bytes)", round, want, buf.Len())
			}
		}
		out, err := Output(context.Background(), c, script)
		if err != nil || !strings.Contains(out, "out199\n") || strings.Contains(out, "err") {
			t.Fatalf("Output: stdout only expected, got err=%v len=%d", err, len(out))
		}
	}
	_, err = Output(context.Background(), c, "echo visible-error >&2; exit 3")
	if err == nil || !strings.Contains(err.Error(), "visible-error") {
		t.Fatalf("stderr must be reported in the error: %v", err)
	}
}
