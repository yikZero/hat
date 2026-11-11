package vm

import (
	"bufio"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"os/exec"
	"strings"
	"syscall"
	"time"

	"golang.org/x/crypto/ssh"
	"golang.org/x/sys/unix"

	"hat/internal/config"
	"hat/internal/session"
)

// ErrNotRunning means no daemon is serving the profile.
var ErrNotRunning = errors.New("VM is not running")

func ctlRoundTrip(ctx context.Context, sock string, op string) (net.Conn, *bufio.Reader, CtlResponse, error) {
	var d net.Dialer
	c, err := d.DialContext(ctx, "unix", sock)
	if err != nil {
		return nil, nil, CtlResponse{}, ErrNotRunning
	}
	if dl, ok := ctx.Deadline(); ok {
		c.SetDeadline(dl)
	}
	b, _ := json.Marshal(CtlRequest{V: ProtoVersion, Op: op})
	if _, err := c.Write(append(b, '\n')); err != nil {
		c.Close()
		return nil, nil, CtlResponse{}, err
	}
	br := bufio.NewReader(c)
	line, err := br.ReadBytes('\n')
	if err != nil {
		c.Close()
		return nil, nil, CtlResponse{}, fmt.Errorf("daemon closed the connection: %w", err)
	}
	var resp CtlResponse
	if err := json.Unmarshal(line, &resp); err != nil {
		c.Close()
		return nil, nil, CtlResponse{}, err
	}
	c.SetDeadline(time.Time{})
	return c, br, resp, nil
}

// Status queries the daemon.
func Status(ctx context.Context, name string) (CtlResponse, error) {
	paths, err := PathsFor(name)
	if err != nil {
		return CtlResponse{}, err
	}
	ctx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	c, _, resp, err := ctlRoundTrip(ctx, paths.CtlSock, "status")
	if err != nil {
		return resp, err
	}
	c.Close()
	return resp, nil
}

// Stop asks the daemon to power off the VM and waits for it to exit.
func Stop(ctx context.Context, name string) error {
	paths, err := PathsFor(name)
	if err != nil {
		return err
	}
	c, _, _, err := ctlRoundTrip(ctx, paths.CtlSock, "stop")
	if err != nil {
		return err
	}
	c.Close()
	deadline := time.Now().Add(60 * time.Second)
	for time.Now().Before(deadline) {
		if !daemonAlive(paths.LockFile) {
			return nil
		}
		time.Sleep(300 * time.Millisecond)
	}
	return errors.New("timed out waiting for the VM to stop")
}

// daemonAlive reports whether some process holds the daemon lock.
func daemonAlive(lockFile string) bool {
	f, err := os.OpenFile(lockFile, os.O_RDWR, 0)
	if err != nil {
		return false
	}
	defer f.Close()
	if err := unix.Flock(int(f.Fd()), unix.LOCK_EX|unix.LOCK_NB); err != nil {
		return true
	}
	unix.Flock(int(f.Fd()), unix.LOCK_UN)
	return false
}

// EnsureRunning starts the daemon if needed and waits until the VM is ready.
// Progress messages go to log.
func EnsureRunning(ctx context.Context, p *config.Profile, log io.Writer) error {
	paths, err := PathsFor(p.Name)
	if err != nil {
		return err
	}
	if resp, err := Status(ctx, p.Name); err == nil && resp.State == "ready" {
		return nil
	}
	if !daemonAlive(paths.LockFile) {
		if err := Prepare(ctx, p, log); err != nil {
			return err
		}
		if err := spawnDaemon(p.Name, paths); err != nil {
			return err
		}
		first := !fileExists(paths.KnownHost)
		if first {
			fmt.Fprintf(log, "[hat] First start of profile %q: installing the guest (a few minutes, once)...\n", p.Name)
		} else {
			fmt.Fprintf(log, "[hat] Starting VM for profile %q...\n", p.Name)
		}
	}
	deadline := time.Now().Add(12 * time.Minute)
	lastState := ""
	for time.Now().Before(deadline) {
		resp, err := Status(ctx, p.Name)
		switch {
		case err == nil && resp.State == "ready":
			return nil
		case err == nil && resp.State == "failed":
			return fmt.Errorf("VM failed to start: %s", resp.Error)
		case err == nil && resp.State != lastState && os.Getenv("HAT_DEBUG") != "":
			fmt.Fprintf(log, "[hat] %s\n", resp.State)
		}
		if err == nil {
			lastState = resp.State
		} else if !daemonAlive(paths.LockFile) && time.Since(deadline.Add(-12*time.Minute)) > 5*time.Second {
			return fmt.Errorf("VM daemon exited; see %s", paths.DaemonLog)
		}
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-time.After(500 * time.Millisecond):
		}
	}
	return fmt.Errorf("timed out waiting for the VM; see %s", paths.DaemonLog)
}

func spawnDaemon(name string, paths Paths) error {
	self, err := os.Executable()
	if err != nil {
		return err
	}
	logf, err := os.OpenFile(paths.DaemonLog, os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0o600)
	if err != nil {
		return err
	}
	defer logf.Close()
	devnull, _ := os.Open(os.DevNull)
	defer devnull.Close()
	cmd := exec.Command(self, "__daemon", name)
	cmd.Stdin, cmd.Stdout, cmd.Stderr = devnull, logf, logf
	cmd.Env = daemonEnv()
	cmd.SysProcAttr = &syscall.SysProcAttr{Setsid: true}
	if err := cmd.Start(); err != nil {
		return fmt.Errorf("starting daemon: %w", err)
	}
	return cmd.Process.Release()
}

// daemonEnv strips proxy variables: the daemon must only use the profile's
// upstream, never an ambient proxy setting.
func daemonEnv() []string {
	var out []string
	for _, kv := range os.Environ() {
		k := strings.ToUpper(strings.SplitN(kv, "=", 2)[0])
		if strings.HasSuffix(k, "_PROXY") {
			continue
		}
		out = append(out, kv)
	}
	return out
}

// Connect returns an SSH client to the guest through the daemon.
func Connect(ctx context.Context, p *config.Profile) (*ssh.Client, error) {
	paths, err := PathsFor(p.Name)
	if err != nil {
		return nil, err
	}
	cctx, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()
	c, br, resp, err := ctlRoundTrip(cctx, paths.CtlSock, "dial")
	if err != nil {
		return nil, err
	}
	if !resp.OK {
		c.Close()
		return nil, errors.New(resp.Error)
	}
	signer, _, err := EnsureKey(paths.SSHDir)
	if err != nil {
		c.Close()
		return nil, err
	}
	return session.Connect(&bufConn{Conn: c, r: br}, p.VM.Username, signer, paths.KnownHost)
}

type bufConn struct {
	net.Conn
	r *bufio.Reader
}

func (b *bufConn) Read(p []byte) (int, error) { return b.r.Read(p) }

// Blackhole toggles the kill-switch test mode in the daemon.
func Blackhole(ctx context.Context, name string, on bool) error {
	paths, err := PathsFor(name)
	if err != nil {
		return err
	}
	op := "blackhole-off"
	if on {
		op = "blackhole-on"
	}
	c, _, resp, err := ctlRoundTrip(ctx, paths.CtlSock, op)
	if err != nil {
		return err
	}
	c.Close()
	if !resp.OK {
		return errors.New(resp.Error)
	}
	return nil
}
