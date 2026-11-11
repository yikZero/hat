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
	"path/filepath"
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
// It is safe to call concurrently from many processes: preparing the disk
// and spawning the daemon happen under a per-profile start lock. If the
// daemon is shutting down (e.g. idle stop) it waits for it to exit and
// starts a new one. Progress messages go to log.
func EnsureRunning(ctx context.Context, p *config.Profile, log io.Writer) error {
	paths, err := PathsFor(p.Name)
	if err != nil {
		return err
	}
	if err := os.MkdirAll(paths.Run, 0o700); err != nil {
		return err
	}
	start := time.Now()
	deadline := start.Add(12 * time.Minute)
	spawns, lastState, announced := 0, "", false
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
		}
		// No daemon (or the previous one finished stopping): start one.
		if err != nil && !daemonAlive(paths.LockFile) {
			if spawns >= 3 {
				return fmt.Errorf("VM daemon keeps exiting; see %s", paths.DaemonLog)
			}
			first, err := startDaemonLocked(ctx, p, paths, log)
			if err != nil {
				return err
			}
			spawns++
			if !announced && !quiet() {
				announced = true
				if first {
					fmt.Fprintf(log, "[hat] First start of profile %q: installing the guest (a few minutes, once)...\n", p.Name)
				} else {
					fmt.Fprintf(log, "[hat] Starting VM for profile %q...\n", p.Name)
				}
			}
		}
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-time.After(500 * time.Millisecond):
		}
	}
	return fmt.Errorf("timed out waiting for the VM; see %s", paths.DaemonLog)
}

func quiet() bool { return os.Getenv("HAT_QUIET") != "" }

// startDaemonLocked prepares the profile and spawns the daemon while holding
// the start lock, unless another process got there first.
func startDaemonLocked(ctx context.Context, p *config.Profile, paths Paths, log io.Writer) (firstBoot bool, err error) {
	unlock, err := lockFile(filepath.Join(paths.Run, "start.lock"))
	if err != nil {
		return false, err
	}
	defer unlock()
	if daemonAlive(paths.LockFile) {
		return false, nil // someone else started it while we waited
	}
	if err := Prepare(ctx, p, log); err != nil {
		return false, err
	}
	if err := spawnDaemon(p.Name, paths); err != nil {
		return false, err
	}
	// Hold the start lock until the new daemon owns its lock, so a
	// concurrent caller does not spawn a second one.
	for i := 0; i < 50 && !daemonAlive(paths.LockFile); i++ {
		time.Sleep(100 * time.Millisecond)
	}
	return !fileExists(paths.KnownHost), nil
}

// lockFile takes an exclusive flock (blocking) and returns the unlock func.
func lockFile(path string) (func(), error) {
	f, err := os.OpenFile(path, os.O_CREATE|os.O_RDWR, 0o600)
	if err != nil {
		return nil, err
	}
	if err := unix.Flock(int(f.Fd()), unix.LOCK_EX); err != nil {
		f.Close()
		return nil, err
	}
	return func() { unix.Flock(int(f.Fd()), unix.LOCK_UN); f.Close() }, nil
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
