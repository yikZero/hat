package vm

import (
	"bufio"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"net"
	"os"
	"os/exec"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"time"

	"github.com/containers/gvisor-tap-vsock/pkg/transport"
	"golang.org/x/crypto/ssh"
	"golang.org/x/sys/unix"

	"hat/internal/config"
	"hat/internal/netstack"
	"hat/internal/secret"
	"hat/internal/session"
	"hat/internal/upstream"
)

// VfkitBin is the vfkit executable (found on PATH by default; override
// with HAT_VFKIT).
var VfkitBin = func() string {
	if v := os.Getenv("HAT_VFKIT"); v != "" {
		return v
	}
	return "vfkit"
}()

// Daemon hosts one profile's VM: vfkit + the proxy-only network stack +
// the control socket.
type Daemon struct {
	p     *config.Profile
	st    *config.State
	paths Paths
	log   *log.Logger

	net       *netstack.Stack
	vfkit     *exec.Cmd
	vfkitDone chan struct{} // closed when vfkit has exited
	signer    ssh.Signer

	mu       sync.Mutex
	state    string
	err      string
	ready    chan struct{}
	sessions atomic.Int32
	lastUse  atomic.Int64
	upstream string

	stopOnce sync.Once
	stopped  chan struct{}
}

// RunDaemon runs in the foreground until the VM stops. It is started by the
// client as a detached `hat __daemon <profile>` process.
func RunDaemon(name string) error {
	p, err := config.Load(name)
	if err != nil {
		return err
	}
	paths, err := PathsFor(name)
	if err != nil {
		return err
	}
	if err := os.MkdirAll(paths.Run, 0o700); err != nil {
		return err
	}
	lock, err := os.OpenFile(paths.LockFile, os.O_CREATE|os.O_RDWR, 0o600)
	if err != nil {
		return err
	}
	defer lock.Close()
	if err := unix.Flock(int(lock.Fd()), unix.LOCK_EX|unix.LOCK_NB); err != nil {
		return fmt.Errorf("daemon for %q is already running", name)
	}
	st, err := config.LoadState(name)
	if err != nil {
		return err
	}
	d := &Daemon{p: p, st: st, paths: paths, ready: make(chan struct{}), stopped: make(chan struct{}),
		log: log.New(os.Stderr, "", log.LstdFlags|log.Lmicroseconds)}
	d.setState("starting", "")
	d.lastUse.Store(time.Now().Unix())
	return d.run()
}

func (d *Daemon) setState(s, errMsg string) {
	d.mu.Lock()
	d.state, d.err = s, errMsg
	d.mu.Unlock()
	if errMsg != "" {
		d.log.Printf("state=%s error=%s", s, errMsg)
	} else {
		d.log.Printf("state=%s", s)
	}
}

func (d *Daemon) fail(err error) error {
	d.setState("failed", err.Error())
	return err
}

func (d *Daemon) run() error {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	// Control socket first, so clients can see progress and errors.
	os.Remove(d.paths.CtlSock)
	ctl, err := net.Listen("unix", d.paths.CtlSock)
	if err != nil {
		return d.fail(fmt.Errorf("control socket: %w", err))
	}
	os.Chmod(d.paths.CtlSock, 0o600)
	defer os.Remove(d.paths.CtlSock)
	go d.serveCtl(ctl)

	err = d.boot(ctx)
	if err != nil {
		d.fail(err)
		// Keep reporting the failure briefly so the waiting client sees it.
		time.Sleep(3 * time.Second)
		d.shutdown()
		return err
	}
	go d.idleWatch()
	<-d.stopped
	return nil
}

func (d *Daemon) boot(ctx context.Context) error {
	if _, err := VfkitVersion(ctx, VfkitBin); err != nil {
		return err
	}
	rawURL, err := secret.ProxyURL(d.p)
	if err != nil {
		return err
	}
	dialer, err := upstream.New(rawURL)
	if err != nil {
		return err
	}
	d.upstream = dialer.String()
	d.net, err = netstack.New(netstack.Config{Dialer: dialer, GuestMAC: d.st.MAC,
		Logf: func(f string, a ...any) { d.log.Printf("net: "+f, a...) }})
	if err != nil {
		return err
	}
	signer, _, err := EnsureKey(d.paths.SSHDir)
	if err != nil {
		return err
	}
	d.signer = signer

	// Network: hat binds the unixgram socket; vfkit connects to it.
	os.Remove(d.paths.NetSock)
	netConn, err := transport.ListenUnixgram("unixgram://" + d.paths.NetSock)
	if err != nil {
		return fmt.Errorf("network socket: %w", err)
	}
	go func() {
		conn, err := transport.AcceptVfkit(netConn)
		if err != nil {
			d.log.Printf("vfkit network handshake: %v", err)
			return
		}
		if err := d.net.AcceptVfkit(ctx, conn); err != nil && ctx.Err() == nil {
			d.log.Printf("vm network ended: %v", err)
		}
	}()

	killOrphan(d.paths.PidFile)
	shares, err := d.p.ExpandedShares()
	if err != nil {
		return err
	}
	var vshares []VfkitShare
	for i, s := range shares {
		if _, err := os.Stat(s.Path); err != nil {
			return fmt.Errorf("shared directory %s: %w", s.Path, err)
		}
		// vfkit gets the resolved host path; the guest mounts it at s.Path.
		vshares = append(vshares, VfkitShare{Tag: "hat" + strconv.Itoa(i), Path: config.RealPath(s.Path)})
	}
	args, err := VfkitArgs(VfkitOptions{
		CPUs: d.p.VM.CPUs, MemoryMB: d.p.VM.MemoryMB, EFIVars: d.paths.EFIVars, Disk: d.paths.Disk,
		NetSocket: d.paths.NetSock, MAC: d.st.MAC, ConsoleLog: d.paths.ConsoleLog, PidFile: d.paths.PidFile,
		Shares: vshares, UserData: d.paths.UserData, MetaData: d.paths.MetaData,
	})
	if err != nil {
		return err
	}
	d.log.Printf("starting: %s %s", VfkitBin, strings.Join(args, " "))
	cmd := exec.Command(VfkitBin, args...)
	cmd.Stdout, cmd.Stderr = d.log.Writer(), d.log.Writer()
	cmd.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}
	if err := cmd.Start(); err != nil {
		return fmt.Errorf("starting vfkit: %w", err)
	}
	d.vfkit = cmd
	d.vfkitDone = make(chan struct{})
	go func() {
		err := cmd.Wait()
		close(d.vfkitDone)
		d.log.Printf("vfkit exited: %v", err)
		d.shutdown()
	}()

	d.setState("booting", "")
	firstBoot := !fileExists(d.paths.KnownHost)
	timeout := 3 * time.Minute
	if firstBoot {
		timeout = 10 * time.Minute // cloud-init + reboot
	}
	bctx, bcancel := context.WithTimeout(ctx, timeout)
	defer bcancel()
	if err := d.waitReady(bctx); err != nil {
		return fmt.Errorf("VM did not become ready: %w (see %s and %s)", err, d.paths.ConsoleLog, d.paths.DaemonLog)
	}
	d.setState("ready", "")
	close(d.ready)
	return nil
}

// ReadyProbe prints the machine-id only once first-boot provisioning has
// finished AND the VM has rebooted since (cloud-init reboots at the end of
// the first boot to apply the machine-id).
const ReadyProbe = `test -f /var/lib/hat-provisioned && ! grep -qx "$(cat /proc/sys/kernel/random/boot_id)" /var/lib/hat-firstboot-id 2>/dev/null && cat /etc/machine-id`

// waitReady waits until SSH works, first-boot provisioning has finished
// (machine-id applied after the reboot), then reconciles settings.
func (d *Daemon) waitReady(ctx context.Context) error {
	var last error
	for {
		select {
		case <-ctx.Done():
			if last != nil {
				return last
			}
			return ctx.Err()
		case <-d.stopped:
			return errors.New("vfkit exited")
		case <-time.After(2 * time.Second):
		}
		c, err := d.sshClient(ctx)
		if err != nil {
			if strings.Contains(err.Error(), "host key changed") {
				return err // will not fix itself; fail fast
			}
			last = err
			continue
		}
		out, err := session.Output(ctx, c, ReadyProbe)
		if err != nil || strings.TrimSpace(out) != d.st.MachineID {
			c.Close()
			last = errors.New("first-boot provisioning still running")
			continue
		}
		err = d.reconcile(ctx, c)
		c.Close()
		return err
	}
}

func (d *Daemon) sshClient(ctx context.Context) (*ssh.Client, error) {
	dctx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
	conn, err := d.net.DialGuest(dctx, 22)
	if err != nil {
		return nil, err
	}
	c, err := session.Connect(conn, d.p.VM.Username, d.signer, d.paths.KnownHost)
	if err != nil {
		conn.Close()
		return nil, err
	}
	return c, nil
}

// reconcile applies settings that may have changed since first boot.
func (d *Daemon) reconcile(ctx context.Context, c *ssh.Client) error {
	q := session.Quote
	var sb strings.Builder
	sb.WriteString("set -e\n")
	fmt.Fprintf(&sb, "sudo date -u -s @%d >/dev/null\n", time.Now().Unix())
	fmt.Fprintf(&sb, "[ \"$(hostname)\" = %s ] || sudo hostnamectl set-hostname %s\n", q(d.p.VM.Hostname), q(d.p.VM.Hostname))
	fmt.Fprintf(&sb, "sudo timedatectl set-timezone %s\n", q(d.p.Timezone))
	shares, _ := d.p.ExpandedShares()
	for i, s := range shares {
		opt := "rw"
		if s.ReadOnly {
			opt = "ro"
		}
		fmt.Fprintf(&sb, "sudo mkdir -p %s; mountpoint -q %s || sudo mount -t virtiofs -o %s hat%d %s\n",
			q(s.Path), q(s.Path), opt, i, q(s.Path))
	}
	out, err := session.Output(ctx, c, sb.String())
	if err != nil {
		return fmt.Errorf("applying profile settings in the VM: %v: %s", err, strings.TrimSpace(out))
	}
	return nil
}

func (d *Daemon) serveCtl(ln net.Listener) {
	for {
		c, err := ln.Accept()
		if err != nil {
			return
		}
		go d.handleCtl(c)
	}
}

func (d *Daemon) status() CtlResponse {
	d.mu.Lock()
	r := CtlResponse{V: ProtoVersion, OK: d.state != "failed", State: d.state, Error: d.err,
		Sessions: int(d.sessions.Load()), Upstream: d.upstream, PID: os.Getpid()}
	d.mu.Unlock()
	if d.net != nil {
		r.GuestIP = d.net.GuestIP()
		r.UpstreamOK = d.net.Stats.UpstreamOK.Load()
		r.UpstreamFailed = d.net.Stats.UpstreamFailed.Load()
		r.Refused = d.net.Stats.Refused.Load()
		r.UDPDropped = d.net.Stats.UDPDropped.Load()
		r.DNSQueries = d.net.Stats.DNSQueries.Load()
		if e := d.net.LastError(); e != nil {
			r.LastError = e.Error()
		}
	}
	return r
}

func (d *Daemon) handleCtl(c net.Conn) {
	defer c.Close()
	c.SetReadDeadline(time.Now().Add(10 * time.Second))
	br := bufio.NewReader(c)
	line, err := br.ReadBytes('\n')
	if err != nil {
		return
	}
	c.SetReadDeadline(time.Time{})
	var req CtlRequest
	enc := json.NewEncoder(c)
	if err := json.Unmarshal(line, &req); err != nil || req.V != ProtoVersion {
		enc.Encode(CtlResponse{V: ProtoVersion, Error: fmt.Sprintf("protocol mismatch (daemon speaks v%d); run: hat stop %s", ProtoVersion, d.p.Name)})
		return
	}
	switch req.Op {
	case "status":
		enc.Encode(d.status())
	case "blackhole-on", "blackhole-off":
		if d.net == nil {
			enc.Encode(CtlResponse{V: ProtoVersion, Error: "network not started"})
			return
		}
		d.net.SetBlackhole(req.Op == "blackhole-on")
		d.log.Printf("kill-switch test mode: %s", req.Op)
		enc.Encode(CtlResponse{V: ProtoVersion, OK: true, State: d.status().State})
	case "stop":
		enc.Encode(CtlResponse{V: ProtoVersion, OK: true, State: "stopping"})
		go d.shutdown()
	case "dial":
		if st := d.status().State; st == "stopping" {
			enc.Encode(CtlResponse{V: ProtoVersion, State: st, Error: "VM is stopping"})
			return
		}
		select {
		case <-d.ready:
		case <-d.stopped:
			enc.Encode(CtlResponse{V: ProtoVersion, Error: "VM stopped: " + d.status().Error})
			return
		}
		ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
		g, err := d.net.DialGuest(ctx, 22)
		cancel()
		if err != nil {
			enc.Encode(CtlResponse{V: ProtoVersion, Error: "connecting to the VM: " + err.Error()})
			return
		}
		defer g.Close()
		d.sessions.Add(1)
		defer func() { d.sessions.Add(-1); d.lastUse.Store(time.Now().Unix()) }()
		enc.Encode(CtlResponse{V: ProtoVersion, OK: true, State: "ready"})
		var wg sync.WaitGroup
		wg.Add(2)
		go func() { defer wg.Done(); io.Copy(g, br); g.(interface{ CloseWrite() error }).CloseWrite() }()
		go func() { defer wg.Done(); io.Copy(c, g); c.(*net.UnixConn).CloseWrite() }()
		wg.Wait()
	default:
		enc.Encode(CtlResponse{V: ProtoVersion, Error: "unknown op " + req.Op})
	}
}

func (d *Daemon) idleWatch() {
	limit := time.Duration(d.p.VM.IdleStopMinutes) * time.Minute
	if limit <= 0 {
		return
	}
	t := time.NewTicker(30 * time.Second)
	defer t.Stop()
	for {
		select {
		case <-d.stopped:
			return
		case <-t.C:
			if d.sessions.Load() == 0 && time.Since(time.Unix(d.lastUse.Load(), 0)) > limit {
				d.log.Printf("idle for %s, stopping", limit)
				d.shutdown()
				return
			}
		}
	}
}

// shutdown powers off the guest gracefully, then escalates.
func (d *Daemon) shutdown() {
	d.stopOnce.Do(func() {
		d.mu.Lock()
		if d.state != "failed" {
			d.state = "stopping"
		}
		d.mu.Unlock()
		if d.vfkit != nil && !closed(d.vfkitDone) {
			if d.net != nil && d.signer != nil {
				ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
				if c, err := d.sshClient(ctx); err == nil {
					session.Output(ctx, c, "sudo systemctl poweroff")
					c.Close()
				}
				cancel()
			}
			waitExit(d.vfkit, d.vfkitDone, 30*time.Second, syscall.SIGTERM)
			waitExit(d.vfkit, d.vfkitDone, 10*time.Second, syscall.SIGKILL)
		}
		if d.net != nil {
			d.net.Close()
		}
		os.Remove(d.paths.NetSock)
		os.Remove(d.paths.PidFile)
		close(d.stopped)
	})
}

// waitExit waits for done, then sends sig if the process is still running.
func waitExit(cmd *exec.Cmd, done <-chan struct{}, wait time.Duration, sig syscall.Signal) {
	select {
	case <-done:
	case <-time.After(wait):
		cmd.Process.Signal(sig)
	}
}

func closed(ch <-chan struct{}) bool {
	select {
	case <-ch:
		return true
	default:
		return false
	}
}

// killOrphan stops a vfkit left behind by a crashed daemon.
func killOrphan(pidFile string) {
	b, err := os.ReadFile(pidFile)
	if err != nil {
		return
	}
	pid, err := strconv.Atoi(strings.TrimSpace(string(b)))
	if err != nil || pid <= 1 {
		return
	}
	if out, err := exec.Command("ps", "-o", "comm=", "-p", strconv.Itoa(pid)).Output(); err == nil &&
		strings.Contains(string(out), "vfkit") {
		syscall.Kill(pid, syscall.SIGTERM)
		time.Sleep(3 * time.Second)
		syscall.Kill(pid, syscall.SIGKILL)
	}
	os.Remove(pidFile)
}

func fileExists(p string) bool {
	_, err := os.Stat(p)
	return err == nil
}
