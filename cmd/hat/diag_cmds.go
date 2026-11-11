package main

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"time"

	"golang.org/x/crypto/ssh"

	"hat/internal/clierr"

	"hat/internal/config"
	"hat/internal/lite"
	"hat/internal/seatbelt"
	"hat/internal/session"
	"hat/internal/shim"
	"hat/internal/upstream"
	"hat/internal/vm"
)

type checkItem struct {
	Name   string `json:"name"`
	Status string `json:"status"` // pass | fail | warn | info
	Detail string `json:"detail,omitempty"`
}

type checker struct {
	failed int
	Items  []checkItem
}

func (c *checker) add(status, name, detail string) {
	c.Items = append(c.Items, checkItem{name, status, detail})
	if jsonOut {
		return
	}
	if detail != "" {
		detail = " — " + detail
	}
	fmt.Printf("  [%s] %s%s\n", strings.ToUpper(status), name, detail)
}

func (c *checker) result(ok bool, name, detail string) {
	if ok {
		c.add("pass", name, detail)
	} else {
		c.failed++
		c.add("fail", name, detail)
	}
}

func (c *checker) info(name, detail string) { c.add("info", name, detail) }
func (c *checker) warn(name, detail string) { c.add("warn", name, detail) }

// finishChecks prints/emits the summary and returns the exit status.
func (c *checker) finish(subject string) (int, error) {
	if jsonOut {
		emit(map[string]any{"subject": subject, "ok": c.failed == 0, "failed": c.failed, "items": c.Items})
	} else if c.failed > 0 {
		fmt.Printf("\n%d check(s) FAILED\n", c.failed)
	} else {
		fmt.Println("\nAll checks passed.")
	}
	if c.failed > 0 {
		return 0, exitError{5}
	}
	return 0, nil
}

type ipInfo struct {
	IP       string `json:"ip"`
	Query    string `json:"query"`
	Country  string `json:"country"`
	Timezone string `json:"timezone"`
}

func parseIPInfo(out string) (ipInfo, bool) {
	var i ipInfo
	start := strings.Index(out, "{")
	if start < 0 || json.Unmarshal([]byte(out[start:strings.LastIndex(out, "}")+1]), &i) != nil {
		return i, false
	}
	if i.IP == "" {
		i.IP = i.Query
	}
	return i, i.IP != ""
}

// egressProbe asks two public "what is my IP" services (HTTPS, then HTTP).
const egressProbe = `curl -fsS --max-time 20 https://ipinfo.io/json 2>/dev/null || curl -fsS --max-time 20 'http://ip-api.com/json/?fields=query,country,timezone'`

func cmdCheck(args []string) (int, error) {
	fs := flag.NewFlagSet("check", flag.ContinueOnError)
	jsonFlag(fs)
	pos, err := parseArgs(fs, args)
	if err != nil {
		return 2, err
	}
	name, err := needName(pos, "check <profile> [--json]")
	if err != nil {
		return 2, err
	}
	p, err := config.Load(name)
	if err != nil {
		return 1, err
	}
	if !jsonOut {
		fmt.Printf("Checking profile %q (%s mode, proxy %s)\n", p.Name, p.Mode, upstream.Redact(p.Proxy.URL))
	}
	c := &checker{}
	if p.Mode == config.ModeLite {
		err = checkLite(p, c)
	} else {
		err = checkVM(p, c)
	}
	if err != nil {
		return 1, err
	}
	return c.finish(p.Name)
}

func liteOut(p *config.Profile, script string) (string, int) {
	var out bytes.Buffer
	code, err := lite.Run(p, lite.Options{Argv: []string{"/bin/sh", "-c", script}, Stdin: strings.NewReader(""),
		Stdout: &out, Stderr: &out, Quiet: true})
	if err != nil {
		return err.Error(), 1
	}
	return out.String(), code
}

func checkLite(p *config.Profile, c *checker) error {
	if runtime.GOOS != "darwin" {
		return errors.New("lite mode checks require macOS")
	}
	out, code := liteOut(p, egressProbe)
	info, ok := parseIPInfo(out)
	c.result(code == 0 && ok, "egress through proxy", fmt.Sprintf("IP %s, country %s, timezone %s", info.IP, info.Country, info.Timezone))
	if ok && info.Timezone != "" && info.Timezone != p.Timezone {
		c.warn("timezone", fmt.Sprintf("profile uses %s but the exit IP looks like %s", p.Timezone, info.Timezone))
	}
	_, code = liteOut(p, "curl -sS --noproxy '*' --max-time 5 http://1.1.1.1/")
	c.result(code != 0, "direct connection blocked (bypassing the proxy fails)", "")
	out, _ = liteOut(p, "dscacheutil -q host -a name example.com; curl -sS --noproxy '*' --max-time 5 http://example.com/ 2>&1")
	c.result(!strings.Contains(out, "ip_address") && !strings.Contains(out, "<html"), "local DNS resolution blocked (no DNS leak)", "")
	_, code = liteOut(p, "dig @8.8.8.8 example.com +time=2 +tries=1")
	c.result(code != 0, "UDP blocked", "")
	out, _ = liteOut(p, `echo "$TZ|$LANG|$(date +%Z)"`)
	c.info("TZ|LANG|zone", strings.TrimSpace(out))

	// Kill switch: same sandbox, upstream pointing at a closed port.
	dead := *p
	l, _ := net.Listen("tcp", "127.0.0.1:0")
	addr := l.Addr().String()
	l.Close()
	dead.Proxy.URL, dead.Proxy.Password, dead.Proxy.AllowLocalUpstream = "socks5://"+addr, config.PasswordNone, true
	_, code = liteOut(&dead, "curl -fsS --max-time 10 http://example.com/ >/dev/null")
	c.result(code != 0, "kill switch (proxy down => no connection)", "")
	return nil
}

func vmOut(ctx context.Context, cl *ssh.Client, script string) (string, int) {
	var out bytes.Buffer
	// bash, not sh: Debian's sh is dash, which lacks /dev/udp and /dev/tcp.
	code, err := session.Run(ctx, cl, session.Request{Argv: []string{"bash", "-c", script}, NoTTY: true,
		Stdin: strings.NewReader(""), Stdout: &out, Stderr: &out})
	if err != nil {
		return err.Error(), 255
	}
	return out.String(), code
}

func checkVM(p *config.Profile, c *checker) error {
	ctx := context.Background()
	if err := vm.EnsureRunning(ctx, p, os.Stderr); err != nil {
		return clierr.Wrap(clierr.VMFailed, "hat debug-bundle "+p.Name, err)
	}
	cl, err := vm.Connect(ctx, p)
	if err != nil {
		return err
	}
	defer cl.Close()
	st, _ := config.LoadState(p.Name)

	out, _ := vmOut(ctx, cl, `hostname; cat /etc/machine-id; cat /sys/class/net/e*/address 2>/dev/null | head -1; date +%Z; echo "$LANG"; id -u`)
	f := strings.Split(strings.TrimSpace(out), "\n")
	get := func(i int) string {
		if i < len(f) {
			return strings.TrimSpace(f[i])
		}
		return ""
	}
	c.result(get(0) == p.VM.Hostname, "hostname", get(0))
	c.result(get(1) == st.MachineID, "machine-id", get(1))
	c.result(get(2) == st.MAC, "MAC address", get(2))
	c.info("timezone / LANG / uid", get(3)+" / "+get(4)+" / "+get(5))

	out, code := vmOut(ctx, cl, egressProbe)
	info, ok := parseIPInfo(out)
	c.result(code == 0 && ok, "egress through proxy", fmt.Sprintf("IP %s, country %s, timezone %s", info.IP, info.Country, info.Timezone))
	if ok && info.Timezone != "" && info.Timezone != p.Timezone {
		c.warn("timezone", fmt.Sprintf("profile uses %s but the exit IP looks like %s", p.Timezone, info.Timezone))
	}
	out, _ = vmOut(ctx, cl, "getent ahostsv4 example.com | head -1")
	c.result(strings.HasPrefix(strings.TrimSpace(out), "198.18.") || strings.HasPrefix(strings.TrimSpace(out), "198.19."),
		"DNS answered locally (names resolved by the proxy, no DNS leak)", strings.TrimSpace(out))
	_, code = vmOut(ctx, cl, "curl -sS --max-time 5 http://169.254.169.254/ && curl -sS --max-time 5 http://192.168.127.1/")
	c.result(code != 0, "host / metadata / private addresses unreachable", "")

	before, _ := vm.Status(ctx, p.Name)
	vmOut(ctx, cl, `for i in 1 2 3; do (echo x > /dev/udp/1.1.1.1/443) 2>/dev/null; done; true`)
	time.Sleep(500 * time.Millisecond)
	after, _ := vm.Status(ctx, p.Name)
	c.result(after.UDPDropped > before.UDPDropped, "UDP dropped", fmt.Sprintf("%d dropped so far", after.UDPDropped))

	if err := vm.Blackhole(ctx, p.Name, true); err != nil {
		return err
	}
	_, code = vmOut(ctx, cl, "curl -fsS --max-time 10 https://example.com/ >/dev/null")
	if err := vm.Blackhole(ctx, p.Name, false); err != nil {
		return err
	}
	c.result(code != 0, "kill switch (proxy down => no connection)", "")
	return nil
}

func pathHasFirst(dir string) bool {
	for _, d := range filepath.SplitList(os.Getenv("PATH")) {
		if d == "" {
			continue
		}
		return d == dir
	}
	return false
}

func cmdDoctor(args []string) (int, error) {
	fs := flag.NewFlagSet("doctor", flag.ContinueOnError)
	jsonFlag(fs)
	if _, err := parseArgs(fs, args); err != nil {
		return 2, err
	}
	c := &checker{}
	if !jsonOut {
		fmt.Printf("%s %s on %s/%s\n", config.App, Version, runtime.GOOS, runtime.GOARCH)
	}
	c.result(runtime.GOOS == "darwin", "macOS", "")
	c.result(runtime.GOARCH == "arm64", "Apple Silicon (vm mode)", "")
	_, err := os.Stat(lite.SandboxExec)
	c.result(err == nil, "sandbox-exec available (lite mode)", lite.SandboxExec)
	if v, err := vm.VfkitVersion(context.Background(), vm.VfkitBin); err != nil {
		c.result(false, "vfkit (vm mode)", err.Error())
	} else {
		c.result(true, "vfkit (vm mode)", v)
	}
	home, _ := config.Home()
	if st, err := os.Stat(home); err == nil {
		c.result(st.Mode().Perm()&0o077 == 0, "~/.hat not accessible by other users", fmt.Sprintf("%s mode %o", home, st.Mode().Perm()))
	}
	bin, _ := config.BinDir()
	f, _ := shim.Load()
	if f != nil && len(f.Shims) > 0 {
		c.result(pathHasFirst(bin), "shim directory is first in PATH", bin)
		for _, n := range f.Names() {
			got, err := exec.LookPath(n)
			c.result(err == nil && filepath.Dir(got) == bin, "shim "+n+" wins on PATH", got)
		}
		if !jsonOut {
			fmt.Println("  (after changing PATH run `hash -r` / `rehash`; IDEs and GUI apps may not use your shell PATH)")
		}
	}
	for _, k := range []string{"HTTP_PROXY", "HTTPS_PROXY", "ALL_PROXY"} {
		if v := os.Getenv(k); v != "" {
			c.info("host "+k, upstream.Redact(v)+" (hat ignores it; profiles always use their own proxy)")
		}
	}
	return c.finish("doctor")
}

func cmdDebugBundle(args []string) error {
	name, err := needName(args, "debug-bundle <profile>")
	if err != nil {
		return err
	}
	p, err := config.Load(name)
	if err != nil {
		return err
	}
	out := fmt.Sprintf("hat-debug-%s-%s.tar.gz", name, time.Now().Format("20060102-150405"))
	f, err := os.OpenFile(out, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0o600)
	if err != nil {
		return err
	}
	defer f.Close()
	gz := gzip.NewWriter(f)
	tw := tar.NewWriter(gz)
	add := func(n string, b []byte) {
		tw.WriteHeader(&tar.Header{Name: n, Mode: 0o600, Size: int64(len(b)), ModTime: time.Now()})
		tw.Write(b)
	}
	run := func(c string, a ...string) []byte {
		o, err := exec.Command(c, a...).CombinedOutput()
		if err != nil {
			o = append(o, []byte("\nerror: "+err.Error())...)
		}
		return o
	}
	tail := func(path string, n int) []byte {
		b, err := os.ReadFile(path)
		if err != nil {
			return []byte(err.Error())
		}
		if len(b) > n {
			b = b[len(b)-n:]
		}
		return b
	}
	add("versions.txt", []byte(fmt.Sprintf("hat %s %s/%s\n%s\n%s", Version, runtime.GOOS, runtime.GOARCH,
		run("sw_vers"), run(vm.VfkitBin, "--version"))))
	dir, _ := config.Dir(name)
	pt, _ := os.ReadFile(filepath.Join(dir, "profile.toml"))
	add("profile.toml", pt) // contains no password (passwords are stored separately)
	st, _ := os.ReadFile(filepath.Join(dir, "state.json"))
	add("state.json", st)
	paths, _ := vm.PathsFor(name)
	add("daemon.log", tail(paths.DaemonLog, 512<<10))
	add("console.log", tail(paths.ConsoleLog, 512<<10))
	ud, _ := os.ReadFile(paths.UserData)
	add("user-data", ud)
	if s, err := vm.Status(context.Background(), name); err == nil {
		b, _ := json.MarshalIndent(s, "", "  ")
		add("status.json", b)
	}
	home, _ := config.Home()
	sb, _ := seatbelt.Generate(seatbelt.Options{ProxyPort: 12345, HatHome: home, AllowTrustd: p.Lite.AllowTrustd})
	add("lite-profile.sb", []byte(sb))
	tw.Close()
	gz.Close()
	fmt.Printf("Wrote %s (no passwords included; review before sharing)\n", out)
	return nil
}
