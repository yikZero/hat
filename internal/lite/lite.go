// Package lite runs a command in lite mode: a local bridge proxy plus a
// deny-by-default macOS sandbox whose only network egress is the bridge.
package lite

import (
	"errors"
	"fmt"
	"io"
	"net/url"
	"os"
	"os/exec"
	"os/signal"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"syscall"

	"hat/internal/bridge"
	"hat/internal/config"
	"hat/internal/seatbelt"
	"hat/internal/secret"
	"hat/internal/upstream"
)

// SandboxExec is the sandbox launcher; replaced in tests on non-macOS.
var SandboxExec = "/usr/bin/sandbox-exec"

// WrapForTest, when non-nil, replaces the sandbox wrapper (tests only).
var WrapForTest func(profile string, argv []string) []string

type Options struct {
	Argv   []string
	Stdin  io.Reader
	Stdout io.Writer
	Stderr io.Writer
	// Dir is the working directory (default: current).
	Dir string
	// ExtraEnv is appended last.
	ExtraEnv []string
	// Quiet suppresses hat's own notices.
	Quiet bool
}

// Run executes argv inside the profile and returns the exit code.
func Run(p *config.Profile, o Options) (int, error) {
	if len(o.Argv) == 0 {
		return 0, errors.New("no command given")
	}
	if WrapForTest == nil && runtime.GOOS != "darwin" {
		return 0, errors.New("lite mode requires macOS (sandbox-exec)")
	}
	if WrapForTest == nil {
		if _, err := os.Stat(SandboxExec); err != nil {
			return 0, fmt.Errorf("%s not found: %w", SandboxExec, err)
		}
	}
	stderr := o.Stderr
	if stderr == nil {
		stderr = os.Stderr
	}
	rawURL, err := secret.ProxyURL(p)
	if err != nil {
		return 0, err
	}
	dialer, err := upstream.New(rawURL)
	if err != nil {
		return 0, err
	}
	br := &bridge.Bridge{Dialer: dialer, User: config.App, Pass: bridge.RandomToken()}
	if os.Getenv("HAT_DEBUG") != "" {
		br.Logf = func(f string, a ...any) { fmt.Fprintf(stderr, "[%s] "+f+"\n", append([]any{config.App}, a...)...) }
	}
	if err := br.Start("127.0.0.1:0"); err != nil {
		return 0, fmt.Errorf("starting local bridge: %w", err)
	}
	defer br.Close()

	hatHome, err := config.Home()
	if err != nil {
		return 0, err
	}
	profileHome := ""
	if p.Lite.IsolateHome {
		dir, _ := config.Dir(p.Name)
		profileHome = filepath.Join(dir, "home")
		if err := os.MkdirAll(profileHome, 0o700); err != nil {
			return 0, err
		}
	}
	binDir, _ := config.BinDir()
	var ro []string
	shares, _ := p.ExpandedShares()
	for _, s := range shares {
		if s.ReadOnly {
			ro = append(ro, s.Path)
		}
	}
	sbpl, err := seatbelt.Generate(seatbelt.Options{
		ProxyPort:         br.Port(),
		HatHome:           realPath(hatHome),
		ProfileHome:       realPathOrEmpty(profileHome),
		ReadableInHatHome: []string{realPath(binDir), realPath(filepath.Join(hatHome, "shims.toml"))},
		ReadOnly:          realPaths(ro),
		AllowTrustd:       p.Lite.AllowTrustd,
		LogTag:            config.App + ":" + p.Name,
	})
	if err != nil {
		return 0, err
	}

	argv := o.Argv
	if lp, err := exec.LookPath(argv[0]); err == nil {
		argv = append([]string{lp}, argv[1:]...)
	} else {
		return 127, fmt.Errorf("%s: command not found", argv[0])
	}
	var full []string
	if WrapForTest != nil {
		full = WrapForTest(sbpl, argv)
	} else {
		full = append([]string{SandboxExec, "-p", sbpl}, argv...)
	}

	cmd := exec.Command(full[0], full[1:]...)
	cmd.Stdin, cmd.Stdout, cmd.Stderr = o.Stdin, o.Stdout, stderr
	if cmd.Stdin == nil {
		cmd.Stdin = os.Stdin
	}
	if cmd.Stdout == nil {
		cmd.Stdout = os.Stdout
	}
	cmd.Dir = o.Dir
	cmd.Env = append(Env(os.Environ(), p, br.Addr(), br.User, br.Pass, profileHome, binDir), o.ExtraEnv...)

	// Keep the bridge alive while the child runs: terminal signals (^C, ^\)
	// reach the child directly through the process group; forward the rest.
	sigs := make(chan os.Signal, 8)
	signal.Notify(sigs, syscall.SIGINT, syscall.SIGQUIT, syscall.SIGTERM, syscall.SIGHUP, syscall.SIGUSR1, syscall.SIGUSR2, syscall.SIGWINCH)
	defer signal.Stop(sigs)
	if err := cmd.Start(); err != nil {
		return 126, err
	}
	done := make(chan struct{})
	go func() {
		for {
			select {
			case s := <-sigs:
				if s == syscall.SIGINT || s == syscall.SIGQUIT || s == syscall.SIGWINCH {
					continue // delivered by the terminal to the whole group
				}
				cmd.Process.Signal(s)
			case <-done:
				return
			}
		}
	}()
	err = cmd.Wait()
	close(done)

	code := ExitCode(cmd.ProcessState, err)
	if n, lastErr := br.LastError(); n > 0 && !o.Quiet {
		fmt.Fprintf(stderr, "[%s] %d connection(s) could not go through the proxy and were blocked (no direct connection was attempted): %v\n",
			config.App, n, lastErr)
	}
	return code, nil
}

// ExitCode converts a finished process state to a shell-style exit code.
func ExitCode(ps *os.ProcessState, err error) int {
	if ps == nil {
		if err != nil {
			return 1
		}
		return 0
	}
	if ws, ok := ps.Sys().(syscall.WaitStatus); ok && ws.Signaled() {
		return 128 + int(ws.Signal())
	}
	return ps.ExitCode()
}

// proxyVars are removed from the inherited environment and then set to the
// bridge.
var proxyVars = []string{"HTTP_PROXY", "HTTPS_PROXY", "ALL_PROXY", "NO_PROXY", "FTP_PROXY",
	"RSYNC_PROXY", "SOCKS_PROXY", "SOCKS5_PROXY", "GRPC_PROXY"}

// Env builds the child environment.
func Env(base []string, p *config.Profile, bridgeAddr, user, pass, profileHome, binDir string) []string {
	drop := map[string]bool{"SSH_AUTH_SOCK": true, "LANGUAGE": true}
	for _, v := range proxyVars {
		drop[v] = true
	}
	var env []string
	for _, kv := range base {
		k, _, _ := strings.Cut(kv, "=")
		ku := strings.ToUpper(k)
		if drop[ku] || strings.HasPrefix(ku, "LC_") || k == "LANG" || k == "TZ" ||
			strings.HasPrefix(k, "HAT_") || k == "BROWSER" {
			continue
		}
		if profileHome != "" && (k == "HOME" || strings.HasPrefix(k, "XDG_")) {
			continue
		}
		env = append(env, kv)
	}
	ui := url.UserPassword(user, pass).String()
	httpURL := "http://" + ui + "@" + bridgeAddr
	socksURL := "socks5h://" + ui + "@" + bridgeAddr
	set := func(k, v string) { env = append(env, k+"="+v) }
	for _, k := range []string{"HTTP_PROXY", "HTTPS_PROXY", "http_proxy", "https_proxy"} {
		set(k, httpURL)
	}
	for _, k := range []string{"ALL_PROXY", "all_proxy"} {
		set(k, socksURL)
	}
	set("NO_PROXY", "")
	set("no_proxy", "")
	set("NODE_USE_ENV_PROXY", "1") // Node.js >= 22.21/24: honour HTTP(S)_PROXY in fetch/http
	set("LANG", p.Locale)
	set("LC_ALL", p.Locale)
	set("LANGUAGE", p.Lang()+":"+strings.SplitN(p.Lang(), "_", 2)[0])
	set("TZ", p.Timezone)
	set("BROWSER", filepath.Join(binDir, OpenURLHelper))
	set("JAVA_TOOL_OPTIONS", strings.TrimSpace(getenv(base, "JAVA_TOOL_OPTIONS")+
		" -Djava.net.preferIPv4Stack=true -Dhttp.proxyHost=127.0.0.1 -Dhttps.proxyHost=127.0.0.1"+
		" -Dhttp.proxyPort="+portOf(bridgeAddr)+" -Dhttps.proxyPort="+portOf(bridgeAddr)))
	set(config.EnvActive, p.Name)
	for k, v := range p.Env {
		set(k, v)
	}
	if profileHome != "" {
		set("HOME", profileHome)
		set("XDG_CONFIG_HOME", filepath.Join(profileHome, ".config"))
		set("XDG_CACHE_HOME", filepath.Join(profileHome, ".cache"))
		set("XDG_DATA_HOME", filepath.Join(profileHome, ".local", "share"))
		set("XDG_STATE_HOME", filepath.Join(profileHome, ".local", "state"))
	}
	return env
}

// OpenURLHelper is the name of the BROWSER helper symlink in the bin dir.
const OpenURLHelper = ".hat-open-url"

func getenv(env []string, key string) string {
	for _, kv := range env {
		if k, v, ok := strings.Cut(kv, "="); ok && k == key {
			return v
		}
	}
	return ""
}

func portOf(addr string) string {
	i := strings.LastIndex(addr, ":")
	if i < 0 {
		return ""
	}
	if _, err := strconv.Atoi(addr[i+1:]); err != nil {
		return ""
	}
	return addr[i+1:]
}

// realPath resolves symlinks (sandbox rules match real paths, e.g. /private/var).
func realPath(p string) string {
	if r, err := filepath.EvalSymlinks(p); err == nil {
		return r
	}
	// Resolve the deepest existing parent.
	dir, base := filepath.Split(filepath.Clean(p))
	if dir == "" || dir == p {
		return p
	}
	return filepath.Join(realPath(filepath.Clean(dir)), base)
}

func realPathOrEmpty(p string) string {
	if p == "" {
		return ""
	}
	return realPath(p)
}

func realPaths(ps []string) []string {
	out := make([]string, len(ps))
	for i, p := range ps {
		out[i] = realPath(p)
	}
	return out
}
