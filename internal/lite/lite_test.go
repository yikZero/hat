package lite

import (
	"bytes"
	"net"
	"os"
	"strings"
	"testing"

	"hat/internal/config"
	"hat/internal/testproxy"
)

func setupProfile(t *testing.T, upstreamAddr string) *config.Profile {
	t.Helper()
	t.Setenv(config.EnvHome, t.TempDir())
	p := config.New("t1")
	p.Mode = config.ModeLite
	p.Proxy.URL = "socks5://" + upstreamAddr
	p.Proxy.AllowLocalUpstream = true
	p.Timezone = "Asia/Tokyo"
	p.Locale = "ja_JP.UTF-8"
	p.Lite.IsolateHome = true
	if err := p.Save(); err != nil {
		t.Fatal(err)
	}
	// Tests run without a sandbox on Linux; the wrapper just records the
	// profile and runs the command.
	WrapForTest = func(profile string, argv []string) []string {
		os.WriteFile(os.Getenv(config.EnvHome)+"/last.sb", []byte(profile), 0o644)
		return argv
	}
	t.Cleanup(func() { WrapForTest = nil })
	return p
}

func TestRunEnvAndExitCode(t *testing.T) {
	up := testproxy.StartSOCKS5("", "")
	defer up.Close()
	p := setupProfile(t, up.Addr())
	t.Setenv("HTTPS_PROXY", "http://leak.example:3128")
	t.Setenv("LC_CTYPE", "C")
	var out bytes.Buffer
	code, err := Run(p, Options{Argv: []string{"sh", "-c", "env; exit 42"}, Stdout: &out, Stdin: strings.NewReader("")})
	if err != nil {
		t.Fatal(err)
	}
	if code != 42 {
		t.Fatalf("exit %d", code)
	}
	env := out.String()
	for _, want := range []string{"TZ=Asia/Tokyo", "LANG=ja_JP.UTF-8", "LC_ALL=ja_JP.UTF-8", "HAT_ACTIVE=t1",
		"ALL_PROXY=socks5h://hat:", "HTTPS_PROXY=http://hat:", "NODE_USE_ENV_PROXY=1", "/profiles/t1/home"} {
		if !strings.Contains(env, want) {
			t.Errorf("env missing %q", want)
		}
	}
	for _, bad := range []string{"leak.example", "LC_CTYPE=C"} {
		if strings.Contains(env, bad) {
			t.Errorf("env still contains %q", bad)
		}
	}
	sb, _ := os.ReadFile(os.Getenv(config.EnvHome) + "/last.sb")
	if !strings.Contains(string(sb), "(deny default") {
		t.Error("sandbox profile not passed")
	}
}

func TestSignalExitCode(t *testing.T) {
	up := testproxy.StartSOCKS5("", "")
	defer up.Close()
	p := setupProfile(t, up.Addr())
	code, err := Run(p, Options{Argv: []string{"sh", "-c", "kill -TERM $$"}, Stdout: &bytes.Buffer{}, Stdin: strings.NewReader("")})
	if err != nil || code != 143 {
		t.Fatalf("code %d err %v", code, err)
	}
}

func TestCurlThroughBridgeAndKillSwitch(t *testing.T) {
	if _, err := os.Stat("/usr/bin/curl"); err != nil {
		t.Skip("curl not available")
	}
	echo := testproxy.StartEcho()
	defer echo.Close()
	_, port, _ := net.SplitHostPort(echo.Addr().String())
	up := testproxy.StartSOCKS5("", "")
	up.Resolve = func(string) string { return "127.0.0.1" }
	p := setupProfile(t, up.Addr())
	var out, errb bytes.Buffer
	// curl honours ALL_PROXY (socks5h): the hostname must reach the upstream unresolved.
	code, err := Run(p, Options{Argv: []string{"curl", "-sS", "--max-time", "5", "telnet://site.test:" + port},
		Stdin: strings.NewReader("hi\n"), Stdout: &out, Stderr: &errb})
	if err != nil || !strings.Contains(out.String(), "hello:hi") {
		t.Fatalf("code %d err %v out %q stderr %q", code, err, out.String(), errb.String())
	}
	if tg := up.Targets(); len(tg) != 1 || tg[0] != "site.test:"+port {
		t.Fatalf("upstream saw %v", tg)
	}
	// Kill switch: upstream down -> curl fails, hat reports the block.
	up.Close()
	out.Reset()
	errb.Reset()
	code, _ = Run(p, Options{Argv: []string{"curl", "-fsS", "--max-time", "5", "http://site.test:" + port + "/"},
		Stdin: strings.NewReader(""), Stdout: &out, Stderr: &errb})
	if code == 0 {
		t.Fatalf("request succeeded with upstream down: %q", out.String())
	}
	if !strings.Contains(errb.String(), "no direct connection was attempted") {
		t.Fatalf("missing kill-switch notice: %q", errb.String())
	}
}
