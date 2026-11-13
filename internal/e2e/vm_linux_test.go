//go:build linux

package e2e

import (
	"bytes"
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"syscall"
	"testing"
	"time"

	"hat/internal/testproxy"
)

type harness struct {
	t      *testing.T
	hat    string
	env    []string
	share  string
	home   string
	proxy  *testproxy.Server
	fakeVF string
}

func build(t *testing.T, dir, pkg, name string) string {
	t.Helper()
	out := filepath.Join(dir, name)
	cmd := exec.Command("go", "build", "-o", out, pkg)
	cmd.Dir = "../.."
	if b, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("build %s: %v\n%s", pkg, err, b)
	}
	return out
}

func (h *harness) run(stdin string, args ...string) (string, string, int) {
	h.t.Helper()
	cmd := exec.Command(h.hat, args...)
	cmd.Env = h.env
	cmd.Dir = h.share
	cmd.Stdin = strings.NewReader(stdin)
	var out, errb bytes.Buffer
	cmd.Stdout, cmd.Stderr = &out, &errb
	err := cmd.Run()
	code := 0
	if err != nil {
		code = cmd.ProcessState.ExitCode()
	}
	return out.String(), errb.String(), code
}

func setup(t *testing.T) *harness {
	if testing.Short() {
		t.Skip("e2e")
	}
	tmp := t.TempDir()
	h := &harness{t: t}
	h.hat = build(t, tmp, "./cmd/hat", "hat")
	h.fakeVF = build(t, tmp, "./internal/e2e/fakevfkit", "fakevfkit")
	h.home = filepath.Join(tmp, "hathome")
	h.share = filepath.Join(tmp, "project")
	os.MkdirAll(h.share, 0o755)
	os.MkdirAll(filepath.Join(h.home, "images"), 0o700)
	os.WriteFile(filepath.Join(h.home, "images", "debian-13.raw"), make([]byte, 1<<20), 0o600)
	h.proxy = testproxy.StartSOCKS5("", "")
	t.Cleanup(h.proxy.Close)
	h.env = append(os.Environ(), "HAT_HOME="+h.home, "HAT_VFKIT="+h.fakeVF, "HOME="+tmp,
		"HAT_SKIP_PREFLIGHT=1") // preflight needs macOS + internet; covered by internal/preflight tests
	if _, e, code := h.run("", "create", "e2e", "--proxy", "socks5://"+h.proxy.Addr(), "--allow-local-upstream",
		"--tz", "Asia/Tokyo", "--locale", "ja_JP.UTF-8", "--share", h.share); code != 0 {
		t.Fatalf("create: %s", e)
	}
	var st struct {
		MachineID string `json:"machine_id"`
	}
	b, _ := os.ReadFile(filepath.Join(h.home, "profiles", "e2e", "state.json"))
	json.Unmarshal(b, &st)
	h.env = append(h.env, "FAKE_MACHINE_ID="+st.MachineID)
	t.Cleanup(func() {
		h.run("", "stop", "e2e")
		exec.Command("pkill", "-f", h.fakeVF).Run()
	})
	return h
}

func TestVMLifecycle(t *testing.T) {
	h := setup(t)

	out, errOut, code := h.run("piped\n", "run", "e2e", "--", "sh", "-c", `echo "$TZ|$LANG|${HAT_ACTIVE-unset}|$GUEST_PWD|$(pwd)"; cat; exit 3`)
	if code != 3 {
		t.Fatalf("exit %d, stderr:\n%s\ndaemon log:\n%s", code, errOut, h.daemonLog())
	}
	// The share is mounted below the guest home, not at its host path
	// (which would carry the host account name), and nothing in the guest
	// environment names hat.
	want := "Asia/Tokyo|ja_JP.UTF-8|unset|/home/dev/project|" + h.share + "\npiped\n"
	if out != want {
		t.Fatalf("stdout %q want %q", out, want)
	}
	if !strings.Contains(errOut, "First start") {
		t.Errorf("expected first-start notice, got %q", errOut)
	}

	// status
	out, _, code = h.run("", "status", "e2e", "--json")
	if code != 0 || !strings.Contains(out, `"state": "ready"`) {
		t.Fatalf("status: %s", out)
	}

	// concurrent sessions
	var wg sync.WaitGroup
	errs := make(chan string, 5)
	for i := 0; i < 5; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			if o, e, c := h.run("", "run", "e2e", "--", "echo", "ok"); c != 0 || o != "ok\n" {
				errs <- e
			}
		}()
	}
	wg.Wait()
	close(errs)
	for e := range errs {
		t.Fatalf("concurrent run failed: %s", e)
	}

	// the proxy never saw SSH or anything else: host->guest traffic is internal
	if tg := h.proxy.Targets(); len(tg) != 0 {
		t.Fatalf("unexpected upstream traffic: %v", tg)
	}

	// stop, then run again (warm restart, not first boot)
	if _, e, c := h.run("", "stop", "e2e"); c != 0 {
		t.Fatalf("stop: %s", e)
	}
	if o, _, _ := h.run("", "status", "e2e"); strings.TrimSpace(o) != "stopped" {
		t.Fatalf("after stop: %q", o)
	}
	out, errOut, code = h.run("", "run", "e2e", "--", "echo", "again")
	if code != 0 || out != "again\n" || strings.Contains(errOut, "First start") {
		t.Fatalf("restart: code %d out %q err %q", code, out, errOut)
	}

	// crash recovery: kill -9 the daemon; the next run must recover
	var st struct {
		OK   bool
		Data struct{ PID int }
	}
	o, _, _ := h.run("", "status", "e2e", "--json")
	json.Unmarshal([]byte(o), &st)
	if !st.OK || st.Data.PID == 0 {
		t.Fatal("no daemon pid")
	}
	syscall.Kill(st.Data.PID, syscall.SIGKILL)
	time.Sleep(300 * time.Millisecond)
	out, errOut, code = h.run("", "run", "e2e", "--", "echo", "recovered")
	if code != 0 || out != "recovered\n" {
		t.Fatalf("after crash: code %d out %q err %q\nlog:\n%s", code, out, errOut, h.daemonLog())
	}
}

func TestVMRefusesUnsharedCwd(t *testing.T) {
	h := setup(t)
	cmd := exec.Command(h.hat, "run", "e2e", "--", "true")
	cmd.Env = h.env
	cmd.Dir = os.TempDir()
	out, _ := cmd.CombinedOutput()
	if cmd.ProcessState.ExitCode() != 125 || !strings.Contains(string(out), "not shared") {
		t.Fatalf("got %d %s", cmd.ProcessState.ExitCode(), out)
	}
}

func (h *harness) daemonLog() string {
	b, _ := os.ReadFile(filepath.Join(h.home, "profiles", "e2e", "daemon.log"))
	return string(b)
}

// A share configured through a symlink alias (macOS: /tmp -> /private/tmp)
// must match a cwd given as the real path, and the command must run in the
// guest under the mount of the share's configured path.
func TestVMSharedThroughSymlinkAlias(t *testing.T) {
	h := setup(t)
	root := filepath.Dir(h.share)
	real := filepath.Join(root, "private-proj")
	os.MkdirAll(filepath.Join(real, "sub"), 0o755)
	alias := filepath.Join(root, "proj-alias")
	if err := os.Symlink(real, alias); err != nil {
		t.Skip(err)
	}
	if _, e, c := h.run("", "share", "add", "e2e", alias); c != 0 {
		t.Fatalf("share add: %s", e)
	}
	cmd := exec.Command(h.hat, "run", "e2e", "--", "sh", "-c", `echo "$GUEST_PWD"`) // the guest dir hat cd'ed to
	var env []string
	for _, kv := range h.env {
		if !strings.HasPrefix(kv, "PWD=") {
			env = append(env, kv)
		}
	}
	cmd.Env = env
	cmd.Dir = filepath.Join(real, "sub")
	out, err := cmd.Output()
	if err != nil {
		t.Fatalf("run from real path: %v %s", err, out)
	}
	if got := strings.TrimSpace(string(out)); got != "/home/dev/proj-alias/sub" {
		t.Fatalf("guest cwd %q, want %q", got, "/home/dev/proj-alias/sub")
	}
}
