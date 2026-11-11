package config

import (
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
)

func TestRoundTripAndPerms(t *testing.T) {
	t.Setenv(EnvHome, t.TempDir())
	p := New("us-east")
	p.Proxy.URL = "socks5://u@203.0.113.7:1080"
	p.Timezone = "America/New_York"
	p.Share = []Share{{Path: "~/code"}}
	if err := p.Save(); err != nil {
		t.Fatal(err)
	}
	q, err := Load("us-east")
	if err != nil {
		t.Fatal(err)
	}
	if q.Proxy != p.Proxy || q.VM.Hostname != p.VM.Hostname || len(q.Share) != 1 {
		t.Fatalf("mismatch: %+v vs %+v", q, p)
	}
	dir, _ := Dir("us-east")
	os.Chmod(filepath.Join(dir, "profile.toml"), 0o644)
	if _, err := Load("us-east"); err == nil || !strings.Contains(err.Error(), "chmod 600") {
		t.Fatalf("expected permission error, got %v", err)
	}
	os.Chmod(filepath.Join(dir, "profile.toml"), 0o600)

	s1, err := LoadState("us-east")
	if err != nil {
		t.Fatal(err)
	}
	s2, _ := LoadState("us-east")
	if s1.MachineID != s2.MachineID || s1.MAC != s2.MAC {
		t.Fatal("state not stable")
	}
	names, _ := List()
	if len(names) != 1 || names[0] != "us-east" {
		t.Fatalf("list %v", names)
	}
}

func TestValidate(t *testing.T) {
	p := New("Bad Name")
	p.Locale, p.Timezone = "english", "Mars/Base"
	err := p.Validate()
	for _, want := range []string{"invalid profile name", "proxy.url is required", "invalid locale", "invalid timezone"} {
		if err == nil || !strings.Contains(err.Error(), want) {
			t.Errorf("missing %q in %v", want, err)
		}
	}
	p = New("ok")
	p.Proxy.URL = "socks5://u:secret@203.0.113.1:1080"
	if err := p.Validate(); err == nil || !strings.Contains(err.Error(), "must not contain a password") {
		t.Errorf("password in URL accepted: %v", err)
	}
	p.Proxy.URL = "http://127.0.0.1:7890"
	if err := p.Validate(); err == nil || !strings.Contains(err.Error(), "allow_local_upstream") {
		t.Errorf("local upstream accepted: %v", err)
	}
	p.Proxy.AllowLocalUpstream = true
	if err := p.Validate(); err != nil {
		t.Errorf("unexpected: %v", err)
	}
}

func TestGuestPath(t *testing.T) {
	p := New("x")
	p.Share = []Share{{Path: "/Users/a/code"}}
	for path, want := range map[string]string{"/Users/a/code": "/Users/a/code", "/Users/a/code/p/q": "/Users/a/code/p/q",
		"/Users/a/codex": "", "/Users/a": ""} {
		if got, _, ok := p.GuestPath(path); got != want || ok != (want != "") {
			t.Errorf("%s: got %q %v", path, got, ok)
		}
	}
}

// macOS: /tmp -> /private/tmp. The same directory must match whichever
// spelling the share and the cwd use, and map to the share's spelling.
func TestGuestPathThroughSymlinkAlias(t *testing.T) {
	root := t.TempDir()
	real := filepath.Join(root, "private", "tmp")
	os.MkdirAll(filepath.Join(real, "proj", "sub"), 0o755)
	alias := filepath.Join(root, "tmp")
	if err := os.Symlink(real, alias); err != nil {
		t.Skip(err)
	}
	p := New("x")
	p.Share = []Share{{Path: filepath.Join(alias, "proj")}}
	got, _, ok := p.GuestPath(filepath.Join(real, "proj", "sub"))
	if !ok || got != filepath.Join(alias, "proj", "sub") {
		t.Fatalf("real cwd under aliased share: %q %v", got, ok)
	}
	p.Share = []Share{{Path: filepath.Join(real, "proj")}}
	got, _, ok = p.GuestPath(filepath.Join(alias, "proj"))
	if !ok || got != filepath.Join(real, "proj") {
		t.Fatalf("aliased cwd under real share: %q %v", got, ok)
	}
	// innermost share wins
	p.Share = []Share{{Path: filepath.Join(real, "proj")}, {Path: filepath.Join(alias, "proj", "sub"), ReadOnly: true}}
	if _, s, _ := p.GuestPath(filepath.Join(real, "proj", "sub")); !s.ReadOnly {
		t.Fatal("outer share chosen over inner one")
	}
}

func TestRandomMAC(t *testing.T) {
	for i := 0; i < 100; i++ {
		m := RandomMAC()
		if !macRe.MatchString(m) {
			t.Fatal(m)
		}
		b0, _ := strconv.ParseUint(m[:2], 16, 8)
		if b0&1 != 0 || b0&2 == 0 {
			t.Fatalf("not local unicast: %s", m)
		}
	}
}

func TestRunDirShort(t *testing.T) {
	t.Setenv(EnvHome, "/Users/someone-with-a-long-name/.hat")
	d, _ := RunDir("a-very-long-profile-name-0123456")
	if len(d)+len("/vfkit-12345-abcdefgh.sock") > 100 {
		t.Fatalf("run dir too long: %s", d)
	}
}

// Reported from the macOS retest: a long symlink alias of an outer share
// must not outrank an inner share given by its real path.
func TestGuestPathInnerShareThroughLongOuterAlias(t *testing.T) {
	root := t.TempDir()
	real := filepath.Join(root, "r")
	inner := filepath.Join(real, "sub")
	if err := os.MkdirAll(inner, 0o700); err != nil {
		t.Fatal(err)
	}
	alias := filepath.Join(root, "a-much-longer-logical-alias-for-the-outer-share")
	if err := os.Symlink(real, alias); err != nil {
		t.Fatal(err)
	}
	p := New("probe")
	p.Share = []Share{{Path: alias}, {Path: inner, ReadOnly: true}}
	for _, cwd := range []string{filepath.Join(alias, "sub"), inner} {
		guest, chosen, ok := p.GuestPath(cwd)
		if !ok || !chosen.ReadOnly || guest != inner {
			t.Fatalf("cwd %s: inner share not selected: guest=%q share=%+v ok=%v", cwd, guest, chosen, ok)
		}
	}
	// The outer share still applies outside the inner one.
	if guest, chosen, ok := p.GuestPath(alias); !ok || chosen.ReadOnly || guest != alias {
		t.Fatalf("outer: guest=%q share=%+v ok=%v", guest, chosen, ok)
	}
}
