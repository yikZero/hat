package shim

import (
	"os"
	"path/filepath"
	"testing"

	"hat/internal/config"
)

func TestAddResolveRemove(t *testing.T) {
	t.Setenv(config.EnvHome, t.TempDir())
	if err := Add("teil", Entry{Command: "teil", Profile: "us-east", Real: "/opt/homebrew/bin/teil"}); err != nil {
		t.Fatal(err)
	}
	if err := Add("teil@jp", Entry{Command: "teil"}); err != nil {
		t.Fatal(err)
	}
	f, _ := Load()
	if len(f.Shims) != 2 || !f.Shims["teil@jp"].Pinned || f.Shims["teil@jp"].Profile != "jp" {
		t.Fatalf("%+v", f.Shims)
	}
	bin, _ := config.BinDir()
	if _, err := os.Readlink(filepath.Join(bin, "teil@jp")); err != nil {
		t.Fatal("symlink missing")
	}
	env := map[string]string{}
	get := func(k string) string { return env[k] }

	p, nested, err := Resolve(f.Shims["teil"], get)
	if p != "us-east" || nested || err != nil {
		t.Fatal(p, nested, err)
	}
	env[config.EnvProfile] = "eu"
	if p, _, _ := Resolve(f.Shims["teil"], get); p != "eu" {
		t.Fatal("HAT_PROFILE ignored")
	}
	if p, _, _ := Resolve(f.Shims["teil@jp"], get); p != "jp" {
		t.Fatal("pinned shim overridden")
	}
	env[config.EnvActive] = "jp"
	if _, _, err := Resolve(f.Shims["teil"], get); err == nil {
		t.Fatal("cross-profile nesting allowed")
	}
	if p, nested, err := Resolve(f.Shims["teil@jp"], get); p != "jp" || !nested || err != nil {
		t.Fatal(p, nested, err)
	}
	if err := Remove("teil"); err != nil {
		t.Fatal(err)
	}
	for _, bad := range []string{"hat", "../x", ".hidden", "a b"} {
		if err := Add(bad, Entry{Command: "x", Profile: "p"}); err == nil {
			t.Errorf("accepted %q", bad)
		}
	}
}

func TestLookPathExcluding(t *testing.T) {
	shimDir := t.TempDir()
	realDir := t.TempDir()
	for _, d := range []string{shimDir, realDir} {
		os.WriteFile(filepath.Join(d, "tool"), []byte("#!/bin/sh\n"), 0o755)
	}
	t.Setenv("PATH", shimDir+string(os.PathListSeparator)+realDir)
	p, err := LookPathExcluding("tool", shimDir)
	if err != nil || p != filepath.Join(realDir, "tool") {
		t.Fatal(p, err)
	}
}
