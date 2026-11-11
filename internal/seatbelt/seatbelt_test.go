package seatbelt

import (
	"os"
	"strings"
	"testing"
)

func TestGenerate(t *testing.T) {
	sb, err := Generate(Options{ProxyPort: 51234, HatHome: "/Users/a/.hat",
		ProfileHome: "/Users/a/.hat/profiles/us/home",
		ReadableInHatHome: []string{"/Users/a/.hat/bin", "/Users/a/.hat/shims.toml"},
		ReadOnly: []string{"/Users/a/ref"}})
	if err != nil {
		t.Fatal(err)
	}
	if os.Getenv("UPDATE_GOLDEN") != "" {
		os.WriteFile("testdata/golden.sb", []byte(sb), 0o644)
	}
	golden, err := os.ReadFile("testdata/golden.sb")
	if err != nil {
		t.Fatal(err)
	}
	if sb != string(golden) {
		t.Fatal("profile differs from testdata/golden.sb (rerun with UPDATE_GOLDEN=1 after review)")
	}
	mustHave := []string{
		"(deny default",
		`(allow network-outbound (remote tcp "localhost:51234"))`,
		`(deny file-read* file-write* (subpath "/Users/a/.hat"))`,
		`(allow file-read* file-write* (subpath "/Users/a/.hat/profiles/us/home"))`,
		`(deny file-write* (subpath "/Users/a/ref"))`,
		`(global-name "com.apple.dnssd.service")`,
		`(deny mach-lookup (global-name "com.apple.trustd.agent")`,
		"(deny lsopen)",
	}
	for _, m := range mustHave {
		if !strings.Contains(sb, m) {
			t.Errorf("missing %s", m)
		}
	}
	// No rule may allow other network egress.
	for _, line := range strings.Split(sb, "\n") {
		l := strings.TrimSpace(line)
		if strings.HasPrefix(l, "(allow network-outbound") && l != `(allow network-outbound (remote tcp "localhost:51234"))` {
			t.Errorf("unexpected egress rule: %s", l)
		}
		if strings.HasPrefix(l, "(allow network*") || strings.Contains(l, "AF_UNIX") && strings.HasPrefix(l, "(allow") ||
			strings.Contains(l, "AF_INET") && strings.HasPrefix(l, "(allow") {
			t.Errorf("forbidden rule: %s", l)
		}
	}
	if strings.Count(sb, "(") != strings.Count(sb, ")") {
		t.Error("unbalanced parentheses")
	}
}

func TestTrustdOptIn(t *testing.T) {
	sb, _ := Generate(Options{ProxyPort: 1, HatHome: "/h", AllowTrustd: true})
	if !strings.Contains(sb, `(allow mach-lookup (global-name "com.apple.trustd.agent"))`) ||
		strings.Contains(sb, `(deny mach-lookup (global-name "com.apple.trustd.agent")`) {
		t.Fatal("trustd opt-in not applied")
	}
}

func TestRejectsBadInput(t *testing.T) {
	if _, err := Generate(Options{ProxyPort: 0, HatHome: "/h"}); err == nil {
		t.Fatal("port 0 accepted")
	}
	if _, err := Generate(Options{ProxyPort: 1, HatHome: "rel"}); err == nil {
		t.Fatal("relative home accepted")
	}
}
