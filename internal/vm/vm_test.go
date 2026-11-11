package vm

import (
	"strings"
	"testing"

	"gopkg.in/yaml.v3"
)

func TestVfkitArgs(t *testing.T) {
	args, err := VfkitArgs(VfkitOptions{CPUs: 2, MemoryMB: 2048, EFIVars: "/p/efi", Disk: "/p/disk.raw",
		NetSocket: "/r/net.sock", MAC: "52:54:00:aa:bb:cc", ConsoleLog: "/p/console.log", PidFile: "/r/vfkit.pid",
		Shares: []VfkitShare{{Tag: "s0", Path: "/Users/a/code"}}, UserData: "/p/seed/user-data", MetaData: "/p/seed/meta-data"})
	if err != nil {
		t.Fatal(err)
	}
	j := strings.Join(args, " ")
	for _, want := range []string{"virtio-net,unixSocketPath=/r/net.sock,mac=52:54:00:aa:bb:cc",
		"--cloud-init /p/seed/user-data,/p/seed/meta-data", "virtio-fs,sharedDir=/Users/a/code,mountTag=s0",
		"efi,variable-store=/p/efi,create"} {
		if !strings.Contains(j, want) {
			t.Errorf("missing %q in %s", want, j)
		}
	}
	if err := assertSingleProxiedNIC(append(args, "--device", "virtio-net,nat")); err == nil {
		t.Fatal("second NIC accepted")
	}
	if err := assertSingleProxiedNIC([]string{"--device", "virtio-net,nat,mac=x"}); err == nil {
		t.Fatal("NAT NIC accepted")
	}
	if _, err := VfkitArgs(VfkitOptions{Disk: "/a,b", EFIVars: "e", NetSocket: "n", MAC: "m"}); err == nil {
		t.Fatal("comma in path accepted")
	}
}

func TestUserDataIsValidYAML(t *testing.T) {
	ud := UserData(SeedInput{InstanceID: "i", Hostname: "dev-box", Username: "dev", UID: 501,
		MachineID: "0123456789abcdef0123456789abcdef", AuthorizedKey: "ssh-ed25519 AAAA test\n",
		Timezone: "Asia/Tokyo", Locale: "ja_JP.UTF-8", Provision: []string{`echo "hi" > /tmp/x`}})
	if !strings.HasPrefix(ud, "#cloud-config\n") {
		t.Fatal("missing header")
	}
	var doc map[string]any
	if err := yaml.Unmarshal([]byte(ud), &doc); err != nil {
		t.Fatalf("invalid yaml: %v\n%s", err, ud)
	}
	users := doc["users"].([]any)[0].(map[string]any)
	if users["uid"] != 501 || users["name"] != "dev" {
		t.Fatalf("users: %v", users)
	}
	if doc["timezone"] != "Asia/Tokyo" || doc["hostname"] != "dev-box" {
		t.Fatalf("doc: %v", doc)
	}
	rc := doc["runcmd"].([]any)
	found := false
	for _, c := range rc {
		if s, ok := c.([]any); ok && len(s) == 3 && strings.Contains(s[2].(string), "0123456789abcdef0123456789abcdef") {
			found = true
		}
	}
	if !found {
		t.Fatal("machine-id not written")
	}
}

func TestEnsureKeyStable(t *testing.T) {
	d := t.TempDir()
	_, a, err := EnsureKey(d)
	if err != nil {
		t.Fatal(err)
	}
	_, b, _ := EnsureKey(d)
	if a != b || !strings.HasPrefix(a, "ssh-ed25519 ") {
		t.Fatalf("%q %q", a, b)
	}
}
