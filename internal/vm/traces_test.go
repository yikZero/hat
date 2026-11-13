package vm

import (
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"hat/internal/config"
)

// Everything hat writes into the guest is readable by programs there, so
// none of it may name hat (or the profile).
func TestSeedHasNoHatTraces(t *testing.T) {
	in := SeedInput{InstanceID: DefaultInstanceID, Hostname: "debian", Username: "dev", UID: 501,
		MachineID: "0123456789abcdef0123456789abcdef", AuthorizedKey: "ssh-ed25519 AAAA test",
		Timezone: "Asia/Tokyo", Locale: "ja_JP.UTF-8"}
	for name, doc := range map[string]string{"user-data": UserData(in), "meta-data": MetaData(in)} {
		if strings.Contains(strings.ToLower(doc), "hat") {
			t.Errorf("%s mentions hat:\n%s", name, doc)
		}
	}
	for _, s := range []string{ProvisionedMarker, FirstBootMarker, SysctlConf, SSHDConf, ShareTag(0)} {
		if strings.Contains(s, "hat") {
			t.Errorf("guest name %q mentions hat", s)
		}
	}
}

func TestInstanceIDKeptForExistingDisks(t *testing.T) {
	dir := t.TempDir()
	md := filepath.Join(dir, "meta-data")
	const mid = "0123456789abcdef0123456789abcdef"
	if got := instanceID(md, true, "us", mid); got != DefaultInstanceID {
		t.Errorf("new disk: %q", got)
	}
	// A disk from an older version with no seed left: its original id.
	if got := instanceID(md, false, "us", mid); got != "hat-us-01234567" {
		t.Errorf("legacy disk without meta-data: %q", got)
	}
	os.WriteFile(md, []byte("instance-id: hat-us-01234567\nlocal-hostname: x\n"), 0o600)
	if got := instanceID(md, false, "us", mid); got != "hat-us-01234567" {
		t.Errorf("legacy disk: %q", got)
	}
	os.WriteFile(md, []byte(MetaData(SeedInput{InstanceID: DefaultInstanceID, Hostname: "x"})), 0o600)
	if got := instanceID(md, false, "us", mid); got != DefaultInstanceID {
		t.Errorf("current disk: %q", got)
	}
	// A recreated disk starts over even if an old seed is still there.
	os.WriteFile(md, []byte("instance-id: hat-us-01234567\n"), 0o600)
	if got := instanceID(md, true, "us", mid); got != DefaultInstanceID {
		t.Errorf("recreated disk: %q", got)
	}
}

// guestSh runs a guest script with /var/lib and /etc moved under root and
// sudo dropped.
func guestSh(t *testing.T, root, script string) (string, error) {
	t.Helper()
	script = strings.NewReplacer("/var/lib/", root+"/var/lib/", "/etc/", root+"/etc/", "sudo ", "",
		"/Users", root+"/Users", "/Volumes", root+"/Volumes", "/private", root+"/private").Replace(script)
	out, err := exec.Command("sh", "-c", script).CombinedOutput()
	return string(out), err
}

func TestReadyProbeAndLegacyMigration(t *testing.T) {
	bootID, err := os.ReadFile("/proc/sys/kernel/random/boot_id")
	if err != nil {
		t.Skip(err)
	}
	root := t.TempDir()
	write := func(p, s string) {
		p = filepath.Join(root, p)
		os.MkdirAll(filepath.Dir(p), 0o755)
		if err := os.WriteFile(p, []byte(s), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	write("etc/machine-id", "mid\n")
	if out, err := guestSh(t, root, ReadyProbe); err == nil {
		t.Fatalf("ready before provisioning: %q", out)
	}
	// A VM provisioned by an older version, rebooted since.
	write("var/lib/hat-provisioned", "")
	write("var/lib/hat-firstboot-id", "an-earlier-boot\n")
	write("etc/sysctl.d/90-hat.conf", "sysctl\n")
	write("etc/ssh/sshd_config.d/90-hat.conf", "sshd\n")
	// Old mount points: empty ones go, anything with content stays.
	for _, d := range []string{"Users/yikzero/code/proj", "Volumes/Data", "private/tmp/x"} {
		os.MkdirAll(filepath.Join(root, d), 0o755)
	}
	write("Users/someone/notes.txt", "keep\n")
	if out, err := guestSh(t, root, ReadyProbe); err != nil || out != "mid\n" {
		t.Fatalf("legacy VM not ready: %q %v", out, err)
	}
	for i := 0; i < 2; i++ { // idempotent
		if out, err := guestSh(t, root, "set -e\n"+migrateGuestScript); err != nil {
			t.Fatalf("migration run %d: %v %s", i, err, out)
		}
	}
	for _, p := range []string{ProvisionedMarker, FirstBootMarker, SysctlConf, SSHDConf} {
		if _, err := os.Stat(filepath.Join(root, p)); err != nil {
			t.Errorf("not migrated: %v", err)
		}
	}
	for _, p := range []string{"/Users/yikzero", "/Volumes", "/private"} {
		if _, err := os.Stat(filepath.Join(root, p)); err == nil {
			t.Errorf("empty legacy mount point left: %s", p)
		}
	}
	if _, err := os.Stat(filepath.Join(root, "Users/someone/notes.txt")); err != nil {
		t.Errorf("non-empty directory removed: %v", err)
	}
	for _, p := range []string{legacyProvisionedMarker, legacyFirstBootMarker, legacySysctlConf, legacySSHDConf} {
		if _, err := os.Stat(filepath.Join(root, p)); err == nil {
			t.Errorf("left behind: %s", p)
		}
	}
	if out, err := guestSh(t, root, ReadyProbe); err != nil || out != "mid\n" {
		t.Fatalf("migrated VM not ready: %q %v", out, err)
	}
	// Still in the first boot: not ready.
	write(FirstBootMarker[1:], string(bootID))
	if out, err := guestSh(t, root, ReadyProbe); err == nil {
		t.Fatalf("ready during the first boot: %q", out)
	}
}

func TestMountScript(t *testing.T) {
	t.Setenv("HOME", "/Users/alice")
	p := config.New("x")
	p.Share = []config.Share{{Path: "~/code/proj", ReadOnly: true}, {Path: "/Volumes/Data"}, {Path: "~/code"}, {Path: "~/my files"}}
	shares, err := p.ExpandedShares()
	if err != nil {
		t.Fatal(err)
	}
	got := MountScript(p, shares)
	// ExpandedShares order (and so the tags): /Users/alice/code,
	// /Users/alice/code/proj, /Users/alice/my files, /Volumes/Data.
	want := "mkdir -p /home/dev/code; mountpoint -q /home/dev/code || sudo mount -t virtiofs -o rw share0 /home/dev/code\n" +
		"mkdir -p /home/dev/code/proj; mountpoint -q /home/dev/code/proj || sudo mount -t virtiofs -o ro share1 /home/dev/code/proj\n" +
		"mkdir -p '/home/dev/my files'; mountpoint -q '/home/dev/my files' || sudo mount -t virtiofs -o rw share2 '/home/dev/my files'\n" +
		"sudo mkdir -p /mnt/host/Volumes/Data; mountpoint -q /mnt/host/Volumes/Data || sudo mount -t virtiofs -o rw share3 /mnt/host/Volumes/Data\n"
	if got != want {
		t.Fatalf("got:\n%s\nwant:\n%s", got, want)
	}
	if strings.Contains(got, "/Users/") {
		t.Fatal("host home path reached the guest")
	}
}
