package vm

import (
	"fmt"
	"strings"

	"hat/internal/session"
)

// GuestUID matches the default macOS user id so files in virtio-fs shares
// are owned by the guest user.
const GuestUID = 501

// Guest files written at first boot. Programs in the guest can read them,
// so their names do not mention hat.
const (
	markerDir         = "/var/lib/misc"
	ProvisionedMarker = markerDir + "/provisioned"
	FirstBootMarker   = markerDir + "/firstboot-boot-id"
	SysctlConf        = "/etc/sysctl.d/90-disable-ipv6.conf"
	SSHDConf          = "/etc/ssh/sshd_config.d/90-local.conf"
)

// DefaultInstanceID is the cloud-init instance-id of new VMs. Each profile
// has its own disk, so it need not be unique; this is the value the
// cloud-init NoCloud documentation uses, so it reveals nothing. VMs created
// by older versions keep theirs (see Prepare): changing it would make
// cloud-init provision the VM again.
const DefaultInstanceID = "iid-local01"

// SeedInput holds the per-profile identity written by cloud-init on first
// boot. Settings that may change later (hostname, timezone, locale, shares)
// are also re-applied over SSH on every boot.
type SeedInput struct {
	InstanceID    string
	Hostname      string
	Username      string
	UID           int
	MachineID     string
	AuthorizedKey string
	Timezone      string
	Locale        string
	Provision     []string
}

// MetaData returns the NoCloud meta-data document.
func MetaData(in SeedInput) string {
	return fmt.Sprintf("instance-id: %s\nlocal-hostname: %s\n", in.InstanceID, in.Hostname)
}

// yq quotes a string as a YAML double-quoted scalar.
func yq(s string) string {
	r := strings.NewReplacer(`\`, `\\`, `"`, `\"`, "\n", `\n`, "\t", `\t`)
	return `"` + r.Replace(s) + `"`
}

// UserData returns the #cloud-config document.
func UserData(in SeedInput) string {
	var b strings.Builder
	w := func(format string, a ...any) { fmt.Fprintf(&b, format+"\n", a...) }
	w("#cloud-config")
	w("hostname: %s", yq(in.Hostname))
	w("preserve_hostname: false")
	w("manage_etc_hosts: true")
	w("timezone: %s", yq(in.Timezone))
	w("locale: %s", yq(in.Locale))
	w("ssh_pwauth: false")
	w("disable_root: true")
	w("package_update: false")
	w("package_upgrade: false")
	w("users:")
	w("  - name: %s", yq(in.Username))
	w("    uid: %d", in.UID)
	w("    shell: /bin/bash")
	w(`    sudo: "ALL=(ALL) NOPASSWD:ALL"`)
	w("    lock_passwd: true")
	w("    ssh_authorized_keys:")
	w("      - %s", yq(strings.TrimSpace(in.AuthorizedKey)))
	w("write_files:")
	w("  - path: %s", SysctlConf)
	w("    content: |")
	w("      net.ipv6.conf.all.disable_ipv6 = 1")
	w("      net.ipv6.conf.default.disable_ipv6 = 1")
	w("  - path: %s", SSHDConf)
	w("    content: |")
	w("      PasswordAuthentication no")
	w("      PermitRootLogin no")
	w("      X11Forwarding no")
	w("      AllowAgentForwarding no")
	w("      AllowTcpForwarding no")
	w("      AcceptEnv LANG LC_* TZ")
	w("runcmd:")
	// Background jobs that would phone home or need NTP (UDP is dropped).
	w("  - [sh, -c, %s]", yq("for u in apt-daily.timer apt-daily-upgrade.timer unattended-upgrades.service "+
		"systemd-timesyncd.service chrony.service man-db.timer e2scrub_all.timer fstrim.timer "+
		"motd-news.timer popularity-contest.timer; do systemctl disable --now \"$u\" 2>/dev/null; done; true"))
	w("  - [sh, -c, %s]", yq(fmt.Sprintf("printf '%%s\\n' %s > /etc/machine-id && rm -f /var/lib/dbus/machine-id && "+
		"ln -sf /etc/machine-id /var/lib/dbus/machine-id", in.MachineID)))
	w("  - [sh, -c, %s]", yq(localeScript(in.Locale)))
	for _, c := range in.Provision {
		w("  - [sh, -c, %s]", yq(c))
	}
	// Remember this (first) boot so the daemon only reports ready after
	// the reboot below has happened.
	w("  - [sh, -c, %s]", yq("mkdir -p "+markerDir+" && cat /proc/sys/kernel/random/boot_id > "+FirstBootMarker))
	w("  - [touch, %s]", ProvisionedMarker)
	w("power_state:")
	w("  mode: reboot")
	w(`  message: "first boot complete, rebooting"`)
	w("  condition: true")
	return b.String()
}

func localeScript(locale string) string {
	return fmt.Sprintf("L=%s; if ! locale -a 2>/dev/null | grep -qi \"^$(echo ${L%%.*}).utf-\\?8$\"; then "+
		"(command -v locale-gen >/dev/null || (apt-get update && DEBIAN_FRONTEND=noninteractive apt-get install -y locales)) && "+
		"sed -i \"s/^# *\\($L\\)/\\1/\" /etc/locale.gen && grep -q \"^$L\" /etc/locale.gen || echo \"$L UTF-8\" >> /etc/locale.gen; "+
		"locale-gen; fi; update-locale LANG=$L; true", session.Quote(locale))
}
