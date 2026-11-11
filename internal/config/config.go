// Package config manages profiles stored under the application home
// directory (default ~/.hat, overridable with HAT_HOME).
//
// Layout:
//
//	~/.hat/profiles/<name>/profile.toml   user-editable settings (0600)
//	~/.hat/profiles/<name>/state.json     generated identity, never edited
//	~/.hat/profiles/<name>/secret         proxy password if password="file"
//	~/.hat/shims.toml, ~/.hat/bin/        shims
//	~/.hat/run/<hash>/                    sockets (short paths)
package config

import (
	"bytes"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"net/url"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"time"

	"github.com/BurntSushi/toml"

	"hat/internal/clierr"
	"hat/internal/upstream"
)

// App is the command name; used for directories, env vars and messages.
const App = "hat"

// Environment variables.
const (
	EnvHome    = "HAT_HOME"    // overrides ~/.hat
	EnvProfile = "HAT_PROFILE" // selects the profile for shims
	EnvActive  = "HAT_ACTIVE"  // set inside a profile (nesting guard)
)

const SchemaVersion = 1

const (
	ModeLite = "lite"
	ModeVM   = "vm"
)

// Password storage for the upstream proxy.
const (
	PasswordNone     = "none"
	PasswordKeychain = "keychain"
	PasswordFile     = "file"
)

type Profile struct {
	Name string `toml:"-"`

	Schema   int    `toml:"schema"`
	Mode     string `toml:"mode"`
	Locale   string `toml:"locale"`
	Timezone string `toml:"timezone"`

	Proxy  ProxyConfig       `toml:"proxy"`
	Env    map[string]string `toml:"env,omitempty"`
	Share  []Share           `toml:"share,omitempty"`
	Lite   LiteConfig        `toml:"lite"`
	VM     VMConfig          `toml:"vm"`
	Checks ChecksConfig      `toml:"checks"`
}

// Check levels for ChecksConfig.OnStart.
const (
	CheckOff   = "off"
	CheckQuick = "quick" // proxy reachable + credentials accepted
	CheckFull  = "full"  // quick + exit IP lookup and expectations
)

// ChecksConfig controls the preflight checklist run before every launch.
type ChecksConfig struct {
	// OnStart is off | quick | full (default full).
	OnStart string `toml:"on_start" json:"on_start"`
	// CacheSeconds reuses a passing result for this long (default 600).
	CacheSeconds int `toml:"cache_seconds" json:"cache_seconds"`
	// ExpectCountry (ISO code, e.g. "US") refuses to run if the exit IP is
	// elsewhere — protects against a proxy that silently changes location.
	ExpectCountry string `toml:"expect_country,omitempty" json:"expect_country,omitempty"`
	// ExpectIP refuses to run unless the exit IP matches exactly.
	ExpectIP string `toml:"expect_ip,omitempty" json:"expect_ip,omitempty"`
}

// Level returns the effective on-start level.
func (c ChecksConfig) Level() string {
	if c.OnStart == "" {
		return CheckFull
	}
	return c.OnStart
}

// Cache returns the effective cache duration.
func (c ChecksConfig) Cache() time.Duration {
	if c.CacheSeconds <= 0 {
		return 10 * time.Minute
	}
	return time.Duration(c.CacheSeconds) * time.Second
}

type ProxyConfig struct {
	// URL without password, e.g. socks5://user@host:1080
	URL string `toml:"url"`
	// Password is where the password is stored: none | keychain | file.
	Password string `toml:"password"`
	// AllowLocalUpstream permits an upstream on loopback/private addresses
	// (e.g. a local Clash). The kill switch then depends on that proxy.
	AllowLocalUpstream bool `toml:"allow_local_upstream,omitempty"`
}

type Share struct {
	Path string `toml:"path"`
	// ReadOnly is enforced in lite mode by the sandbox; in vm mode it is a
	// guest-side read-only mount (root in the guest could remount it).
	ReadOnly bool `toml:"read_only,omitempty"`
}

type LiteConfig struct {
	// IsolateHome points HOME/XDG dirs at a per-profile directory.
	IsolateHome bool `toml:"isolate_home" json:"isolate_home"`
	// AllowTrustd lets the system certificate service run (needed by
	// Go/Swift CLIs that verify TLS via the OS). trustd may contact OCSP/CRL
	// servers directly from the real IP.
	AllowTrustd bool `toml:"allow_trustd" json:"allow_trustd"`
}

type VMConfig struct {
	CPUs            int    `toml:"cpus"`
	MemoryMB        int    `toml:"memory_mb"`
	DiskGB          int    `toml:"disk_gb"`
	Image           string `toml:"image"`
	Hostname        string `toml:"hostname"`
	Username        string `toml:"username"`
	IdleStopMinutes int    `toml:"idle_stop_minutes"`
	// Provision commands run once (as root) after the first boot.
	Provision []string `toml:"provision,omitempty"`
}

// State is generated once and never edited by the user.
type State struct {
	MachineID string    `json:"machine_id"`
	MAC       string    `json:"mac"`
	Created   time.Time `json:"created"`
}

var (
	nameRe     = regexp.MustCompile(`^[a-z0-9][a-z0-9_-]{0,31}$`)
	localeRe   = regexp.MustCompile(`^[a-z]{2,3}_[A-Z]{2}(\.UTF-8)?$`)
	hostnameRe = regexp.MustCompile(`^[a-zA-Z0-9]([a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?$`)
	userRe     = regexp.MustCompile(`^[a-z_][a-z0-9_-]{0,30}$`)
	macRe      = regexp.MustCompile(`^([0-9a-f]{2}:){5}[0-9a-f]{2}$`)
	midRe      = regexp.MustCompile(`^[0-9a-f]{32}$`)
)

// Home returns the application home directory.
func Home() (string, error) {
	if h := os.Getenv(EnvHome); h != "" {
		return filepath.Abs(h)
	}
	uh, err := os.UserHomeDir()
	if err != nil {
		return "", err
	}
	return filepath.Join(uh, "."+App), nil
}

func sub(parts ...string) (string, error) {
	h, err := Home()
	if err != nil {
		return "", err
	}
	return filepath.Join(append([]string{h}, parts...)...), nil
}

func ProfilesDir() (string, error) { return sub("profiles") }
func BinDir() (string, error)      { return sub("bin") }
func ImagesDir() (string, error)   { return sub("images") }

// Dir returns the directory of the named profile.
func Dir(name string) (string, error) { return sub("profiles", name) }

// RunDir returns a short per-profile directory for unix sockets (macOS
// limits socket paths to 104 bytes).
func RunDir(name string) (string, error) {
	h, err := Home()
	if err != nil {
		return "", err
	}
	sum := sha256.Sum256([]byte(h + "\x00" + name))
	return filepath.Join(h, "run", hex.EncodeToString(sum[:4])), nil
}

func ValidName(name string) error {
	if !nameRe.MatchString(name) {
		return fmt.Errorf("invalid profile name %q (lowercase letters, digits, - and _, max 32)", name)
	}
	return nil
}

// New returns a profile with defaults applied.
func New(name string) *Profile {
	p := &Profile{Name: name}
	p.Defaults()
	return p
}

// Defaults fills unset fields.
func (p *Profile) Defaults() {
	if p.Schema == 0 {
		p.Schema = SchemaVersion
	}
	if p.Mode == "" {
		p.Mode = ModeVM
	}
	if p.Locale == "" {
		p.Locale = "en_US.UTF-8"
	}
	if p.Timezone == "" {
		p.Timezone = "UTC"
	}
	if p.Proxy.Password == "" {
		p.Proxy.Password = PasswordNone
	}
	if p.VM.CPUs == 0 {
		p.VM.CPUs = 2
	}
	if p.VM.MemoryMB == 0 {
		p.VM.MemoryMB = 2048
	}
	if p.VM.DiskGB == 0 {
		p.VM.DiskGB = 16
	}
	if p.VM.Image == "" {
		p.VM.Image = "debian-13"
	}
	if p.VM.Username == "" {
		p.VM.Username = "dev"
	}
	if p.VM.Hostname == "" {
		p.VM.Hostname = "host-" + randHex(3)
	}
	if p.VM.IdleStopMinutes == 0 {
		p.VM.IdleStopMinutes = 30
	}
	if p.Checks.OnStart == "" {
		p.Checks.OnStart = CheckFull
	}
	if p.Checks.CacheSeconds == 0 {
		p.Checks.CacheSeconds = 600
	}
}

// Validate checks every field. It never contacts the network.
func (p *Profile) Validate() error {
	var errs []error
	add := func(format string, a ...any) { errs = append(errs, fmt.Errorf(format, a...)) }
	if err := ValidName(p.Name); err != nil {
		errs = append(errs, err)
	}
	if p.Schema != SchemaVersion {
		add("schema = %d is not supported (expected %d)", p.Schema, SchemaVersion)
	}
	if p.Mode != ModeLite && p.Mode != ModeVM {
		add("mode must be %q or %q", ModeLite, ModeVM)
	}
	if p.Proxy.URL == "" {
		add("proxy.url is required (every profile must use a proxy)")
	} else if u, err := url.Parse(p.Proxy.URL); err != nil {
		add("proxy.url: %v", err)
	} else {
		if _, has := u.User.Password(); u.User != nil && has {
			add("proxy.url must not contain a password; use `%s proxy-password %s`", App, p.Name)
		}
		if _, err := upstream.New(p.Proxy.URL); err != nil {
			errs = append(errs, err)
		} else if !p.Proxy.AllowLocalUpstream && upstream.IsLocalHost(u.Hostname()) {
			add("proxy %s is on a local/private address; set proxy.allow_local_upstream = true (or pass --allow-local-upstream) "+
				"if intended (the kill switch then depends on that proxy never connecting directly)", u.Host)
		}
	}
	switch p.Proxy.Password {
	case PasswordNone, PasswordKeychain, PasswordFile:
	default:
		add("proxy.password must be none, keychain or file")
	}
	if !localeRe.MatchString(p.Locale) {
		add("invalid locale %q (example: en_US.UTF-8)", p.Locale)
	}
	if _, err := time.LoadLocation(p.Timezone); err != nil || p.Timezone == "Local" || p.Timezone == "" {
		add("invalid timezone %q (example: America/New_York)", p.Timezone)
	}
	for i, s := range p.Share {
		if !strings.HasPrefix(s.Path, "/") && s.Path != "~" && !strings.HasPrefix(s.Path, "~/") {
			add("share[%d] %q: must be absolute or start with ~/", i, s.Path)
		}
	}
	for k := range p.Env {
		if k == "" || strings.ContainsAny(k, "= \t\n") {
			add("invalid env var name %q", k)
		}
	}
	if !hostnameRe.MatchString(p.VM.Hostname) {
		add("invalid vm.hostname %q", p.VM.Hostname)
	}
	if !userRe.MatchString(p.VM.Username) || p.VM.Username == "root" {
		add("invalid vm.username %q", p.VM.Username)
	}
	switch p.Checks.OnStart {
	case "", CheckOff, CheckQuick, CheckFull:
	default:
		add("checks.on_start must be off, quick or full")
	}
	if c := p.Checks.ExpectCountry; c != "" && !regexp.MustCompile(`^[A-Z]{2}$`).MatchString(c) {
		add("checks.expect_country must be a 2-letter ISO code like US (got %q)", c)
	}
	if ip := p.Checks.ExpectIP; ip != "" && net.ParseIP(ip) == nil {
		add("checks.expect_ip is not an IP address: %q", ip)
	}
	if p.VM.CPUs < 1 || p.VM.MemoryMB < 512 || p.VM.DiskGB < 4 {
		add("vm: cpus >= 1, memory_mb >= 512, disk_gb >= 4")
	}
	return errors.Join(errs...)
}

// Lang returns the language part of the locale, e.g. "en_US".
func (p *Profile) Lang() string { return strings.SplitN(p.Locale, ".", 2)[0] }

// ExpandedShares returns shares with ~ expanded and paths cleaned, sorted.
func (p *Profile) ExpandedShares() ([]Share, error) {
	uh, err := os.UserHomeDir()
	if err != nil {
		return nil, err
	}
	out := make([]Share, 0, len(p.Share))
	for _, s := range p.Share {
		abs := s.Path
		if abs == "~" {
			abs = uh
		} else if strings.HasPrefix(abs, "~/") {
			abs = filepath.Join(uh, abs[2:])
		}
		out = append(out, Share{Path: filepath.Clean(abs), ReadOnly: s.ReadOnly})
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Path < out[j].Path })
	return out, nil
}

// GuestPath maps a host directory to its path inside the VM. Shares are
// mounted in the guest at their configured path, so the result is always
// expressed under that path even when the host path reaches the share
// through a symlink alias (on macOS /tmp is /private/tmp, /var is
// /private/var). The innermost matching share wins.
func (p *Profile) GuestPath(hostPath string) (guest string, share Share, ok bool) {
	shares, err := p.ExpandedShares()
	if err != nil {
		return "", Share{}, false
	}
	hostPath = filepath.Clean(hostPath)
	hostReal := realPath(hostPath)
	best := -1
	for _, s := range shares {
		for _, cand := range [][2]string{{s.Path, hostPath}, {realPath(s.Path), hostReal}} {
			base, target := cand[0], cand[1]
			if target != base && !strings.HasPrefix(target, base+string(filepath.Separator)) {
				continue
			}
			if len(base) <= best {
				continue
			}
			rel, err := filepath.Rel(base, target)
			if err != nil {
				continue
			}
			best, guest, share, ok = len(base), filepath.Join(s.Path, rel), s, true
		}
	}
	return guest, share, ok
}

// realPath resolves symlinks; if the path does not exist it resolves the
// deepest existing parent.
func realPath(p string) string {
	if r, err := filepath.EvalSymlinks(p); err == nil {
		return r
	}
	dir, base := filepath.Split(filepath.Clean(p))
	dir = filepath.Clean(dir)
	if dir == p || dir == "." || dir == "/" {
		return p
	}
	return filepath.Join(realPath(dir), base)
}

// RealPath is realPath for other packages.
func RealPath(p string) string { return realPath(p) }

// Load reads and validates a profile by name.
func Load(name string) (*Profile, error) {
	if err := ValidName(name); err != nil {
		return nil, err
	}
	dir, err := Dir(name)
	if err != nil {
		return nil, err
	}
	file := filepath.Join(dir, "profile.toml")
	st, err := os.Stat(file)
	if errors.Is(err, os.ErrNotExist) {
		return nil, clierr.New(clierr.NotFound, fmt.Sprintf("%s list; %s create %s --proxy URL", App, App, name),
			"profile %q does not exist", name)
	}
	if err != nil {
		return nil, err
	}
	if st.Mode().Perm()&0o077 != 0 {
		return nil, fmt.Errorf("%s is accessible by other users (mode %o); run: chmod 600 %s", file, st.Mode().Perm(), file)
	}
	var p Profile
	md, err := toml.DecodeFile(file, &p)
	if err != nil {
		return nil, fmt.Errorf("profile %q: %w", name, err)
	}
	if und := md.Undecoded(); len(und) > 0 {
		return nil, fmt.Errorf("profile %q: unknown keys %v", name, und)
	}
	p.Name = name
	if err := p.Validate(); err != nil {
		return nil, clierr.Wrap(clierr.Usage, fmt.Sprintf("fix with: %s set %s KEY=VALUE (or %s edit %s)", App, name, App, name),
			fmt.Errorf("profile %q is invalid:\n%w", name, err))
	}
	return &p, nil
}

// Save writes the profile atomically with 0600 permissions.
func (p *Profile) Save() error {
	if err := p.Validate(); err != nil {
		return err
	}
	dir, err := Dir(p.Name)
	if err != nil {
		return err
	}
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return err
	}
	var buf bytes.Buffer
	fmt.Fprintf(&buf, "# %s profile %q — edit with care, then run: %s show %s\n", App, p.Name, App, p.Name)
	if err := toml.NewEncoder(&buf).Encode(p); err != nil {
		return err
	}
	return WriteFileAtomic(filepath.Join(dir, "profile.toml"), buf.Bytes(), 0o600)
}

// LoadState reads state.json, creating it on first use.
func LoadState(name string) (*State, error) {
	dir, err := Dir(name)
	if err != nil {
		return nil, err
	}
	file := filepath.Join(dir, "state.json")
	b, err := os.ReadFile(file)
	if errors.Is(err, os.ErrNotExist) {
		s := &State{MachineID: randHex(16), MAC: RandomMAC(), Created: time.Now().UTC()}
		b, _ := json.MarshalIndent(s, "", "  ")
		if err := os.MkdirAll(dir, 0o700); err != nil {
			return nil, err
		}
		return s, WriteFileAtomic(file, b, 0o600)
	}
	if err != nil {
		return nil, err
	}
	var s State
	if err := json.Unmarshal(b, &s); err != nil {
		return nil, fmt.Errorf("%s: %w", file, err)
	}
	if !midRe.MatchString(s.MachineID) || !macRe.MatchString(s.MAC) {
		return nil, fmt.Errorf("%s is corrupt", file)
	}
	return &s, nil
}

// List returns all profile names.
func List() ([]string, error) {
	dir, err := ProfilesDir()
	if err != nil {
		return nil, err
	}
	ents, err := os.ReadDir(dir)
	if errors.Is(err, os.ErrNotExist) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	var out []string
	for _, e := range ents {
		if e.IsDir() && nameRe.MatchString(e.Name()) {
			if _, err := os.Stat(filepath.Join(dir, e.Name(), "profile.toml")); err == nil {
				out = append(out, e.Name())
			}
		}
	}
	return out, nil
}

// WriteFileAtomic writes via a temp file + rename.
func WriteFileAtomic(path string, data []byte, perm os.FileMode) error {
	tmp := filepath.Join(filepath.Dir(path), "."+filepath.Base(path)+".tmp")
	if err := os.WriteFile(tmp, data, perm); err != nil {
		return err
	}
	if err := os.Chmod(tmp, perm); err != nil {
		return err
	}
	return os.Rename(tmp, path)
}

// RandomMAC returns a random locally-administered unicast MAC address.
func RandomMAC() string {
	b := make([]byte, 6)
	rand.Read(b)
	b[0] = (b[0] | 0x02) &^ 0x01
	parts := make([]string, 6)
	for i, x := range b {
		parts[i] = fmt.Sprintf("%02x", x)
	}
	return strings.Join(parts, ":")
}

func randHex(n int) string {
	b := make([]byte, n)
	rand.Read(b)
	return hex.EncodeToString(b)
}
