package main

import (
	"bufio"
	"context"
	"flag"
	"fmt"
	"os"
	"sort"
	"strconv"
	"strings"
	"time"

	"hat/internal/clierr"
	"hat/internal/config"
	"hat/internal/preflight"
	"hat/internal/upstream"
	"hat/internal/vm"
)

// jsonFlag registers --json on a command's flag set (same as the global).
func jsonFlag(fs *flag.FlagSet) {
	fs.BoolVar(&jsonOut, "json", jsonOut, "machine-readable output")
}

type shareView struct {
	Path     string `json:"path"`
	ReadOnly bool   `json:"read_only"`
}

type profileView struct {
	Name            string              `json:"name"`
	Mode            string              `json:"mode"`
	Proxy           string              `json:"proxy"`
	PasswordStorage string              `json:"password_storage"`
	Locale          string              `json:"locale"`
	Timezone        string              `json:"timezone"`
	Shares          []shareView         `json:"shares"`
	Env             map[string]string   `json:"env,omitempty"`
	Checks          config.ChecksConfig `json:"checks"`
	Lite            *config.LiteConfig  `json:"lite,omitempty"`
	VM              *vmView             `json:"vm,omitempty"`
	Dir             string              `json:"dir"`
}

type vmView struct {
	Hostname        string `json:"hostname"`
	Username        string `json:"username"`
	MachineID       string `json:"machine_id"`
	MAC             string `json:"mac"`
	CPUs            int    `json:"cpus"`
	MemoryMB        int    `json:"memory_mb"`
	DiskGB          int    `json:"disk_gb"`
	IdleStopMinutes int    `json:"idle_stop_minutes"`
	State           string `json:"state"`
}

func viewOf(p *config.Profile) profileView {
	dir, _ := config.Dir(p.Name)
	v := profileView{Name: p.Name, Mode: p.Mode, Proxy: upstream.Redact(p.Proxy.URL), PasswordStorage: p.Proxy.Password,
		Locale: p.Locale, Timezone: p.Timezone, Env: p.Env, Checks: p.Checks, Dir: dir, Shares: []shareView{}}
	if shares, err := p.ExpandedShares(); err == nil {
		for _, s := range shares {
			v.Shares = append(v.Shares, shareView{s.Path, s.ReadOnly})
		}
	}
	if p.Mode == config.ModeLite {
		l := p.Lite
		v.Lite = &l
	} else {
		st, _ := config.LoadState(p.Name)
		vv := &vmView{Hostname: p.VM.Hostname, Username: p.VM.Username, CPUs: p.VM.CPUs, MemoryMB: p.VM.MemoryMB,
			DiskGB: p.VM.DiskGB, IdleStopMinutes: p.VM.IdleStopMinutes, State: "stopped"}
		if st != nil {
			vv.MachineID, vv.MAC = st.MachineID, st.MAC
		}
		if s, err := vm.Status(context.Background(), p.Name); err == nil {
			vv.State = s.State
		}
		v.VM = vv
	}
	return v
}

// settable describes the keys accepted by `hat set`.
var settable = []struct{ key, help string }{
	{"mode", "vm | lite"},
	{"locale", "e.g. en_US.UTF-8"},
	{"timezone", "IANA zone, e.g. America/New_York"},
	{"proxy.url", "proxy URL without password"},
	{"proxy.allow_local_upstream", "true | false"},
	{"checks.on_start", "off | quick | full"},
	{"checks.cache_seconds", "seconds a passing preflight is reused"},
	{"checks.expect_country", "ISO country code the exit IP must be in (empty to clear)"},
	{"checks.expect_ip", "exact exit IP required (empty to clear)"},
	{"lite.isolate_home", "true | false"},
	{"lite.allow_trustd", "true | false"},
	{"vm.hostname", "guest hostname"},
	{"vm.username", "guest user (only before first start)"},
	{"vm.cpus", "number"},
	{"vm.memory_mb", "number"},
	{"vm.idle_stop_minutes", "number (0 = never)"},
	{"env.NAME", "environment variable for the profile (empty value removes it)"},
}

func setKey(p *config.Profile, key, val string) error {
	b := func() (bool, error) { return strconv.ParseBool(val) }
	n := func() (int, error) { return strconv.Atoi(val) }
	var err error
	switch key {
	case "mode":
		p.Mode = val
	case "locale":
		p.Locale = val
	case "timezone", "tz":
		p.Timezone = val
	case "proxy.url":
		p.Proxy.URL = val
	case "proxy.allow_local_upstream":
		p.Proxy.AllowLocalUpstream, err = b()
	case "checks.on_start":
		p.Checks.OnStart = val
	case "checks.cache_seconds":
		p.Checks.CacheSeconds, err = n()
	case "checks.expect_country":
		p.Checks.ExpectCountry = strings.ToUpper(val)
	case "checks.expect_ip":
		p.Checks.ExpectIP = val
	case "lite.isolate_home":
		p.Lite.IsolateHome, err = b()
	case "lite.allow_trustd":
		p.Lite.AllowTrustd, err = b()
	case "vm.hostname":
		p.VM.Hostname = val
	case "vm.username":
		p.VM.Username = val
	case "vm.cpus":
		p.VM.CPUs, err = n()
	case "vm.memory_mb":
		p.VM.MemoryMB, err = n()
	case "vm.idle_stop_minutes":
		p.VM.IdleStopMinutes, err = n()
	default:
		if name, ok := strings.CutPrefix(key, "env."); ok && name != "" {
			if p.Env == nil {
				p.Env = map[string]string{}
			}
			if val == "" {
				delete(p.Env, name)
			} else {
				p.Env[name] = val
			}
			return nil
		}
		return usageErr("unknown key %q (see: %s set --help)", key, config.App)
	}
	if err != nil {
		return usageErr("%s: invalid value %q", key, val)
	}
	return nil
}

func cmdSet(args []string) error {
	fs := flag.NewFlagSet("set", flag.ContinueOnError)
	jsonFlag(fs)
	fs.Usage = func() {
		fmt.Fprintf(os.Stderr, "usage: %s set <profile> KEY=VALUE...\n\nkeys:\n", config.App)
		for _, s := range settable {
			fmt.Fprintf(os.Stderr, "  %-28s %s\n", s.key, s.help)
		}
	}
	pos, err := parseArgs(fs, args)
	if err != nil {
		return err
	}
	if len(pos) < 2 {
		fs.Usage()
		return usageErr("usage: %s set <profile> KEY=VALUE...", config.App)
	}
	p, err := config.Load(pos[0])
	if err != nil {
		return err
	}
	oldUser := p.VM.Username
	for _, kv := range pos[1:] {
		k, v, ok := strings.Cut(kv, "=")
		if !ok {
			return usageErr("expected KEY=VALUE, got %q", kv)
		}
		if err := setKey(p, strings.TrimSpace(k), v); err != nil {
			return err
		}
	}
	if p.VM.Username != oldUser && fileExistsPath(vmKnownHost(p.Name)) {
		return usageErr("vm.username cannot change after the VM was created")
	}
	if err := p.Save(); err != nil {
		return clierr.Wrap(clierr.Usage, "", err)
	}
	if jsonOut {
		return emit(viewOf(p))
	}
	fmt.Printf("Updated %s.\n", p.Name)
	if p.Mode == config.ModeVM {
		if st, err := vm.Status(context.Background(), p.Name); err == nil && st.State != "" {
			fmt.Printf("The VM is running; restart it to apply VM settings: %s stop %s\n", config.App, p.Name)
		}
	}
	return nil
}

func vmKnownHost(name string) string {
	paths, err := vm.PathsFor(name)
	if err != nil {
		return ""
	}
	return paths.KnownHost
}

func fileExistsPath(p string) bool {
	if p == "" {
		return false
	}
	_, err := os.Stat(p)
	return err == nil
}

func cmdPreflight(args []string) (int, error) {
	fs := flag.NewFlagSet("preflight", flag.ContinueOnError)
	jsonFlag(fs)
	force := fs.Bool("force", false, "ignore the cached result")
	level := fs.String("level", "", "quick | full (default: the profile's checks.on_start, or full if off)")
	pos, err := parseArgs(fs, args)
	if err != nil {
		return 2, err
	}
	name, err := needName(pos, "preflight <profile> [--force] [--level quick|full]")
	if err != nil {
		return 2, err
	}
	p, err := config.Load(name)
	if err != nil {
		return 0, err
	}
	lv := *level
	if lv == "" && p.Checks.Level() == config.CheckOff {
		lv = config.CheckFull
	}
	ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
	defer cancel()
	r, err := preflight.Run(ctx, p, preflight.Options{Level: lv, Force: *force})
	if jsonOut {
		if err != nil {
			printReportJSON(r)
			return 0, err
		}
		return 0, emit(r)
	}
	printReport(r)
	return 0, err
}

func printReportJSON(r *preflight.Report) {
	if r != nil {
		emit(r)
	}
}

func printReport(r *preflight.Report) {
	if r == nil {
		return
	}
	cached := ""
	if r.Cached {
		cached = fmt.Sprintf(" (cached from %s ago)", time.Since(r.At).Round(time.Second))
	}
	fmt.Printf("Preflight for %q, level %s%s\n", r.Profile, r.Level, cached)
	for _, it := range r.Items {
		fmt.Printf("  [%s] %-15s %s\n", strings.ToUpper(it.Status), it.Name, it.Detail)
	}
}

// runPreflight is the launch hook: silent when everything passes.
func runPreflight(p *config.Profile) error {
	if skipPreflight {
		return nil
	}
	ctx, cancel := context.WithTimeout(context.Background(), 45*time.Second)
	defer cancel()
	r, err := preflight.Run(ctx, p, preflight.Options{})
	if err != nil {
		return err
	}
	if !r.Cached {
		var warns []string
		for _, it := range r.Items {
			if it.Status == preflight.Warn {
				warns = append(warns, it.Name+": "+it.Detail)
			}
		}
		sort.Strings(warns)
		for _, w := range warns {
			notice("warning: %s", w)
		}
	}
	return nil
}

// readSecretStdin reads one line (the password) from stdin.
func readSecretStdin() (string, error) {
	line, err := bufio.NewReader(os.Stdin).ReadString('\n')
	if err != nil && line == "" {
		return "", clierr.New(clierr.InputRequired, "pipe the password on stdin, e.g. printf '%s\\n' \"$PW\" | hat ...", "no password on stdin")
	}
	return strings.TrimRight(line, "\r\n"), nil
}
