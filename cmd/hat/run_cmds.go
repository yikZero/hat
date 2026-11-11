package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"golang.org/x/crypto/ssh"

	"hat/internal/clierr"
	"hat/internal/config"
	"hat/internal/lite"
	"hat/internal/session"
	"hat/internal/shim"
	"hat/internal/vm"
)

type runOpts struct {
	home    bool // vm: run in the guest home instead of cwd
	shell   bool // interactive shell: fall back to home if cwd not shared
	noTTY   bool
	forceTT bool
}

// splitDash splits "a b -- c d" into (["a","b"], ["c","d"]).
func splitDash(args []string) ([]string, []string, bool) {
	for i, a := range args {
		if a == "--" {
			return args[:i], args[i+1:], true
		}
	}
	return args, nil, false
}

func cmdRun(args []string) (int, error) {
	before, cmd, ok := splitDash(args)
	fs := flag.NewFlagSet("run", flag.ContinueOnError)
	home := fs.Bool("home", false, "vm: run in the guest home directory instead of the current directory")
	noTTY := fs.Bool("T", false, "never allocate a terminal")
	tty := fs.Bool("t", false, "force a terminal")
	pos, err := parseArgs(fs, before)
	if err != nil {
		return 2, err
	}
	if !ok && len(pos) > 1 {
		cmd, pos = pos[1:], pos[:1]
	}
	if len(pos) != 1 || len(cmd) == 0 {
		return 2, usageErr("usage: %s run <profile> [--home] -- <command> [args...]", config.App)
	}
	p, err := config.Load(pos[0])
	if err != nil {
		return 1, err
	}
	return runInProfile(p, cmd, runOpts{home: *home, noTTY: *noTTY, forceTT: *tty})
}

func cmdShell(args []string) (int, error) {
	name, err := needName(args, "shell <profile>")
	if err != nil {
		return 2, err
	}
	p, err := config.Load(name)
	if err != nil {
		return 1, err
	}
	if p.Mode == config.ModeLite {
		sh := os.Getenv("SHELL")
		if sh == "" {
			sh = "/bin/zsh"
		}
		fmt.Fprintf(os.Stderr, "[%s] shell in profile %q (lite) — exit to leave\n", config.App, p.Name)
		return runInProfile(p, []string{sh, "-i"}, runOpts{})
	}
	return runInProfile(p, []string{"bash", "-l"}, runOpts{shell: true})
}

func runInProfile(p *config.Profile, argv []string, o runOpts) (int, error) {
	if active := os.Getenv(config.EnvActive); active != "" {
		return 1, usageErr("already inside profile %q; nested profiles are not supported", active)
	}
	if p.Mode == config.ModeLite {
		if err := runPreflight(p); err != nil {
			return 1, err
		}
		if err := shim.EnsureHelpers(lite.OpenURLHelper); err != nil {
			return 1, err
		}
		code, err := lite.Run(p, lite.Options{Argv: argv, Quiet: quietOut})
		if err != nil && code == 127 {
			err = clierr.Wrap(clierr.CommandNotFound, "install it on this Mac, or check PATH", err)
		}
		return code, err
	}
	return runVM(p, argv, o)
}

func runVM(p *config.Profile, argv []string, o runOpts) (int, error) {
	dir := ""
	if !o.home {
		cwd, err := os.Getwd()
		if err != nil {
			return 1, err
		}
		// Prefer the shell's logical path when it is the same directory.
		if pwd := os.Getenv("PWD"); pwd != "" && pwd != cwd {
			if a, err1 := os.Stat(pwd); err1 == nil {
				if b, err2 := os.Stat(cwd); err2 == nil && os.SameFile(a, b) {
					cwd = pwd
				}
			}
		}
		if guest, _, ok := p.GuestPath(cwd); ok {
			dir = guest
		} else if !o.shell {
			return 125, clierr.New(clierr.NotShared,
				fmt.Sprintf("%s share add %s %s   (or run in the VM home: %s run %s --home -- ...)",
					config.App, p.Name, session.Quote(cwd), config.App, p.Name),
				"the current directory %s is not shared with profile %q", cwd, p.Name)
		}
	}
	if err := runPreflight(p); err != nil {
		return 1, err
	}
	ctx, cancel := signal.NotifyContext(context.Background(), syscall.SIGTERM)
	defer cancel()
	var client *ssh.Client
	for attempt := 0; ; attempt++ {
		if err := vm.EnsureRunning(ctx, p, os.Stderr); err != nil {
			return 1, clierr.Wrap(clierr.VMFailed, "hat debug-bundle "+p.Name, err)
		}
		c, err := vm.Connect(ctx, p)
		if err == nil {
			client = c
			break
		}
		// The VM may be shutting down (idle stop) right now: start it again.
		if attempt < 2 && strings.Contains(err.Error(), "stopping") {
			time.Sleep(time.Second)
			continue
		}
		return 1, clierr.Wrap(clierr.VMFailed, "hat status "+p.Name, fmt.Errorf("connecting to the VM: %w", err))
	}
	defer client.Close()
	env := map[string]string{
		"LANG": p.Locale, "LC_ALL": p.Locale, "TZ": p.Timezone, config.EnvActive: p.Name,
	}
	for _, k := range []string{"COLORTERM", "NO_COLOR", "FORCE_COLOR", "CLICOLOR"} {
		if v, ok := os.LookupEnv(k); ok {
			env[k] = v
		}
	}
	for k, v := range p.Env {
		env[k] = v
	}
	code, err := session.Run(context.Background(), client, session.Request{
		Argv: argv, Dir: dir, Env: env, LoginShell: true, NoTTY: o.noTTY, ForceTTY: o.forceTT,
	})
	if err == nil && code == 255 {
		if st, serr := vm.Status(context.Background(), p.Name); serr == nil && st.LastError != "" {
			fmt.Fprintf(os.Stderr, "[%s] last proxy error: %s (no direct connection was attempted)\n", config.App, st.LastError)
		}
	}
	return code, err
}

// runShim handles invocation through a shim symlink (argv[0] = shim name).
func runShim(name string, args []string) (int, error) {
	f, err := shim.Load()
	if err != nil {
		return 1, err
	}
	e, ok := f.Shims[name]
	if !ok {
		return 127, clierr.New(clierr.NotFound, config.App+" shim list", "%s is not a registered hat shim", name)
	}
	profile, nested, err := shim.Resolve(e, os.Getenv)
	if err != nil {
		return 1, err
	}
	bin, _ := config.BinDir()
	if nested {
		// Already inside this profile (lite): run the real program directly.
		real := e.Real
		if real == "" {
			if real, err = shim.LookPathExcluding(e.Command, bin); err != nil {
				return 127, err
			}
		}
		return 1, syscall.Exec(real, append([]string{real}, args...), os.Environ())
	}
	p, err := config.Load(profile)
	if err != nil {
		return 1, clierr.Wrap(clierr.NotFound, "", fmt.Errorf("shim %s: %w (the command was NOT run)", name, err))
	}
	argv := append([]string{e.Command}, args...)
	if p.Mode == config.ModeLite {
		real := e.Real
		if _, serr := os.Stat(real); real == "" || serr != nil {
			if real, err = shim.LookPathExcluding(e.Command, bin); err != nil {
				return 127, err
			}
		}
		argv[0] = real
	}
	return runInProfile(p, argv, runOpts{})
}

func cmdShim(args []string) error {
	if len(args) == 0 {
		return fmt.Errorf("usage: %s shim add|rm|list ...", config.App)
	}
	switch args[0] {
	case "list", "ls":
		f, err := shim.Load()
		if err != nil {
			return err
		}
		if jsonOut || (len(args) > 1 && args[1] == "--json") {
			type sv struct {
				Name    string `json:"name"`
				Command string `json:"command"`
				Profile string `json:"profile"`
				Pinned  bool   `json:"pinned"`
				Real    string `json:"real,omitempty"`
			}
			out := []sv{}
			for _, n := range f.Names() {
				e := f.Shims[n]
				out = append(out, sv{n, e.Command, e.Profile, e.Pinned, e.Real})
			}
			return emit(out)
		}
		bin, _ := config.BinDir()
		if len(f.Shims) == 0 {
			fmt.Printf("No shims. Add one with: %s shim add <command> --profile <p>\n", config.App)
		}
		for _, n := range f.Names() {
			e := f.Shims[n]
			fmt.Printf("%-20s -> %s in profile %s%s\n", n, e.Command, e.Profile, map[bool]string{true: " (pinned)"}[e.Pinned])
		}
		fmt.Printf("\nShim directory: %s (must come first in PATH)\n", bin)
		return nil
	case "rm", "remove":
		if len(args) != 2 {
			return fmt.Errorf("usage: %s shim rm <name>", config.App)
		}
		return shim.Remove(args[1])
	case "add":
	default:
		return fmt.Errorf("unknown shim command %q", args[0])
	}
	fs := flag.NewFlagSet("shim add", flag.ContinueOnError)
	profile := fs.String("profile", "", "profile to run the command in")
	as := fs.String("as", "", "shim name (default: the command name; use name@profile for a pinned variant)")
	pos, err := parseArgs(fs, args[1:])
	if err != nil {
		return err
	}
	if len(pos) != 1 {
		return fmt.Errorf("usage: %s shim add <command> --profile <p> [--as NAME]", config.App)
	}
	command := pos[0]
	name := *as
	if name == "" {
		name = command
	}
	prof := *profile
	if prof == "" {
		if _, after, ok := cut(name, "@"); ok {
			prof = after
		}
	}
	if prof == "" {
		return errors.New("--profile is required")
	}
	p, err := config.Load(prof)
	if err != nil {
		return err
	}
	bin, _ := config.BinDir()
	e := shim.Entry{Command: command, Profile: prof}
	if p.Mode == config.ModeLite {
		real, err := shim.LookPathExcluding(command, bin)
		if err != nil {
			return fmt.Errorf("%v — install %s on this Mac first", err, command)
		}
		e.Real = real
	}
	if err := shim.Add(name, e); err != nil {
		return err
	}
	fmt.Printf("Added shim %s -> %s in profile %s\n", name, command, prof)
	if p.Mode == config.ModeVM {
		fmt.Printf("Note: vm profiles run the Linux version of %s inside the VM. Install it there once, e.g.:\n  %s run %s --home -- sudo apt-get install -y <package>   (or npm/pip/curl installer)\n",
			command, config.App, prof)
	}
	if !pathHasFirst(bin) {
		fmt.Printf("\nAdd the shim directory to the front of PATH (e.g. in ~/.zshrc), then open a new terminal:\n  export PATH=\"%s:$PATH\"\n", bin)
	}
	return nil
}

func cut(s, sep string) (string, string, bool) {
	for i := 0; i+len(sep) <= len(s); i++ {
		if s[i:i+len(sep)] == sep {
			return s[:i], s[i+len(sep):], true
		}
	}
	return s, "", false
}
