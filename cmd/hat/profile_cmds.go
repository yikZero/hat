package main

import (
	"bytes"
	"context"
	"errors"
	"flag"
	"fmt"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"text/tabwriter"
	"time"

	"golang.org/x/term"

	"hat/internal/config"
	"hat/internal/secret"
	"hat/internal/shim"
	"hat/internal/upstream"
	"hat/internal/vm"
)

type multiFlag []string

func (m *multiFlag) String() string     { return strings.Join(*m, ",") }
func (m *multiFlag) Set(v string) error { *m = append(*m, v); return nil }

// parseArgs parses flags that may appear before or after positional args.
func parseArgs(fs *flag.FlagSet, args []string) ([]string, error) {
	var pos []string
	for {
		if err := fs.Parse(args); err != nil {
			return nil, err
		}
		if fs.NArg() == 0 {
			return pos, nil
		}
		pos = append(pos, fs.Arg(0))
		args = fs.Args()[1:]
	}
}

func needName(pos []string, usage string) (string, error) {
	if len(pos) != 1 {
		return "", fmt.Errorf("usage: %s %s", config.App, usage)
	}
	return pos[0], config.ValidName(pos[0])
}

func cmdCreate(args []string) error {
	fs := flag.NewFlagSet("create", flag.ContinueOnError)
	proxy := fs.String("proxy", "", "upstream proxy URL: socks5://user:pass@host:port or http://...")
	mode := fs.String("mode", config.ModeVM, "vm (full isolation) or lite (sandbox only)")
	tz := fs.String("tz", "", "IANA timezone, e.g. America/New_York")
	locale := fs.String("locale", "", "locale, e.g. en_US.UTF-8")
	hostname := fs.String("hostname", "", "VM hostname (default: random)")
	username := fs.String("username", "", "VM user name (default: dev)")
	keychain := fs.Bool("keychain", false, "store the proxy password in the macOS Keychain (prompts)")
	allowLocal := fs.Bool("allow-local-upstream", false, "allow a proxy on localhost/LAN (e.g. local Clash)")
	isolateHome := fs.Bool("isolate-home", false, "lite: give the profile its own HOME")
	allowTrustd := fs.Bool("allow-trustd", false, "lite: allow system TLS verification (needed by Go/Swift CLIs)")
	cpus := fs.Int("cpus", 0, "VM CPUs (default 2)")
	mem := fs.Int("memory", 0, "VM memory in MB (default 2048)")
	disk := fs.Int("disk", 0, "VM disk in GB (default 16)")
	start := fs.Bool("start", false, "vm: boot the VM now")
	var shares multiFlag
	fs.Var(&shares, "share", "directory to share with the profile (repeatable)")
	pos, err := parseArgs(fs, args)
	if err != nil {
		return err
	}
	name, err := needName(pos, "create <profile> --proxy URL [flags]")
	if err != nil {
		return err
	}
	if existing, _ := config.List(); contains(existing, name) {
		return fmt.Errorf("profile %q already exists", name)
	}
	if *proxy == "" {
		return errors.New("--proxy is required (every profile must use a proxy)")
	}
	u, err := url.Parse(*proxy)
	if err != nil {
		return fmt.Errorf("--proxy: %w", err)
	}
	password, hasPassword := "", false
	if u.User != nil {
		password, hasPassword = u.User.Password()
		u.User = url.User(u.User.Username())
	}
	p := config.New(name)
	p.Mode = *mode
	p.Proxy.URL = u.String()
	p.Proxy.AllowLocalUpstream = *allowLocal
	if *tz != "" {
		p.Timezone = *tz
	}
	if *locale != "" {
		p.Locale = *locale
	}
	if *hostname != "" {
		p.VM.Hostname = *hostname
	}
	if *username != "" {
		p.VM.Username = *username
	}
	if *cpus > 0 {
		p.VM.CPUs = *cpus
	}
	if *mem > 0 {
		p.VM.MemoryMB = *mem
	}
	if *disk > 0 {
		p.VM.DiskGB = *disk
	}
	p.Lite.IsolateHome = *isolateHome
	p.Lite.AllowTrustd = *allowTrustd
	for _, s := range shares {
		abs, err := absShare(s)
		if err != nil {
			return err
		}
		p.Share = append(p.Share, config.Share{Path: abs})
	}
	switch {
	case *keychain:
		if hasPassword {
			return errors.New("with --keychain, leave the password out of --proxy; you will be prompted")
		}
		p.Proxy.Password = config.PasswordKeychain
	case hasPassword:
		p.Proxy.Password = config.PasswordFile
	case u.User != nil && u.User.Username() != "" && term.IsTerminal(int(os.Stdin.Fd())):
		pw, err := readPassword("Proxy password for " + u.User.Username() + " (empty for none): ")
		if err != nil {
			return err
		}
		if pw != "" {
			password, p.Proxy.Password = pw, config.PasswordFile
		}
	}
	if err := p.Validate(); err != nil {
		return err
	}
	if err := p.Save(); err != nil {
		return err
	}
	if p.Proxy.Password == config.PasswordFile {
		if err := secret.SetFile(name, password); err != nil {
			return err
		}
	}
	if p.Proxy.Password == config.PasswordKeychain {
		fmt.Println("Enter the proxy password for the Keychain:")
		if err := secret.SetKeychainInteractive(name); err != nil {
			return err
		}
	}
	st, err := config.LoadState(name)
	if err != nil {
		return err
	}
	fmt.Printf("Created profile %q (%s mode)\n", name, p.Mode)
	fmt.Printf("  proxy     %s\n  timezone  %s\n  locale    %s\n", upstream.Redact(p.Proxy.URL), p.Timezone, p.Locale)
	if p.Mode == config.ModeVM {
		fmt.Printf("  hostname  %s\n  machine   %s\n  mac       %s\n", p.VM.Hostname, st.MachineID, st.MAC)
	}
	fmt.Printf("\nNext:\n  %s check %s\n  %s run %s -- <command>\n  %s shim add <command> --profile %s\n",
		config.App, name, config.App, name, config.App, name)
	if *start && p.Mode == config.ModeVM {
		return vm.EnsureRunning(context.Background(), p, os.Stderr)
	}
	return nil
}

func absShare(s string) (string, error) {
	if strings.HasPrefix(s, "~") {
		return s, nil
	}
	abs, err := filepath.Abs(s)
	if err != nil {
		return "", err
	}
	st, err := os.Stat(abs)
	if err != nil {
		return "", err
	}
	if !st.IsDir() {
		return "", fmt.Errorf("%s is not a directory (only directories can be shared)", abs)
	}
	// Store ~/... form when under HOME, so profiles stay portable.
	if home, err := os.UserHomeDir(); err == nil && strings.HasPrefix(abs, home+"/") {
		return "~/" + strings.TrimPrefix(abs, home+"/"), nil
	}
	return abs, nil
}

func readPassword(prompt string) (string, error) {
	fmt.Fprint(os.Stderr, prompt)
	b, err := term.ReadPassword(int(os.Stdin.Fd()))
	fmt.Fprintln(os.Stderr)
	return strings.TrimRight(string(b), "\r\n"), err
}

func contains(list []string, s string) bool {
	for _, x := range list {
		if x == s {
			return true
		}
	}
	return false
}

func cmdList(args []string) error {
	names, err := config.List()
	if err != nil {
		return err
	}
	if len(names) == 0 {
		fmt.Printf("No profiles yet. Create one with: %s create <name> --proxy socks5://user:pass@host:port\n", config.App)
		return nil
	}
	tw := tabwriter.NewWriter(os.Stdout, 0, 4, 2, ' ', 0)
	fmt.Fprintln(tw, "NAME\tMODE\tPROXY\tTIMEZONE\tLOCALE\tVM")
	for _, n := range names {
		p, err := config.Load(n)
		if err != nil {
			fmt.Fprintf(tw, "%s\t?\t(error: %v)\t\t\t\n", n, err)
			continue
		}
		state := "-"
		if p.Mode == config.ModeVM {
			state = "stopped"
			if st, err := vm.Status(context.Background(), n); err == nil {
				state = st.State
			}
		}
		fmt.Fprintf(tw, "%s\t%s\t%s\t%s\t%s\t%s\n", n, p.Mode, upstream.Redact(p.Proxy.URL), p.Timezone, p.Locale, state)
	}
	return tw.Flush()
}

func cmdShow(args []string) error {
	name, err := needName(args, "show <profile>")
	if err != nil {
		return err
	}
	p, err := config.Load(name)
	if err != nil {
		return err
	}
	dir, _ := config.Dir(name)
	b, err := os.ReadFile(filepath.Join(dir, "profile.toml"))
	if err != nil {
		return err
	}
	fmt.Printf("# %s\n%s\n", filepath.Join(dir, "profile.toml"), b)
	st, err := config.LoadState(name)
	if err == nil {
		fmt.Printf("# generated identity (state.json)\nmachine_id = %s\nmac        = %s\n", st.MachineID, st.MAC)
	}
	fmt.Printf("password storage = %s\n", p.Proxy.Password)
	return nil
}

func cmdEdit(args []string) error {
	name, err := needName(args, "edit <profile>")
	if err != nil {
		return err
	}
	if _, err := config.Load(name); err != nil {
		return err
	}
	dir, _ := config.Dir(name)
	file := filepath.Join(dir, "profile.toml")
	orig, err := os.ReadFile(file)
	if err != nil {
		return err
	}
	editor := os.Getenv("VISUAL")
	if editor == "" {
		editor = os.Getenv("EDITOR")
	}
	if editor == "" {
		editor = "vi"
	}
	tmp := filepath.Join(dir, ".profile.edit.toml")
	if err := os.WriteFile(tmp, orig, 0o600); err != nil {
		return err
	}
	defer os.Remove(tmp)
	for {
		cmd := exec.Command("sh", "-c", editor+` "$1"`, "sh", tmp)
		cmd.Stdin, cmd.Stdout, cmd.Stderr = os.Stdin, os.Stdout, os.Stderr
		if err := cmd.Run(); err != nil {
			return fmt.Errorf("editor: %w", err)
		}
		edited, _ := os.ReadFile(tmp)
		if bytes.Equal(edited, orig) {
			fmt.Println("No changes.")
			return nil
		}
		// Validate by loading from a scratch home.
		if err := os.WriteFile(file, edited, 0o600); err != nil {
			return err
		}
		if _, err := config.Load(name); err != nil {
			os.WriteFile(file, orig, 0o600)
			fmt.Fprintf(os.Stderr, "%v\n\nEdit again? [Y/n] ", err)
			var ans string
			fmt.Scanln(&ans)
			if strings.HasPrefix(strings.ToLower(ans), "n") {
				return errors.New("changes discarded")
			}
			continue
		}
		fmt.Println("Saved.")
		if st, err := vm.Status(context.Background(), name); err == nil && st.State != "" {
			fmt.Printf("The VM is running; restart it to apply: %s stop %s\n", config.App, name)
		}
		return nil
	}
}

func cmdRemove(args []string) error {
	fs := flag.NewFlagSet("rm", flag.ContinueOnError)
	yes := fs.Bool("yes", false, "do not ask for confirmation")
	pos, err := parseArgs(fs, args)
	if err != nil {
		return err
	}
	name, err := needName(pos, "rm <profile> [--yes]")
	if err != nil {
		return err
	}
	dir, _ := config.Dir(name)
	if _, err := os.Stat(dir); err != nil {
		return fmt.Errorf("profile %q does not exist", name)
	}
	if !*yes {
		fmt.Printf("Delete profile %q, its VM disk and all data inside it? [y/N] ", name)
		var ans string
		fmt.Scanln(&ans)
		if !strings.HasPrefix(strings.ToLower(ans), "y") {
			return errors.New("aborted")
		}
	}
	ctx, cancel := context.WithTimeout(context.Background(), 70*time.Second)
	defer cancel()
	if err := vm.Stop(ctx, name); err != nil && !errors.Is(err, vm.ErrNotRunning) {
		return fmt.Errorf("stopping VM: %w", err)
	}
	secret.Delete(name)
	if f, err := shim.Load(); err == nil {
		for n, e := range f.Shims {
			if e.Profile == name {
				shim.Remove(n)
				fmt.Printf("Removed shim %s\n", n)
			}
		}
	}
	if run, err := config.RunDir(name); err == nil {
		os.RemoveAll(run)
	}
	if err := os.RemoveAll(dir); err != nil {
		return err
	}
	fmt.Printf("Deleted profile %q\n", name)
	return nil
}

func cmdProxyPassword(args []string) error {
	fs := flag.NewFlagSet("proxy-password", flag.ContinueOnError)
	keychain := fs.Bool("keychain", false, "store in the macOS Keychain")
	none := fs.Bool("none", false, "the proxy needs no password")
	pos, err := parseArgs(fs, args)
	if err != nil {
		return err
	}
	name, err := needName(pos, "proxy-password <profile> [--keychain|--none]")
	if err != nil {
		return err
	}
	p, err := config.Load(name)
	if err != nil {
		return err
	}
	switch {
	case *none:
		secret.Delete(name)
		p.Proxy.Password = config.PasswordNone
	case *keychain:
		if err := secret.SetKeychainInteractive(name); err != nil {
			return err
		}
		p.Proxy.Password = config.PasswordKeychain
	default:
		pw, err := readPassword("Proxy password: ")
		if err != nil {
			return err
		}
		if err := secret.SetFile(name, pw); err != nil {
			return err
		}
		p.Proxy.Password = config.PasswordFile
	}
	if err := p.Save(); err != nil {
		return err
	}
	fmt.Println("Saved. Restart a running VM to apply:", config.App, "stop", name)
	return nil
}

func cmdShare(args []string) error {
	if len(args) == 0 {
		return fmt.Errorf("usage: %s share add|rm|list <profile> [dir] [--ro]", config.App)
	}
	sub := args[0]
	fs := flag.NewFlagSet("share", flag.ContinueOnError)
	ro := fs.Bool("ro", false, "read-only")
	pos, err := parseArgs(fs, args[1:])
	if err != nil {
		return err
	}
	if len(pos) < 1 {
		return fmt.Errorf("usage: %s share %s <profile> [dir]", config.App, sub)
	}
	p, err := config.Load(pos[0])
	if err != nil {
		return err
	}
	switch sub {
	case "list", "ls":
		shares, _ := p.ExpandedShares()
		for _, s := range shares {
			mode := "rw"
			if s.ReadOnly {
				mode = "ro"
			}
			fmt.Printf("%s\t%s\n", mode, s.Path)
		}
		return nil
	case "add", "rm":
	default:
		return fmt.Errorf("unknown share command %q", sub)
	}
	dir := "."
	if len(pos) > 1 {
		dir = pos[1]
	}
	abs, err := absShare(dir)
	if err != nil {
		return err
	}
	var kept []config.Share
	for _, s := range p.Share {
		if s.Path != abs {
			kept = append(kept, s)
		}
	}
	if sub == "add" {
		kept = append(kept, config.Share{Path: abs, ReadOnly: *ro})
	} else if len(kept) == len(p.Share) {
		return fmt.Errorf("%s is not shared", abs)
	}
	p.Share = kept
	if err := p.Save(); err != nil {
		return err
	}
	fmt.Printf("%s: %s %s\n", p.Name, map[string]string{"add": "shared", "rm": "unshared"}[sub], abs)
	if p.Mode == config.ModeVM {
		if st, err := vm.Status(context.Background(), p.Name); err == nil && st.State != "" {
			fmt.Printf("The VM is running; restart it to apply: %s stop %s\n", config.App, p.Name)
		}
	}
	return nil
}
