// Command hat runs CLI programs inside isolated "profiles": each profile
// has its own upstream proxy (with a kill switch), locale and timezone, and
// in VM mode its own hostname, machine-id, MAC address and credentials.
package main

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"hat/internal/config"
	"hat/internal/lite"
)

// Version is set at build time with -ldflags "-X main.Version=...".
var Version = "0.1.0-dev"

const usage = `hat — run CLI programs inside isolated network/identity profiles

Profiles
  hat create <p> --proxy URL [--mode vm|lite] [--tz ZONE] [--locale L] [--share DIR]...
  hat list | show <p> | edit <p> | rm <p>
  hat proxy-password <p> [--keychain|--file|--none]
  hat share add|rm <p> <dir> [--ro]

Run
  hat run <p> [--home] -- <command> [args...]
  hat shell <p>
  hat shim add <command> --profile <p> [--as NAME]    (then just type the command)
  hat shim rm <NAME> | hat shim list

VM
  hat start | stop | status <p>
  hat image pull [debian-13] | hat image import <file.tar.xz>

Diagnostics
  hat check <p>          egress IP, DNS/UDP leak probes, kill-switch test
  hat doctor             PATH, vfkit, sandbox-exec
  hat debug-bundle <p>   collect logs for a bug report
  hat version

Every profile always uses its proxy. If the proxy is unreachable, connections
fail; hat never falls back to a direct connection.
`

func main() {
	name := filepath.Base(os.Args[0])
	switch {
	case name == lite.OpenURLHelper:
		os.Exit(openURL(os.Args[1:]))
	case name != config.App && !strings.HasPrefix(name, config.App+".") && name != "main" && !strings.HasPrefix(name, "__debug"):
		os.Exit(exit(runShim(name, os.Args[1:])))
	}
	os.Exit(exit(dispatch(os.Args[1:])))
}

// exitError carries a specific exit code.
type exitError struct{ code int }

func (e exitError) Error() string { return fmt.Sprintf("exit %d", e.code) }

func exit(code int, err error) int {
	var ee exitError
	if errors.As(err, &ee) {
		return ee.code
	}
	if err != nil {
		fmt.Fprintf(os.Stderr, "%s: %v\n", config.App, err)
		if code == 0 {
			code = 1
		}
	}
	return code
}

func dispatch(args []string) (int, error) {
	if len(args) == 0 {
		fmt.Print(usage)
		return 0, nil
	}
	cmd, rest := args[0], args[1:]
	switch cmd {
	case "-h", "--help", "help":
		fmt.Print(usage)
		return 0, nil
	case "version", "--version":
		fmt.Printf("%s %s\n", config.App, Version)
		return 0, nil
	case "create":
		return 0, cmdCreate(rest)
	case "list", "ls":
		return 0, cmdList(rest)
	case "show":
		return 0, cmdShow(rest)
	case "edit":
		return 0, cmdEdit(rest)
	case "rm", "remove", "delete":
		return 0, cmdRemove(rest)
	case "proxy-password":
		return 0, cmdProxyPassword(rest)
	case "share":
		return 0, cmdShare(rest)
	case "run":
		return cmdRun(rest)
	case "shell":
		return cmdShell(rest)
	case "shim":
		return 0, cmdShim(rest)
	case "start":
		return 0, cmdStart(rest)
	case "stop":
		return 0, cmdStop(rest)
	case "status":
		return 0, cmdStatus(rest)
	case "image":
		return 0, cmdImage(rest)
	case "check":
		return cmdCheck(rest)
	case "doctor":
		return cmdDoctor(rest)
	case "debug-bundle":
		return 0, cmdDebugBundle(rest)
	case "__daemon":
		return 0, cmdDaemon(rest)
	}
	return 2, fmt.Errorf("unknown command %q (see: %s help)", cmd, config.App)
}

// openURL is the BROWSER helper used inside profiles: opening the host
// browser would use the real network, so it only prints the URL.
func openURL(args []string) int {
	for _, u := range args {
		fmt.Fprintf(os.Stderr, "[%s] Open this URL in a browser that uses the same proxy:\n  %s\n", config.App, u)
	}
	return 0
}
