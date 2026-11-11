// Command hat runs CLI programs inside isolated "profiles": each profile
// has its own upstream proxy (with a kill switch), locale and timezone, and
// in VM mode its own hostname, machine-id, MAC address and credentials.
package main

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"runtime"

	"golang.org/x/term"

	"hat/internal/clierr"
	"hat/internal/config"
	"hat/internal/lite"
	"hat/internal/shim"
)

// Version is set at build time with -ldflags "-X main.Version=...".
var Version = "0.1.0-dev"

const usage = `hat — run CLI programs inside isolated network/identity profiles

Examples
  hat create us --proxy socks5://user@1.2.3.4:1080 --password-stdin --tz America/New_York --share ~/code
  hat preflight us                  # checklist: proxy, exit IP, expectations
  hat run us -- curl -s https://ipinfo.io
  hat shim add teil --profile us    # then just type: teil ...
  hat --json list

Profiles
  hat create <p> --proxy URL [--mode vm|lite] [--tz ZONE] [--locale L] [--share DIR]...
                 [--password-stdin] [--expect-country CC] [--exists-ok]
  hat list | show <p> | rm <p> --yes
  hat set <p> KEY=VALUE...          (non-interactive edit; see: hat set --help)
  hat edit <p>                      (opens $EDITOR)
  hat proxy-password <p> [--password-stdin|--keychain|--none]
  hat share add|rm|list <p> [dir] [--ro]

Run
  hat run <p> [--home] [-T|-t] -- <command> [args...]
  hat shell <p>
  hat shim add <command> --profile <p> [--as NAME] | shim rm <NAME> | shim list

Checks
  hat preflight <p> [--force] [--level quick|full]   runs automatically before every launch
  hat check <p>          full leak test inside the profile (DNS, UDP, kill switch, identity)
  hat doctor             PATH, vfkit, sandbox-exec
  hat debug-bundle <p>   collect logs for a bug report

VM
  hat start | stop | status <p>
  hat image pull | import <file.tar.xz>

Global flags (before the command) and environment
  --json         machine-readable output on stdout; errors as JSON on stderr   (HAT_JSON=1)
  --quiet, -q    no notices on stderr                                           (HAT_QUIET=1)
  --no-input     never prompt; fail with a hint instead (automatic without a TTY) (HAT_NO_INPUT=1)
  --skip-preflight  skip the launch checklist (the kill switch still applies)   (HAT_SKIP_PREFLIGHT=1)
  HAT_PROFILE    profile for shims;  HAT_HOME  data directory (default ~/.hat)

Exit codes: 0 ok, 1 error, 2 usage/input required, 3 not found, 4 proxy unreachable/auth,
5 preflight failed, 6 VM failed, 7 already exists. run/shell/shims return the command's
exit code, or 125 when hat itself fails (127 command not found).

Every profile always uses its proxy. If the proxy is unreachable, connections
fail; hat never falls back to a direct connection.
`

var (
	jsonOut       = os.Getenv("HAT_JSON") != ""
	quietOut      = os.Getenv("HAT_QUIET") != ""
	noInput       = os.Getenv("HAT_NO_INPUT") != ""
	skipPreflight = os.Getenv("HAT_SKIP_PREFLIGHT") != ""
)

func main() {
	name := filepath.Base(os.Args[0])
	if name == lite.OpenURLHelper {
		os.Exit(openURL(os.Args[1:]))
	}
	if name != config.App && isShim(name) {
		code, err := runShim(name, os.Args[1:])
		os.Exit(finish(true, code, err))
	}
	args := parseGlobals(os.Args[1:])
	if quietOut {
		os.Setenv("HAT_QUIET", "1")
	}
	runLike := len(args) > 0 && (args[0] == "run" || args[0] == "shell")
	code, err := dispatch(args)
	os.Exit(finish(runLike, code, err))
}

// isShim reports whether name is a registered shim (so a renamed hat
// binary, e.g. hat-darwin-arm64, still works as hat).
func isShim(name string) bool {
	f, err := shim.Load()
	if err != nil {
		return false
	}
	_, ok := f.Shims[name]
	return ok
}

// parseGlobals consumes global flags placed before the command.
func parseGlobals(args []string) []string {
	for len(args) > 0 {
		switch args[0] {
		case "--json":
			jsonOut = true
		case "--quiet", "-q":
			quietOut = true
		case "--no-input":
			noInput = true
		case "--skip-preflight":
			skipPreflight = true
		default:
			return args
		}
		args = args[1:]
	}
	return args
}

// interactive reports whether we may prompt the user.
func interactive() bool {
	return !noInput && !jsonOut && term.IsTerminal(int(os.Stdin.Fd()))
}

// exitError carries a specific exit code without an error message.
type exitError struct{ code int }

func (e exitError) Error() string { return fmt.Sprintf("exit %d", e.code) }

// finish prints err (text or JSON) and returns the process exit code.
func finish(runLike bool, code int, err error) int {
	var ee exitError
	if errors.As(err, &ee) {
		return ee.code
	}
	if err == nil {
		return code
	}
	exit := clierr.ExitCode(err)
	if runLike {
		// The command's own exit codes pass through; hat's failures are 125.
		c, _, _ := clierr.Classify(err)
		switch {
		case c == clierr.CommandNotFound || code == 127:
			exit = 127
		case code == 126:
			exit = 126
		default:
			exit = 125
		}
	}
	printError(err, exit)
	return exit
}

func printError(err error, exit int) {
	if jsonOut {
		b, _ := json.Marshal(map[string]any{"ok": false, "schema": 1, "error": clierr.ToPayload(err, exit)})
		fmt.Fprintln(os.Stderr, string(b))
		return
	}
	fmt.Fprintf(os.Stderr, "%s: %v\n", config.App, err)
	if _, hint, _ := clierr.Classify(err); hint != "" {
		fmt.Fprintf(os.Stderr, "  hint: %s\n", hint)
	}
}

// emit writes a successful JSON result to stdout.
func emit(data any) error {
	enc := json.NewEncoder(os.Stdout)
	enc.SetIndent("", "  ")
	return enc.Encode(map[string]any{"ok": true, "schema": 1, "data": data})
}

// notice prints a human notice to stderr unless quiet or JSON.
func notice(format string, a ...any) {
	if quietOut || jsonOut {
		return
	}
	fmt.Fprintf(os.Stderr, "["+config.App+"] "+format+"\n", a...)
}

func usageErr(format string, a ...any) error {
	return clierr.New(clierr.Usage, config.App+" help", format, a...)
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
		if jsonOut {
			return 0, emit(map[string]string{"version": Version, "os": runtime.GOOS, "arch": runtime.GOARCH})
		}
		fmt.Printf("%s %s\n", config.App, Version)
		return 0, nil
	case "create":
		return 0, cmdCreate(rest)
	case "list", "ls":
		return 0, cmdList(rest)
	case "show":
		return 0, cmdShow(rest)
	case "set":
		return 0, cmdSet(rest)
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
	case "preflight":
		return cmdPreflight(rest)
	case "check":
		return cmdCheck(rest)
	case "doctor":
		return cmdDoctor(rest)
	case "debug-bundle":
		return 0, cmdDebugBundle(rest)
	case "__daemon":
		return 0, cmdDaemon(rest)
	}
	return 2, usageErr("unknown command %q", cmd)
}

// openURL is the BROWSER helper used inside profiles: opening the host
// browser would use the real network, so it only prints the URL.
func openURL(args []string) int {
	for _, u := range args {
		fmt.Fprintf(os.Stderr, "[%s] Open this URL in a browser that uses the same proxy:\n  %s\n", config.App, u)
	}
	return 0
}
