# hat

> Put a different hat on your command-line programs. Each profile gets its own exit IP (proxy only, with a kill switch), language and timezone; in `vm` mode it also gets its own hostname, machine-id, MAC address and credentials. Manage your CLI environments the way an anti-detect browser manages browser profiles.

Use cases: testing programs as if from another region or language, keeping work and personal accounts and networks fully separate, privacy.

```
teil chat                 # via a shim, runs inside the us-east profile
hat run jp -- curl https://example.com
hat shell us-east
```

## Two modes

| | `lite` | `vm` (default) |
|---|---|---|
| How | macOS sandbox (Seatbelt) + local bridge proxy | one lightweight Linux VM per profile (vfkit) |
| Startup | instant | a few minutes the first time (installs the guest), seconds afterwards |
| Exit IP / no DNS leaks / kill switch | ✅ enforced by the kernel sandbox | ✅ the VM's only network path leads to the proxy |
| Language, timezone | ✅ | ✅ |
| Hostname, machine-id, MAC | ❌ (same as the Mac) | ✅ per profile |
| Credentials / Keychain | ❌ shared (optional separate HOME) | ✅ fully separate |
| Program that runs | the one installed on your Mac | the Linux build installed in the VM |
| CLIs using the system TLS stack (Go/Swift) | need `--allow-trustd`, or use vm | ✅ |

## Security guarantees (and what is not guaranteed)

**Guaranteed**
- Every profile **must** have a proxy. If the proxy is unreachable, connections fail; hat **never falls back to a direct connection**.
- Hostnames are not resolved locally; they are passed to the proxy as-is (socks5h semantics). The system resolver (mDNSResponder) is blocked inside the sandbox; inside the VM every query on port 53 is answered locally by hat (fake-ip).
- UDP (QUIC etc.), ICMP and IPv6 are dropped; connections to the host, the LAN and cloud metadata addresses (169.254.169.254) are refused.
- Programs in the lite sandbox cannot read `~/.hat` (other profiles' proxy passwords) and cannot ask the system to open a browser (`open` would use the real network).
- In the code, only `internal/upstream` can open network connections; the `internal/policy` test enforces this.

**Not guaranteed / known limitations**
- Shims are a convenience, not enforcement: programs started by absolute path, from an IDE or from the Dock bypass them.
- The VM can be identified as a VM (DMI reports Apple Virtualization). vfkit generates a new GenericMachineIdentifier on every boot (readable by root only).
- Programs in the VM still see and may report what any Linux machine has: hostname, working directory, and — when run inside a git repository — its remote URL, branch and commit. Using the same repository from two profiles links them; hat cannot hide that. Absolute symlinks inside shared directories show their macOS target (e.g. `/Users/<you>/…`) to anything that reads them.
- Read-only shares (`--ro`) in vm mode are enforced inside the VM, so root in the VM can bypass them. Only directories can be shared, not single files, and changing shares requires a VM restart (`hat stop <p>`).
- If the upstream proxy runs on your machine (e.g. a local Clash, which needs `--allow-local-upstream`), the kill switch depends on that proxy never connecting directly itself (use global mode with a fixed node).
- With `lite` + `--allow-trustd`, the system certificate service may check revocation (OCSP/CRL) from your real IP.

## Install

Requirements: Apple Silicon Mac, macOS 13+. vm mode needs [vfkit](https://github.com/crc-org/vfkit) ≥ 0.6.1:

```bash
brew install vfkit
```

Build from source (Go 1.26+), or download `hat-darwin-arm64` from the latest CI run under the repository's Actions tab:

```bash
make build-mac
```

```bash
sudo install -m 755 dist/hat-darwin-arm64 /usr/local/bin/hat
```

Put the shim directory first in your PATH (add this to `~/.zshrc`):

```bash
export PATH="$HOME/.hat/bin:$PATH"
```

## Quick start

```bash
hat create us-east --proxy 'socks5://user:pass@203.0.113.10:1080' --tz America/New_York --share ~/code
```

```bash
hat preflight us-east
```

`preflight` is the launch checklist (see below); it also runs automatically before every launch. For a thorough leak test run `hat check us-east`: from inside the profile it verifies that the exit IP is the proxy's, DNS and UDP do not leak, private networks are unreachable, the kill switch works, and the hostname / machine-id / MAC are the profile's.

Run a command in a profile (in vm mode the current directory must be shared):

```bash
cd ~/code/project && hat run us-east -- curl -s https://ipinfo.io
```

In vm mode shared directories are **not** mounted at their macOS path, which would carry your account name (`/Users/<you>/…`) into every program's working directory. A directory below your home is mounted at the same place below the guest home (`~/code/project` → `/home/dev/code/project`); your home itself at `/mnt/host-home`; anything else at `/mnt/host/<path>` (`/Volumes/Data` → `/mnt/host/Volumes/Data`). Mounts follow real paths (symlinks resolved), so a share reached through a symlink is mounted where its target is. `hat share list <p>` shows the mapping. In a git worktree whose `.git` file points at a macOS path, `hat run` shows git the guest path instead (a bind mount inside the VM; nothing on the Mac changes); the repository must be shared too. Relative paths work as before; absolute macOS paths in arguments do not exist in the VM. VMs started by an older hat keep the old mounts until restarted (`hat stop <p>`).

Open a shell in a profile:

```bash
hat shell us-east
```

### Wrapping a CLI (example: teil)

In vm mode, first install the Linux build of teil in the VM (example; use teil's own install method):

```bash
hat run us-east --home -- bash -lc 'npm install -g teil'
```

Create a shim; from then on typing `teil` runs it in us-east:

```bash
hat shim add teil --profile us-east
```

Bind the same tool to another profile:

```bash
hat shim add teil --as teil@jp
```

Switch profiles for one invocation:

```bash
HAT_PROFILE=jp teil chat
```

## Launch checklist (preflight)

Before anything starts through `hat run`, `hat shell` or a shim, hat runs a round of checks. **If any check fails, nothing is started:**

| Check | What it verifies | Level |
|---|---|---|
| config | profile is valid; its files are readable only by you | always |
| platform | lite: sandbox-exec available; vm: platform supported | always |
| proxy | the proxy is reachable and accepts the credentials (opens one tunnel through it) | quick |
| egress | exit IP, country and timezone, looked up through the proxy | full |
| expect_country / expect_ip | the exit must be in the expected country / be the expected IP (catches a proxy that silently moved) | full |
| timezone | warns (only) if the exit IP's timezone differs from the profile's | full |

- A passing result is cached for 10 minutes (`checks.cache_seconds`), so running many commands stays fast; failures are never cached.
- The default level is `full`; set `quick` or `off` with `hat set <p> checks.on_start=quick`.
- Pin the exit country: `hat set <p> checks.expect_country=US` (or `--expect-country US` at creation).
- Run it by hand: `hat preflight <p> [--force] [--json]`.
- The kill switch does not depend on the checklist: if the proxy dies after a passing preflight, connections still fail closed. The checklist exists to fail early with a clear error and to catch "the exit moved" problems.

## For AI agents

hat is designed to be agent-friendly (following [clig.dev](https://clig.dev/) and community conventions for agent CLIs) and ships [`skills/hat/SKILL.md`](skills/hat/SKILL.md), which agents such as Claude Code can use directly as a skill.

- **Structured output:** every read command supports `--json` (or `HAT_JSON=1`) with the envelope `{"ok":true,"schema":1,"data":...}`; data goes to stdout, notices to stderr.
- **Structured errors:** `{"ok":false,"error":{"code":"PROXY_UNREACHABLE","message":...,"hint":...,"retryable":true,"exit_code":4}}`.
- **Exit codes:** 0 ok, 1 error, 2 usage / input required, 3 not found, 4 proxy unreachable / auth failed, 5 preflight failed, 6 VM failed, 7 already exists. `run`, `shell` and shims pass through the command's own exit code; when hat itself fails they return 125 (127 for command not found).
- **Never blocks on a prompt:** without a TTY hat is non-interactive automatically (or pass `--no-input`). Change settings with `hat set <p> KEY=VALUE`, delete with `--yes`, and pass passwords with `--password-stdin` (never as an argument).
- **Idempotent:** `hat create --exists-ok`; starting the same VM concurrently is safe.
- **Signals:** SIGINT/SIGTERM sent to hat are forwarded to the running program.

## Commands

| Command | Description |
|---|---|
| `hat create <p> --proxy URL [--mode vm\|lite] [--tz] [--locale] [--hostname] [--share DIR] [--password-stdin] [--expect-country CC] [--exists-ok]` | create a profile; the password is stored separately (0600 file, or `--keychain`) |
| `hat list` / `show <p>` / `rm <p> --yes` | manage profiles |
| `hat set <p> KEY=VALUE...` | change settings non-interactively (`hat set --help` lists the keys) |
| `hat edit <p>` | edit in $EDITOR (validated before saving) |
| `hat proxy-password <p> [--password-stdin\|--keychain\|--none]` | change the proxy password |
| `hat share add\|rm\|list <p> [dir] [--ro]` | shared directories |
| `hat run <p> [--home] -- cmd...` | run a command; exit code, signals, pipes and terminal size pass through |
| `hat shell <p>` | interactive shell |
| `hat shim add <cmd> --profile <p> [--as name]` / `shim rm` / `shim list` | command shims |
| `hat start\|stop\|status <p>` | VM lifecycle (stops automatically after 30 idle minutes) |
| `hat preflight <p> [--force] [--level quick\|full]` | launch checklist |
| `hat check <p>` | full leak and kill-switch test from inside the profile |
| `hat doctor` | checks PATH, vfkit, sandbox-exec |
| `hat debug-bundle <p>` | collects logs for a bug report (no passwords) |

## Files

```
~/.hat/profiles/<p>/profile.toml   settings (editable, 0600, no password)
~/.hat/profiles/<p>/state.json     generated identity: machine-id, MAC (do not edit)
~/.hat/profiles/<p>/secret         proxy password (when password = "file")
~/.hat/profiles/<p>/preflight.json last launch checklist result
~/.hat/profiles/<p>/disk.raw       VM disk
~/.hat/profiles/<p>/daemon.log     VM daemon log; console.log is the VM console
~/.hat/bin/                        shims
~/.hat/images/                     base guest image (Debian 13 arm64, downloaded once)
```

## Development

Conventions for contributors (and AI agents working in this repository) are in [`AGENTS.md`](AGENTS.md).

```bash
make test
```

```bash
make e2e
```

`make e2e` runs the complete VM lifecycle on Linux against a fake vfkit (a "VM" simulated with gVisor): first start, command execution, concurrency, stop, restart and recovery after a daemon crash. On a real Mac, verify with:

```bash
scripts/macos-smoke.sh 'socks5://user:pass@host:port'
```

Design notes and research (in Chinese): `docs/PLAN.md`, `docs/research.md`.
