# AGENTS.md — working on the hat codebase

hat runs CLI programs inside isolated profiles on macOS (Apple Silicon): every
profile forces all traffic through one upstream proxy with a kill switch, and
sets locale/timezone; `vm` profiles also isolate hostname, machine-id, MAC and
credentials inside a Linux VM. User docs: `README.md`. Design: `docs/PLAN.md`.
Agents *using* hat (not developing it) should read `skills/hat/SKILL.md`.

## Hard rules (security invariants)

1. **No direct network access.** Only `internal/upstream` may open outbound
   connections, and only to the configured proxy server. Everything else gets
   connections through an `upstream.Dialer`. `internal/policy` enforces this;
   if you must add an exception, add it to `allowed` with a reason and expect
   pushback.
2. **Fail closed.** Any failure (profile, proxy, sandbox, VM, shim) must stop
   with an error. Never fall back to running the real program unsandboxed or
   to a direct connection.
3. **Names, not IPs.** Hostnames go to the proxy unresolved (socks5h
   semantics). Never resolve names on the host.
4. **Secrets** never appear in argv, logs, `show`, JSON output or errors
   (`upstream.Redact`). Profile files are 0600 in a 0700 directory.
5. The lite sandbox profile is deny-by-default (`internal/seatbelt`). Changing
   it requires updating `testdata/golden.sb` deliberately
   (`UPDATE_GOLDEN=1 go test ./internal/seatbelt`) and explaining why.

## Layout

```
cmd/hat/              CLI (main.go: globals, JSON envelope, exit codes)
internal/upstream     the only dialer (SOCKS5 / HTTP CONNECT)
internal/bridge       lite: local HTTP+SOCKS5 proxy with per-run credentials
internal/seatbelt     lite: SBPL generator (base.sb adapted from sandbox-runtime)
internal/lite         lite: runs a command under sandbox-exec
internal/netstack     vm: gVisor stack; TCP -> proxy, fake-ip DNS, drop UDP/ICMP
internal/vm           vm: image, cloud-init, vfkit args, daemon, client
internal/session      SSH sessions to the guest (PTY, signals, exit codes)
internal/preflight    launch checklist (proxy, exit IP, expectations), cached
internal/clierr       error codes -> exit codes + JSON error payload
internal/shim         argv[0] shims in ~/.hat/bin
internal/e2e          Linux end-to-end VM test with a fake vfkit
```

## Build and test

```bash
make test        # vet + unit/integration tests (race)
make e2e         # VM lifecycle with fake vfkit (Linux)
make build-mac   # dist/hat-darwin-arm64 (pure Go, CGO_ENABLED=0)
```

Development usually happens on Linux; macOS-only behaviour (Seatbelt, vfkit,
Keychain, real guest boot) is verified with `scripts/macos-smoke.sh` on a Mac.
Keep the main binary pure Go so it cross-compiles.

## CLI conventions (keep them when adding commands)

- Data to stdout; notices/progress to stderr (`notice()`), silenced by
  `--quiet`/`--json`.
- Every read command supports `--json` (`jsonFlag(fs)` + `emit(v)`), envelope
  `{"ok":true,"schema":1,"data":...}`; errors print
  `{"ok":false,"schema":1,"error":{code,message,hint,retryable,exit_code}}`.
- Return classified errors (`clierr.New/Wrap`) with an actionable hint.
- Never prompt unless `interactive()`; offer a flag instead (`--yes`,
  `--password-stdin`, `hat set`).
- Commands should be idempotent where possible (`create --exists-ok`).
