---
name: hat
description: Run command-line programs inside an isolated hat profile on macOS — all traffic forced through that profile's proxy (kill switch, no DNS leaks), with the profile's locale/timezone and, in vm mode, its own hostname/machine-id/MAC/credentials. Use when asked to run a CLI "in profile X", "through the US proxy", "as the work identity", to test behaviour from another region/language, or to create/check/manage hat profiles.
---

# Using hat from an agent

hat is non-interactive by default when there is no TTY. Always prefer
`--json` and check exit codes.

## Discover

```bash
hat --json list                 # profiles: name, mode, proxy (redacted), timezone, vm.state
hat --json show <p>             # one profile incl. shares, checks, identity
hat --json shim list
```

## Run a command in a profile

```bash
hat run <p> -- <command> [args...]
```

- The command's stdout/stderr/exit code pass through unchanged.
- Exit **125** = hat itself failed (proxy down, preflight failed, VM failed,
  directory not shared) — the message on stderr starts with `hat:` and has a
  `hint:` line. With `HAT_JSON=1` that error is one JSON line on stderr:
  `{"ok":false,"error":{"code":"PROXY_UNREACHABLE","hint":"...","retryable":true}}`.
- Exit 127 = command not found in the profile.
- vm profiles run the *Linux* program inside the VM and need the current
  directory to be shared (`hat share add <p> <dir>`), or pass `--home`.
  The directory has a different path in the VM (`~/x` → `/home/<user>/x`,
  other paths → `/mnt/host/<path>`; see `hat --json show <p>`,
  `shares[].guest`): pass relative paths, not absolute macOS paths.
  git worktrees work if their repository is shared too.
- `-T` forces no TTY (use for captured output); stdin is streamed.
- A launch checklist (preflight) runs first and is cached ~10 min; it fails
  with code `PREFLIGHT_FAILED` / `EGRESS_MISMATCH` if the proxy is down or
  exits in the wrong country. Do **not** bypass it with `--skip-preflight`
  unless the user asks; never try to "fix" a failure by running the program
  outside hat.

## Create and change profiles (no prompts)

```bash
printf '%s\n' "$PROXY_PASSWORD" | hat --json create us \
  --proxy socks5://user@host:1080 --password-stdin \
  --tz America/New_York --locale en_US.UTF-8 --expect-country US \
  --share "$PWD" --exists-ok
hat --json set us timezone=America/Chicago checks.expect_country=US env.FOO=bar
hat share add us "$PWD"
hat rm us --yes
```

Never put a proxy password inside `--proxy` or any argv; use `--password-stdin`.

## Verify

```bash
hat --json preflight <p> --force   # proxy reachable, exit IP/country, expectations
hat --json check <p>               # full leak test inside the profile (slower)
hat --json status <p>              # vm: state, proxy errors, dropped UDP, DNS queries
```

## Exit codes (management commands)

0 ok · 1 error · 2 usage/input required · 3 not found · 4 proxy unreachable/auth ·
5 preflight/check failed · 6 VM failed · 7 already exists

Retry only errors with `"retryable": true` (proxy unreachable, VM failed), with backoff.
