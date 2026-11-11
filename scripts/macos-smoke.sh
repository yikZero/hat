#!/bin/bash
# hat smoke test for macOS (Apple Silicon).
#
#   scripts/macos-smoke.sh 'socks5://user:pass@host:port' [--keep] [--lite-only]
#
# Creates two throw-away profiles (smoke-lite, smoke-vm), runs every check,
# prints PASS/FAIL per item and writes a debug bundle at the end. Send the
# printed summary and the bundle back if anything fails.
set -u
PROXY="${1:?usage: $0 PROXY_URL [--keep] [--lite-only]}"; shift
KEEP=0; LITE_ONLY=0
for a in "$@"; do case "$a" in --keep) KEEP=1;; --lite-only) LITE_ONLY=1;; esac; done

HAT="${HAT:-hat}"
command -v "$HAT" >/dev/null || HAT="$(cd "$(dirname "$0")/.." && pwd)/dist/hat-darwin-arm64"
PASS=0; FAIL=0
ok()   { echo "  [PASS] $*"; PASS=$((PASS+1)); }
bad()  { echo "  [FAIL] $*"; FAIL=$((FAIL+1)); }
expect_code() { # name want cmd...
  local name="$1" want="$2"; shift 2
  "$@" </dev/null >/tmp/hat-smoke.out 2>&1; local got=$?
  if [ "$got" = "$want" ]; then ok "$name (exit $got)"; else bad "$name (exit $got, want $want): $(tail -3 /tmp/hat-smoke.out)"; fi
}
now() { python3 -c 'import time; print(time.time())' 2>/dev/null || date +%s; }

echo "== environment"
sw_vers 2>/dev/null | tr '\n' ' '; echo; uname -m
"$HAT" version
"$HAT" doctor || true

WORK="$(mktemp -d /tmp/hat-smoke.XXXXXX)"
cd "$WORK"
cleanup() {
  [ "$KEEP" = 1 ] && { echo "(kept profiles smoke-lite / smoke-vm)"; return; }
  "$HAT" rm smoke-lite --yes >/dev/null 2>&1
  "$HAT" rm smoke-vm --yes >/dev/null 2>&1
}
trap cleanup EXIT
"$HAT" rm smoke-lite --yes >/dev/null 2>&1; "$HAT" rm smoke-vm --yes >/dev/null 2>&1

echo "== lite mode"
if "$HAT" create smoke-lite --mode lite --proxy "$PROXY" --tz America/New_York --locale en_US.UTF-8 </dev/null >/dev/null; then
  ok "create lite profile"
  "$HAT" preflight smoke-lite --force && ok "preflight (proxy + exit IP)" || bad "preflight (see above)"
  "$HAT" --json preflight smoke-lite | python3 -c 'import json,sys; d=json.load(sys.stdin); assert d["ok"] and d["data"]["cached"]' \
    && ok "preflight cached + JSON envelope" || bad "preflight cache/JSON"
  "$HAT" set smoke-lite checks.expect_country=ZZ >/dev/null
  expect_code "expect_country mismatch blocks launch" 125 "$HAT" run smoke-lite -- true
  "$HAT" set smoke-lite checks.expect_country= >/dev/null
  expect_code "rm without --yes refused (no TTY)" 2 "$HAT" rm smoke-lite
  "$HAT" check smoke-lite && ok "hat check smoke-lite" || bad "hat check smoke-lite (see above)"
  expect_code "exit code passthrough" 42 "$HAT" run smoke-lite -- sh -c 'exit 42'
  expect_code "signal exit code (SIGTERM => 143)" 143 "$HAT" run smoke-lite -- sh -c 'kill -TERM $$'
  out=$(echo hello | "$HAT" run smoke-lite -- cat); [ "$out" = hello ] && ok "stdin pipe" || bad "stdin pipe: $out"
  out=$("$HAT" run smoke-lite -- sh -c 'echo "$TZ $LANG"'); [ "$out" = "America/New_York en_US.UTF-8" ] && ok "TZ/LANG" || bad "TZ/LANG: $out"
  out=$("$HAT" run smoke-lite -- /usr/bin/curl -sS --noproxy '*' --max-time 5 https://1.1.1.1 2>&1); [ $? -ne 0 ] && ok "direct HTTPS blocked" || bad "direct HTTPS NOT blocked"
  out=$("$HAT" run smoke-lite -- /usr/bin/python3 -c 'import socket; print(socket.gethostbyname("example.com"))' 2>&1)
  echo "$out" | grep -qE '^[0-9]+\.' && bad "local DNS resolution works inside sandbox (DNS leak): $out" || ok "local DNS resolution blocked"
  out=$("$HAT" run smoke-lite -- cat "$HOME/.hat/profiles/smoke-lite/profile.toml" 2>&1); [ $? -ne 0 ] && ok "~/.hat unreadable from inside" || bad "~/.hat readable from inside the sandbox"
  out=$("$HAT" run smoke-lite -- /usr/bin/open https://example.com 2>&1); [ $? -ne 0 ] && ok "open (host browser) blocked" || bad "open launched the host browser"
else
  bad "create lite profile"
fi

if [ "$LITE_ONLY" = 0 ]; then
  echo "== vm mode"
  if "$HAT" create smoke-vm --proxy "$PROXY" --tz Asia/Tokyo --locale ja_JP.UTF-8 --hostname smoke-box --share "$WORK" </dev/null >/dev/null; then
    ok "create vm profile"
    t0=$(now); "$HAT" start smoke-vm && ok "first boot ($(python3 -c "print(round($(now)-$t0))" 2>/dev/null)s)" || bad "first boot (see: $HAT debug-bundle smoke-vm)"
    "$HAT" check smoke-vm && ok "hat check smoke-vm" || bad "hat check smoke-vm (see above)"
    t0=$(now); out=$("$HAT" run smoke-vm -- echo warm); [ "$out" = warm ] && ok "warm exec ($(python3 -c "print(round(($(now)-$t0)*1000))" 2>/dev/null) ms)" || bad "warm exec: $out"
    expect_code "exit code passthrough" 42 "$HAT" run smoke-vm -- sh -c 'exit 42'
    out=$(echo hello | "$HAT" run smoke-vm -- cat); [ "$out" = hello ] && ok "stdin pipe" || bad "stdin pipe: $out"
    out=$("$HAT" run smoke-vm -- sh -c 'echo "$TZ $LANG $(pwd)"'); [ "$out" = "Asia/Tokyo ja_JP.UTF-8 $WORK" ] && ok "TZ/LANG/cwd" || bad "TZ/LANG/cwd: $out"
    "$HAT" run smoke-vm -- sh -c 'echo from-vm > file-from-vm'; [ "$(cat file-from-vm 2>/dev/null)" = from-vm ] && ok "write to shared dir" || bad "write to shared dir"
    owner=$(stat -f %u file-from-vm 2>/dev/null); [ "$owner" = "$(id -u)" ] && ok "file owner is you ($owner)" || bad "file owner $owner"
    expect_code "unshared cwd refused" 125 sh -c "cd /tmp && '$HAT' run smoke-vm -- true"
    "$HAT" stop smoke-vm >/dev/null && ok "stop" || bad "stop"
    t0=$(now); out=$("$HAT" run smoke-vm -- hostname); [ "$out" = smoke-box ] && ok "restart + hostname ($(python3 -c "print(round($(now)-$t0))" 2>/dev/null)s)" || bad "restart: $out"
    pid=$("$HAT" status smoke-vm --json | python3 -c 'import json,sys; print(json.load(sys.stdin)["data"]["pid"])' 2>/dev/null)
    [ -n "$pid" ] && kill -9 "$pid"; sleep 1
    out=$("$HAT" run smoke-vm -- echo recovered 2>&1); [ "$out" = recovered ] && ok "recovery after daemon crash" || bad "recovery after daemon crash: $out"
  else
    bad "create vm profile"
  fi
fi

echo
echo "== summary: $PASS passed, $FAIL failed"
if [ "$FAIL" -gt 0 ]; then
  for p in smoke-vm smoke-lite; do "$HAT" debug-bundle "$p" 2>/dev/null; done
  echo "Please send the summary above and the hat-debug-*.tar.gz file(s) in $WORK"
  KEEP=1
fi
exit $([ "$FAIL" = 0 ] && echo 0 || echo 1)
