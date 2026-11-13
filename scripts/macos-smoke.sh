#!/bin/bash
# hat smoke test for macOS (Apple Silicon).
#
#   scripts/macos-smoke.sh 'socks5://user:pass@host:port' [--keep] [--lite-only]
#
# Environment:
#   HAT                path to the hat binary (default: hat on PATH, else dist/)
#   HAT_HOME           data directory to use (e.g. a throw-away one)
#   EXTRA_CREATE_ARGS  extra flags for `hat create`, e.g. --allow-local-upstream
#                      when the proxy runs on this Mac (Surge, Clash, ...)
#
# Creates two throw-away profiles (smoke-lite, smoke-vm), runs every check,
# prints PASS/FAIL per item and writes a debug bundle at the end. Send the
# printed summary and the bundle back if anything fails.
set -u
PROXY="${1:?usage: $0 PROXY_URL [--keep] [--lite-only]}"; shift
KEEP=0; LITE_ONLY=0
for a in "$@"; do case "$a" in --keep) KEEP=1;; --lite-only) LITE_ONLY=1;; esac; done

HAT="${HAT:-hat}"
read -r -a EXTRA <<<"${EXTRA_CREATE_ARGS:-}"
HAT_DATA="${HAT_HOME:-$HOME/.hat}"
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
if "$HAT" create smoke-lite --mode lite --proxy "$PROXY" --tz America/New_York --locale en_US.UTF-8 ${EXTRA[@]+"${EXTRA[@]}"} </dev/null >/dev/null; then
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
  out=$("$HAT" run smoke-lite -- cat "$HAT_DATA/profiles/smoke-lite/profile.toml" 2>&1); [ $? -ne 0 ] && ok "hat data dir unreadable from inside" || bad "hat data dir readable from inside the sandbox"
  out=$("$HAT" run smoke-lite -- /usr/bin/open https://example.com 2>&1); [ $? -ne 0 ] && ok "open (host browser) blocked" || bad "open launched the host browser"
else
  bad "create lite profile"
fi

if [ "$LITE_ONLY" = 0 ]; then
  echo "== vm mode"
  REAL="$(cd "$WORK" && pwd -P)"   # /private/tmp/... on macOS
  # A share nested in another one through an absolute symlink.
  mkdir -p "$WORK/nested-real" && ln -s "$REAL/nested-real" "$WORK/nested-link"
  if "$HAT" create smoke-vm --proxy "$PROXY" --tz Asia/Tokyo --locale ja_JP.UTF-8 --hostname smoke-box --share "$WORK" --share "$WORK/nested-link" ${EXTRA[@]+"${EXTRA[@]}"} </dev/null >/dev/null; then
    ok "create vm profile"
    t0=$(now); "$HAT" start smoke-vm && ok "first boot ($(python3 -c "print(round($(now)-$t0))" 2>/dev/null)s)" || bad "first boot (see: $HAT debug-bundle smoke-vm)"
    "$HAT" check smoke-vm && ok "hat check smoke-vm" || bad "hat check smoke-vm (see above)"
    t0=$(now); out=$("$HAT" run smoke-vm -- echo warm); [ "$out" = warm ] && ok "warm exec ($(python3 -c "print(round(($(now)-$t0)*1000))" 2>/dev/null) ms)" || bad "warm exec: $out"
    expect_code "exit code passthrough" 42 "$HAT" run smoke-vm -- sh -c 'exit 42'
    out=$(echo hello | "$HAT" run smoke-vm -- cat); [ "$out" = hello ] && ok "stdin pipe" || bad "stdin pipe: $out"
    GUEST_WORK="/mnt/host$REAL"   # outside the home directory: /mnt/host + real host path
    out=$("$HAT" run smoke-vm -- sh -c 'echo "$TZ $LANG $(pwd)"'); [ "$out" = "Asia/Tokyo ja_JP.UTF-8 $GUEST_WORK" ] && ok "TZ/LANG/cwd" || bad "TZ/LANG/cwd: $out"
    out=$("$HAT" run smoke-vm -- sh -c 'cat /var/lib/cloud/data/instance-id; env | grep -c "^HAT_"; grep -c /Users/ /proc/mounts; ls -d /Users /Volumes /private 2>/dev/null | wc -l | tr -d " "; awk "\$3==\"virtiofs\"{print \$1}" /proc/mounts | grep -c "^hat"; ls -d /var/lib/hat-* /etc/sysctl.d/*hat* /etc/ssh/sshd_config.d/*hat* 2>/dev/null | wc -l | tr -d " "' 2>&1)
    [ "$out" = "$(printf 'iid-local01\n0\n0\n0\n0\n0')" ] && ok "no hat traces in the guest" || bad "hat traces in the guest (instance-id, HAT_ env, /Users mounts, macOS dirs, hat tags, hat files): $(echo $out)"
    out=$(cd "$WORK/nested-link" && "$HAT" run smoke-vm -- pwd 2>&1); [ "$out" = "$GUEST_WORK/nested-real" ] && ok "share nested through an absolute symlink" || bad "nested symlink share: $out"
    if command -v git >/dev/null && "$HAT" run smoke-vm -- sh -c 'command -v git' >/dev/null 2>&1; then
      git -C "$WORK" init -q repo && git -C "$WORK/repo" -c user.name=s -c user.email=s@example.com commit -q --allow-empty -m init &&
        git -C "$WORK/repo" worktree add -q "$WORK/repo-wt" 2>/dev/null
      before=$(cat "$WORK/repo-wt/.git" 2>/dev/null)
      out=$(cd "$WORK/repo-wt" && "$HAT" run smoke-vm -- sh -c 'git status --short --branch >/dev/null && echo git-ok && grep -c /Users/ .git' 2>&1)
      [ "$out" = "$(printf 'git-ok\n0')" ] && ok "git worktree in the VM" || bad "git worktree in the VM: $(echo $out)"
      [ "$(cat "$WORK/repo-wt/.git" 2>/dev/null)" = "$before" ] && ok "worktree .git on the Mac unchanged" || bad "worktree .git on the Mac changed: $(cat "$WORK/repo-wt/.git")"
    else
      echo "  skip  git worktree (git missing on the Mac or in the VM)"
    fi
    "$HAT" run smoke-vm -- sh -c 'echo from-vm > file-from-vm'; [ "$(cat file-from-vm 2>/dev/null)" = from-vm ] && ok "write to shared dir" || bad "write to shared dir"
    owner=$(stat -f %u file-from-vm 2>/dev/null); [ "$owner" = "$(id -u)" ] && ok "file owner is you ($owner)" || bad "file owner $owner"
    expect_code "unshared cwd refused" 125 sh -c "cd / && '$HAT' run smoke-vm -- true"
    out=$(cd "$REAL" && env -u PWD "$HAT" run smoke-vm -- sh -c 'echo "$PWD"' 2>/dev/null)
    [ "$out" = "$GUEST_WORK" ] && ok "cwd via symlink alias ($REAL) maps to the share" || bad "cwd via symlink alias: got '$out', want '$GUEST_WORK'"
    "$HAT" stop smoke-vm >/dev/null && ok "stop" || bad "stop"
    t0=$(now); out=$("$HAT" run smoke-vm -- hostname); [ "$out" = smoke-box ] && ok "restart + hostname ($(python3 -c "print(round($(now)-$t0))" 2>/dev/null)s)" || bad "restart: $out"
    pid=$("$HAT" status smoke-vm --json | python3 -c 'import json,sys; print(json.load(sys.stdin)["data"]["pid"])' 2>/dev/null)
    [ -n "$pid" ] && kill -9 "$pid"; sleep 1
    t0=$(now); out=$("$HAT" run smoke-vm -- echo recovered 2>/tmp/hat-smoke.err); code=$?
    if [ "$code" = 0 ] && [ "$out" = recovered ]; then ok "recovery after daemon crash ($(python3 -c "print(round($(now)-$t0,1))" 2>/dev/null)s)"
    else bad "recovery after daemon crash: exit $code, stdout '$out', stderr: $(tail -2 /tmp/hat-smoke.err)"; fi
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
