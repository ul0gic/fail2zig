#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]:-$0}")" && pwd)"
REPO_ROOT="$(cd -- "${SCRIPT_DIR}/../.." && pwd)"

UNIT="fail2zig.service"
RUN_DIR="/run/fail2zig"
SOCK="${RUN_DIR}/fail2zig.sock"
CLIENT="/usr/local/bin/fail2zig"
GRP="fail2zig"
GRP_USER="f2z-e2e-grp"
TARGET="x86_64-linux-musl"

EXP_RUNDIR_OWNER="fail2zig:fail2zig"
EXP_RUNDIR_MODE="750"
EXP_SOCK_OWNER="fail2zig:fail2zig"
EXP_SOCK_MODE="660"

DO_BUILD=0
SKIP_INSTALL=0
LOCAL_BIN="zig-out/bin"
DO_PURGE=0
FORCE=0
CREATED_GROUP=0
CREATED_USER=0
HAD_SERVICE_USER=0
getent passwd fail2zig >/dev/null && HAD_SERVICE_USER=1
INSTALL_ATTEMPTED=0

log()  { printf 'e2e: %s\n' "$*" >&2; }
pass() { printf 'e2e: PASS  %s\n' "$*" >&2; }
fail() { printf 'e2e: FAIL  %s\n' "$*" >&2; dump_journal; exit 1; }

while [ $# -gt 0 ]; do
  case "$1" in
    --build)      DO_BUILD=1; shift ;;
    --local-bin)  [ $# -ge 2 ] || { echo "e2e: --local-bin needs arg" >&2; exit 2; }
                  LOCAL_BIN="$2"; shift 2 ;;
    --skip-install) SKIP_INSTALL=1; shift ;;
    --purge)      DO_PURGE=1; shift ;;
    --force)      FORCE=1; shift ;;
    -h|--help)    printf '%s\n' 'Usage: sudo tests/e2e/deploy_regression.sh [--build] [--local-bin DIR] [--skip-install] [--purge] [--force]'; exit 0 ;;
    *)            echo "e2e: unknown arg: $1" >&2; exit 2 ;;
  esac
done

[ "$(id -u)" -eq 0 ] || { echo "e2e: must run as root" >&2; exit 2; }
command -v systemctl >/dev/null 2>&1 || { echo "e2e: no systemctl — not a systemd host" >&2; exit 2; }
command -v runuser   >/dev/null 2>&1 || { echo "e2e: runuser required" >&2; exit 2; }
if ! systemctl is-system-running --quiet; then
  log "warning: system not fully running ($(systemctl is-system-running 2>/dev/null || true)) — proceeding"
fi

arch="$(uname -m)"
if [ "$arch" != "x86_64" ] && [ "$arch" != "amd64" ]; then
  echo "e2e: harness targets x86_64 (${TARGET}); host is $arch" >&2
  exit 2
fi

if systemctl is-active --quiet "$UNIT" && [ "$FORCE" -ne 1 ]; then
  echo "e2e: $UNIT already active — refusing to clobber (use --force)" >&2
  exit 2
fi

if ! getent group "$GRP" >/dev/null 2>&1; then
  CREATED_GROUP=1
fi

current_invocation() { systemctl show -p InvocationID --value "$UNIT" 2>/dev/null; }

dump_journal() {
  local inv
  inv="$(current_invocation)"
  if [ -n "$inv" ]; then
    log "----- journal for invocation $inv -----"
    journalctl _SYSTEMD_INVOCATION_ID="$inv" --no-pager 2>/dev/null | sed 's/^/e2e:   /' >&2 || true
  else
    log "(no current invocation to dump)"
  fi
}

cleanup() {
  set +e
  systemctl stop "$UNIT" >/dev/null 2>&1
  if [ "$CREATED_USER" -eq 1 ]; then
    userdel -r "$GRP_USER" >/dev/null 2>&1
  fi
  if [ "$DO_PURGE" -eq 1 ]; then
    systemctl disable "$UNIT" >/dev/null 2>&1
    rm -f /usr/local/bin/fail2zig /usr/local/bin/fail2zig-client
    rm -f /etc/systemd/system/fail2zig.service
    rm -rf /run/fail2zig /var/lib/fail2zig
    if [ "$INSTALL_ATTEMPTED" -eq 1 ] && [ "$HAD_SERVICE_USER" -eq 0 ] && getent passwd fail2zig >/dev/null; then
      userdel fail2zig >/dev/null 2>&1
    fi
    if [ "$CREATED_GROUP" -eq 1 ]; then
      groupdel "$GRP" >/dev/null 2>&1
    fi
    systemctl daemon-reload >/dev/null 2>&1
    log "purged installed artifacts"
  fi
}
trap cleanup EXIT

if [ "$DO_BUILD" -eq 1 ]; then
  command -v zig >/dev/null 2>&1 || { echo "e2e: --build needs zig on PATH" >&2; exit 2; }
  log "building ReleaseSafe ${TARGET}"
  ( cd "$REPO_ROOT" && zig build -Dtarget="$TARGET" -Doptimize=ReleaseSafe )
  LOCAL_BIN="${REPO_ROOT}/zig-out/bin"
fi
[ -x "${LOCAL_BIN}/fail2zig" ]        || { echo "e2e: missing ${LOCAL_BIN}/fail2zig" >&2; exit 2; }

if [ "$SKIP_INSTALL" -eq 0 ]; then
  log "installing via scripts/install.sh --local-bin ${LOCAL_BIN}"
  INSTALL_ATTEMPTED=1
  "${REPO_ROOT}/scripts/install.sh" --local-bin "$LOCAL_BIN"
else
  log "using the release gate's existing candidate installation"
fi

if ! cmp -s "${REPO_ROOT}/deploy/fail2zig.service" /etc/systemd/system/fail2zig.service; then
  fail "installed unit differs from deploy/fail2zig.service (drop-in or edit detected)"
fi
if [ -d "/etc/systemd/system/${UNIT}.d" ] && compgen -G "/etc/systemd/system/${UNIT}.d/*.conf" >/dev/null; then
  fail "drop-ins present under ${UNIT}.d — harness requires the unmodified unit"
fi
pass "installed; shipped unit verified byte-identical, no drop-ins"

systemctl daemon-reload
log "starting $UNIT (shipped unit, no overrides)"
systemctl start "$UNIT" || fail "systemctl start failed"

ready=0
for _ in $(seq 1 50); do
  if systemctl is-active --quiet "$UNIT" && "$CLIENT" status >/dev/null 2>&1; then
    ready=1
    break
  fi
  sleep 0.1
done

[ "$(systemctl is-active "$UNIT")" = "active" ] || fail "service not active"
NR="$(systemctl show -p NRestarts --value "$UNIT")"
[ "$NR" = "0" ] || fail "NRestarts=$NR (expected 0 — crash-loop signature of SYS-019)"
[ "$ready" -eq 1 ] || fail "service active but IPC never became ready"
pass "service active (running), NRestarts=0"

INV="$(current_invocation)"
[ -n "$INV" ] || fail "could not read InvocationID"
JSLICE="$(journalctl _SYSTEMD_INVOCATION_ID="$INV" --no-pager 2>/dev/null || true)"
if printf '%s\n' "$JSLICE" | grep -Eiq 'SIGSYS|seccomp|System Call|chown|operation not permitted'; then
  fail "forbidden journal markers in invocation $INV (SIGSYS/seccomp/chown)"
fi
pass "clean journal for invocation $INV (no SIGSYS/seccomp/chown)"

[ -d "$RUN_DIR" ] || fail "$RUN_DIR missing"
RD="$(stat -c '%U:%G %a' "$RUN_DIR")"
[ "$RD" = "${EXP_RUNDIR_OWNER} ${EXP_RUNDIR_MODE}" ] || \
  fail "$RUN_DIR is '$RD', expected '${EXP_RUNDIR_OWNER} ${EXP_RUNDIR_MODE}'"
pass "$RUN_DIR = $RD"

[ -S "$SOCK" ] || fail "socket $SOCK missing"
SS="$(stat -c '%U:%G %a' "$SOCK")"
[ "$SS" = "${EXP_SOCK_OWNER} ${EXP_SOCK_MODE}" ] || \
  fail "socket is '$SS', expected '${EXP_SOCK_OWNER} ${EXP_SOCK_MODE}'"
pass "socket = $SS"

"$CLIENT" status >/dev/null 2>&1 || fail "root: fail2zig status failed"
pass "root client connected"

if ! id "$GRP_USER" >/dev/null 2>&1; then
  useradd --system --no-create-home --shell /usr/sbin/nologin "$GRP_USER"
  CREATED_USER=1
fi
usermod -aG "$GRP" "$GRP_USER"
if ! runuser -u "$GRP_USER" -g "$GRP" -- "$CLIENT" status >/dev/null 2>&1; then
  fail "group user $GRP_USER (in $GRP) could not connect"
fi
pass "group user connected"

set +e
DENY_OUT="$(runuser -u nobody -- "$CLIENT" status 2>&1)"
DENY_RC=$?
set -e
[ "$DENY_RC" -ne 0 ] || fail "non-group user 'nobody' unexpectedly connected"
[ "$DENY_RC" -eq 3 ] || fail "non-group denial rc=$DENY_RC (expected 3)"
printf '%s' "$DENY_OUT" | grep -q "group '${GRP}' membership" || \
  fail "non-group denial lacked expected message; got: $DENY_OUT"
pass "non-group user denied (rc=3, group-membership message)"

log "ALL 7 ASSERTIONS PASSED"
exit 0
