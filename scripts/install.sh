#!/usr/bin/env bash

set -euo pipefail


REPO="${FAIL2ZIG_REPO:-ul0gic/fail2zig}"
VERSION="${FAIL2ZIG_VERSION:-latest}"
PREFIX="${FAIL2ZIG_PREFIX:-/usr/local}"
CONFIG_DIR="${FAIL2ZIG_CONFIG_DIR:-/etc/fail2zig}"
SYSTEMD_DIR="${FAIL2ZIG_SYSTEMD_DIR:-/etc/systemd/system}"
SYSTEM_GROUP="${FAIL2ZIG_GROUP:-fail2zig}"
SYSTEM_USER=fail2zig
STATE_DIR=/var/lib/fail2zig
STATE_FILE=${STATE_DIR}/state.bin
MAN_DIR="${FAIL2ZIG_MAN_DIR:-${PREFIX}/share/man}"
DOC_DIR="${FAIL2ZIG_DOC_DIR:-${PREFIX}/share/doc/fail2zig}"

DRY_RUN=0
LOCAL_BIN=""
SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]:-$0}")" && pwd)"
REPO_ROOT="$(cd -- "${SCRIPT_DIR}/.." && pwd)"

TMPDIR_BASE="${TMPDIR:-/tmp}"
WORKDIR=""


log()  { printf 'fail2zig: %s\n' "$*" >&2; }
die()  { printf 'fail2zig: error: %s\n' "$*" >&2; exit 1; }
run()  {
  if [ "${DRY_RUN}" -eq 1 ]; then
    printf 'fail2zig: DRY-RUN: %s\n' "$*" >&2
  else
    "$@"
  fi
}

cleanup() {
  if [ -n "${WORKDIR}" ] && [ -d "${WORKDIR}" ]; then
    rm -rf "${WORKDIR}"
  fi
}
trap cleanup EXIT

usage() {
  cat <<'USAGE'
Usage: install.sh [OPTIONS]

Options:
  --dry-run               Print every action without executing it.
  --local-bin <dir>       Install from a local directory containing a freshly
                          built `fail2zig` executable instead of downloading
                          a release.
  --version <tag>         Version tag to install (default: latest).
                          Equivalent to FAIL2ZIG_VERSION=<tag>.
  -h, --help              Show this help.

Environment overrides:
  FAIL2ZIG_VERSION        Release tag, e.g. v0.4.1 (default: latest).
  FAIL2ZIG_REPO           GitHub owner/repo (default: ul0gic/fail2zig).
  FAIL2ZIG_PREFIX         Install prefix (default: /usr/local).
  FAIL2ZIG_CONFIG_DIR     Config directory (default: /etc/fail2zig).
  FAIL2ZIG_SYSTEMD_DIR    systemd unit directory (default: /etc/systemd/system).
  FAIL2ZIG_GROUP          System group name (default: fail2zig).
  FAIL2ZIG_MAN_DIR        Man-page root (default: <prefix>/share/man).
  FAIL2ZIG_DOC_DIR        Notice directory (default: <prefix>/share/doc/fail2zig).
USAGE
}


while [ $# -gt 0 ]; do
  case "$1" in
    --dry-run)     DRY_RUN=1; shift ;;
    --local-bin)   [ $# -ge 2 ] || die "--local-bin requires an argument"
                   LOCAL_BIN="$2"; shift 2 ;;
    --version)     [ $# -ge 2 ] || die "--version requires an argument"
                   VERSION="$2"; shift 2 ;;
    -h|--help)     usage; exit 0 ;;
    *)             usage; die "unknown argument: $1" ;;
  esac
done


require_cmd() {
  command -v "$1" >/dev/null 2>&1 || die "missing required command: $1"
}

require_cmd uname
require_cmd install
require_cmd mktemp
require_cmd sha256sum

if [ -z "${LOCAL_BIN}" ]; then
  require_cmd curl
fi

if [ "${DRY_RUN}" -ne 1 ]; then
  if [ "${EUID:-$(id -u)}" -ne 0 ]; then
    die "must run as root (try: sudo $0 $*)"
  fi
fi


detect_target() {
  local arch endian
  arch="$(uname -m)"
  case "${arch}" in
    x86_64|amd64) echo "x86_64-linux-musl" ;;
    aarch64|arm64) echo "aarch64-linux-musl" ;;
    armv7l|armv8l) echo "arm-linux-musleabihf" ;;
    mips|mipsel)
      require_cmd od
      endian="$(od -An -tu1 -j5 -N1 /proc/self/exe)"
      case "${endian//[[:space:]]/}" in
        1) echo "mipsel-linux-musleabi" ;;
        2) echo "mips-linux-musleabi" ;;
        *) die "cannot determine MIPS ELF endianness" ;;
      esac ;;
    *)
      die "unsupported architecture: ${arch}"
      ;;
  esac
}

TARGET="$(detect_target)"
log "detected target: ${TARGET}"


resolve_version() {
  local v="$1"
  if [ "${v}" = "latest" ]; then
    log "resolving latest release from github.com/${REPO}..."
    local api="https://api.github.com/repos/${REPO}/releases/latest"
    local tag
    tag="$(curl -fsSL "${api}" | sed -n 's/.*"tag_name": *"\([^"]*\)".*/\1/p' | head -n1)"
    [ -n "${tag}" ] || die "could not resolve latest release tag (GitHub API returned no tag_name)"
    echo "${tag}"
  else
    case "${v}" in
      v*) echo "${v}" ;;
      *)  echo "v${v}" ;;
    esac
  fi
}

RESOLVED_TAG=""
if [ -z "${LOCAL_BIN}" ]; then
  RESOLVED_TAG="$(resolve_version "${VERSION}")"
  log "using release: ${RESOLVED_TAG}"
fi


WORKDIR="$(mktemp -d "${TMPDIR_BASE}/fail2zig-install.XXXXXX")"
log "staging in ${WORKDIR}"


stage_from_release() {
  local tag="$1"
  local base="https://github.com/${REPO}/releases/download/${tag}"
  local version="${tag#v}"

  local daemon_asset="fail2zig-v${version}-${TARGET}"
  local asset

  log "downloading SHA256SUMS"
  curl -fsSL --retry 3 -o "${WORKDIR}/SHA256SUMS" "${base}/SHA256SUMS"

  for asset in \
    "${daemon_asset}" \
    fail2zig.service \
    fail2zig.toml.example \
    fail2zig.1 \
    fail2zig.toml.5 \
    LICENSE \
    SQLITE-NOTICE.md \
    COPYING.date-profile
  do
    log "downloading ${asset}"
    curl -fsSL --retry 3 -o "${WORKDIR}/${asset}" "${base}/${asset}"
    verify_sha "${asset}"
  done

  echo "${daemon_asset}" > "${WORKDIR}/.daemon_name"
}

verify_sha() {
  local asset="$1"
  local expected
  expected="$(sed -n "s/^\\([0-9a-f]\\{64\\}\\)  \\(\\.\\/\\)\\{0,1\\}${asset}\$/\\1/p" "${WORKDIR}/SHA256SUMS" | head -n1)"
  [ -n "${expected}" ] || die "no SHA256 entry for ${asset} in SHA256SUMS"

  local actual
  actual="$(sha256sum "${WORKDIR}/${asset}" | awk '{print $1}')"
  if [ "${expected}" != "${actual}" ]; then
    die "SHA256 mismatch for ${asset}: expected=${expected} actual=${actual}"
  fi
  log "verified SHA256: ${asset}"
}

stage_from_local() {
  local dir="$1"
  [ -d "${dir}" ] || die "--local-bin directory does not exist: ${dir}"
  [ -x "${dir}/fail2zig" ] || die "missing executable: ${dir}/fail2zig"

  cp "${dir}/fail2zig" "${WORKDIR}/fail2zig"
  echo "fail2zig" > "${WORKDIR}/.daemon_name"

  local source_path
  local staged_name
  for source_path in \
    deploy/fail2zig.service \
    deploy/fail2zig.toml.example \
    docs/man/fail2zig.1 \
    docs/man/fail2zig.toml.5 \
    LICENSE \
    SQLITE-NOTICE.md \
    engine/compat/COPYING.date-profile
  do
    [ -f "${REPO_ROOT}/${source_path}" ] || die "missing ${source_path} in repo tree"
    staged_name="${source_path##*/}"
    cp "${REPO_ROOT}/${source_path}" "${WORKDIR}/${staged_name}"
  done

  log "staged executable from ${dir}"
}

if [ -n "${LOCAL_BIN}" ]; then
  stage_from_local "${LOCAL_BIN}"
else
  stage_from_release "${RESOLVED_TAG}"
fi

DAEMON_STAGED="${WORKDIR}/$(cat "${WORKDIR}/.daemon_name")"


# Only these native SQLite paths are an automatic ownership transition. Stop all
# writers for the whole install; the installer never stops or starts a service.
[[ "$SYSTEM_GROUP" =~ ^[a-z_][a-z0-9_-]*$ ]] || die "invalid system group name"
for path in "$PREFIX" "$CONFIG_DIR" "$SYSTEMD_DIR" "$MAN_DIR" "$DOC_DIR"; do
  [[ "$path" =~ ^/[a-zA-Z0-9_./-]+$ ]] || die "install paths must be absolute and contain only letters, digits, /, _, . or -"
done
for cmd in getent stat readlink od awk; do require_cmd "$cmd"; done

check_stopped() {
  local proc fd target comm state_path
  for proc in /proc/[0-9]*; do
    [ -d "$proc" ] || continue
    [ "${proc##*/}" != "$$" ] || continue
    comm="$(cat "$proc/comm" 2>/dev/null || :)"
    [ "$comm" != fail2zig ] || die "stop every fail2zig daemon before installing (active PID ${proc##*/})"
    for fd in "$proc"/fd/*; do
      for state_path in "$STATE_FILE" "$STATE_FILE-wal" "$STATE_FILE-shm"; do
        if [ -e "$state_path" ] && [[ "$fd" -ef "$state_path" ]]; then
          die "state inode is open by PID ${proc##*/}; stop every writer before installing"
        fi
      done
      target="$(readlink "$fd" 2>/dev/null || :)"
      case "$target" in
        "$STATE_FILE"|"$STATE_FILE-wal"|"$STATE_FILE-shm")
          die "state is open by PID ${proc##*/}; stop every writer before installing" ;;
      esac
    done
  done
}

check_state() {
  local path owner mode
  for path in /var /var/lib "$STATE_DIR"; do
    [ ! -L "$path" ] || die "refusing symlink state parent: $path"
    [ -e "$path" ] || continue
    [ -d "$path" ] || die "state parent is not a directory: $path"
    owner="$(stat -c %u "$path")"
    if [ "$path" = "$STATE_DIR" ]; then
      [ "$owner" = 0 ] || [ "$owner" = "$SERVICE_UID" ] || die "unexpected state directory owner: $path"
    else
      [ "$owner" = 0 ] || die "state ancestor must be root-owned: $path"
    fi
    mode="$(stat -c %a "$path")"
    (( (8#$mode & 0022) == 0 )) || die "state parent is group/world writable: $path"
  done
  for path in "$STATE_FILE" "$STATE_FILE-wal" "$STATE_FILE-shm"; do
    [ ! -L "$path" ] || die "refusing symlink state file: $path"
    [ -e "$path" ] || continue
    [ -f "$path" ] && [ "$(stat -c %h "$path")" = 1 ] || die "state must be a regular file with one link: $path"
    owner="$(stat -c %u "$path")"
    [ "$owner" = 0 ] || [ "$owner" = "$SERVICE_UID" ] || die "unexpected state file owner: $path"
  done
  if [ -f "$STATE_FILE" ]; then
    [ "$(od -An -tx1 -N16 "$STATE_FILE" | tr -d ' \n')" = 53514c69746520666f726d6174203300 ] ||
      die "state.bin is not native SQLite; legacy v0.3.0 state cannot be converted by this installer. Preserve it and select a new native database explicitly."
  elif [ -e "$STATE_FILE-wal" ] || [ -e "$STATE_FILE-shm" ]; then
    die "orphan SQLite sidecar; restore the complete database before installing"
  fi
}

SERVICE_UID="$(id -u "$SYSTEM_USER" 2>/dev/null || :)"
if [ -f "$CONFIG_DIR/config.toml" ]; then
  [ ! -L "$CONFIG_DIR/config.toml" ] || die "refusing symlink configuration"
  # Conservative recognition, not a second TOML parser: unusual spelling needs
  # explicit operator review, as do all custom state paths.
  awk '
    /^[[:space:]]*#/ { next }
    /state_file/ && $0 !~ /^[[:space:]]*state_file[[:space:]]*=[[:space:]]*"\/var\/lib\/fail2zig\/state.bin"[[:space:]]*(#.*)?$/ { exit 1 }
  ' "$CONFIG_DIR/config.toml" || die "custom/unrecognized state_file: stop all writers, back up state, and explicitly chown only its verified parent/database/-wal/-shm to fail2zig:$SYSTEM_GROUP; use a matching systemd ReadWritePaths override. Automatic custom-path upgrades are refused."
fi
if [ "$DRY_RUN" -ne 1 ]; then check_stopped; fi
check_state
# File.tryLock(.exclusive) uses flock on Linux. Hold the same lock until exit,
# including across bind-mount aliases, while changing owner and installing files.
if [ "$DRY_RUN" -ne 1 ] && [ -f "$STATE_FILE" ]; then
  require_cmd flock
  exec 9<> "$STATE_FILE"
  flock --exclusive --nonblock 9 || die "native state authority is still running; stop it before upgrading"
fi

if getent group "${SYSTEM_GROUP}" >/dev/null 2>&1; then
  log "group ${SYSTEM_GROUP} already exists"
else
  log "creating system group ${SYSTEM_GROUP}"
  run groupadd --system "${SYSTEM_GROUP}"
fi


if getent passwd "$SYSTEM_USER" >/dev/null; then
  IFS=: read -r _ _ account_uid account_gid _ account_home account_shell < <(getent passwd "$SYSTEM_USER")
  [ "$account_uid" -ne 0 ] && [ "$account_gid" = "$(getent group "$SYSTEM_GROUP" | cut -d: -f3)" ] || die "existing fail2zig account must be non-root with primary group $SYSTEM_GROUP"
  case "$account_shell" in /usr/sbin/nologin|/sbin/nologin|/bin/false) ;; *) die "existing fail2zig account must have a non-login shell" ;; esac
  [ "$account_home" = /nonexistent ] || die "existing fail2zig account must have home /nonexistent"
else
  if [ "$DRY_RUN" -ne 1 ]; then require_cmd useradd; fi
  run useradd --system --gid "$SYSTEM_GROUP" --home-dir /nonexistent --no-create-home --shell /usr/sbin/nologin "$SYSTEM_USER"
fi

if [ "$DRY_RUN" -ne 1 ]; then
  SERVICE_UID="$(id -u "$SYSTEM_USER")"
  check_stopped
  check_state
fi
run install -d -o "$SYSTEM_USER" -g "$SYSTEM_GROUP" -m 0750 "$STATE_DIR"
for path in "$STATE_FILE" "$STATE_FILE-wal" "$STATE_FILE-shm"; do
  if [ -e "$path" ]; then
    run chown --no-dereference "$SYSTEM_USER:$SYSTEM_GROUP" "$path"
    run chmod 0600 "$path"
  fi
done


log "installing executable to ${PREFIX}/bin"
run install -d -o root -g root -m 0755 "${PREFIX}/bin"
run install -o root -g root -m 0755 "${DAEMON_STAGED}" "${PREFIX}/bin/fail2zig"
if [ -e "${PREFIX}/bin/fail2zig-client" ]; then
  log "removing the retired ${PREFIX}/bin/fail2zig-client (one executable now serves every command)"
  run rm -f "${PREFIX}/bin/fail2zig-client"
fi


log "ensuring ${CONFIG_DIR} exists"
run install -d -o root -g "${SYSTEM_GROUP}" -m 0750 "${CONFIG_DIR}"

if [ -f "${WORKDIR}/fail2zig.toml.example" ]; then
  run install -o root -g "${SYSTEM_GROUP}" -m 0640 \
    "${WORKDIR}/fail2zig.toml.example" "${CONFIG_DIR}/fail2zig.toml.example"

  if [ -f "${CONFIG_DIR}/config.toml" ]; then
    log "existing ${CONFIG_DIR}/config.toml bytes preserved; set administrator-owned service-readable permissions"
    run chown root:"$SYSTEM_GROUP" "${CONFIG_DIR}/config.toml"
    run chmod 0640 "${CONFIG_DIR}/config.toml"
  else
    log "seeding ${CONFIG_DIR}/config.toml from example"
    run install -o root -g "${SYSTEM_GROUP}" -m 0640 \
      "${WORKDIR}/fail2zig.toml.example" "${CONFIG_DIR}/config.toml"
  fi
fi


log "installing man pages under ${MAN_DIR}"
run install -d -o root -g root -m 0755 "${MAN_DIR}/man1" "${MAN_DIR}/man5"
run install -o root -g root -m 0644 "${WORKDIR}/fail2zig.1" "${MAN_DIR}/man1/fail2zig.1"
run install -o root -g root -m 0644 "${WORKDIR}/fail2zig.toml.5" "${MAN_DIR}/man5/fail2zig.toml.5"

log "installing license and dependency notices under ${DOC_DIR}"
run install -d -o root -g root -m 0755 "${DOC_DIR}"
run install -o root -g root -m 0644 "${WORKDIR}/LICENSE" "${DOC_DIR}/LICENSE"
run install -o root -g root -m 0644 "${WORKDIR}/SQLITE-NOTICE.md" "${DOC_DIR}/SQLITE-NOTICE.md"
run install -o root -g root -m 0644 "${WORKDIR}/COPYING.date-profile" "${DOC_DIR}/COPYING.date-profile"


log "installing ${SYSTEMD_DIR}/fail2zig.service"
sed -e "s|^Group=.*|Group=${SYSTEM_GROUP}|" \
    -e "s|^ExecStart=.*|ExecStart=${PREFIX}/bin/fail2zig --config ${CONFIG_DIR}/config.toml|" \
    "${WORKDIR}/fail2zig.service" > "${WORKDIR}/fail2zig.service.rendered"
run install -d -o root -g root -m 0755 "$SYSTEMD_DIR"
run install -o root -g root -m 0644 "${WORKDIR}/fail2zig.service.rendered" "${SYSTEMD_DIR}/fail2zig.service"

if command -v systemctl >/dev/null 2>&1; then
  log "reloading systemd"
  run systemctl daemon-reload
else
  log "systemctl not found — skipping daemon-reload"
fi


cat <<SUMMARY

----------------------------------------------------------------------
fail2zig installed successfully.
----------------------------------------------------------------------

  Executable:   ${PREFIX}/bin/fail2zig
  Config dir:   ${CONFIG_DIR}
  Unit file:    ${SYSTEMD_DIR}/fail2zig.service
  Man pages:    ${MAN_DIR}/man1/fail2zig.1, ${MAN_DIR}/man5/fail2zig.toml.5
  Notices:      ${DOC_DIR}

The service runs as fail2zig:${SYSTEM_GROUP}. No service was started or enabled.
For future upgrades: stop fail2zig and every foreground writer, back up the complete
native SQLite state, run this installer, then start after reviewing configuration.
Only default native SQLite paths receive automatic ownership changes.

Next steps (review the config before starting the daemon):

  sudo "\${EDITOR:-vi}" ${CONFIG_DIR}/config.toml
  sudo systemctl enable --now fail2zig
  sudo systemctl status fail2zig

Verify the daemon sees your jails:

  sudo fail2zig status
  sudo fail2zig list

Documentation: https://github.com/${REPO}
----------------------------------------------------------------------
SUMMARY
