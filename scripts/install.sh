#!/usr/bin/env bash
#
# scripts/install.sh — fail2zig one-shot installer.
#
# Designed for:
#   curl -fsSL https://fail2zig.io/install | sudo sh
#
# Also usable directly from a git checkout:
#   sudo scripts/install.sh
#   sudo scripts/install.sh --dry-run
#   sudo scripts/install.sh --local-bin zig-out/bin   # use pre-built binaries
#
# What it does (in order):
#   1. Detect host architecture, map to a supported release target.
#   2. Resolve the version (default: latest GitHub release; override with
#      FAIL2ZIG_VERSION=v0.1.0).
#   3. Download fail2zig + fail2zig-client + SHA256SUMS + systemd unit from
#      that release's asset tree (skipped if --local-bin is supplied).
#   4. Verify SHA256 of each binary against SHA256SUMS. Abort on mismatch.
#   5. Create the `fail2zig` system group if missing.
#   6. Install binaries to /usr/local/bin (mode 0755, root:root).
#   7. Create /etc/fail2zig (mode 0750) and copy the example config if the
#      target config does not already exist. Never clobber operator state.
#   8. Install /etc/systemd/system/fail2zig.service and run `daemon-reload`.
#   9. Print a clear summary. Do NOT auto-enable or start — operators
#      should audit the config first.
#
# Exit code: 0 on success, non-zero on any failure. Every error surfaces
# with a `fail2zig:` prefix so callers grepping logs can find them.
#
# Supported architectures (v0.1.0): x86_64, aarch64.
# 32-bit ARM and MIPS are tracked in SYS-009 and gated on the fix.

set -euo pipefail

# --- configuration knobs ------------------------------------------------------

REPO="${FAIL2ZIG_REPO:-ul0gic/fail2zig}"
VERSION="${FAIL2ZIG_VERSION:-latest}"
PREFIX="${FAIL2ZIG_PREFIX:-/usr/local}"
CONFIG_DIR="${FAIL2ZIG_CONFIG_DIR:-/etc/fail2zig}"
SYSTEMD_DIR="${FAIL2ZIG_SYSTEMD_DIR:-/etc/systemd/system}"
SYSTEM_GROUP="${FAIL2ZIG_GROUP:-fail2zig}"

DRY_RUN=0
LOCAL_BIN=""
# Script dir is used for --local-bin (to find example config / unit).
SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]:-$0}")" && pwd)"
REPO_ROOT="$(cd -- "${SCRIPT_DIR}/.." && pwd)"

TMPDIR_BASE="${TMPDIR:-/tmp}"
WORKDIR=""

# --- small helpers ------------------------------------------------------------

log()  { printf 'fail2zig: %s\n' "$*" >&2; }
die()  { printf 'fail2zig: error: %s\n' "$*" >&2; exit 1; }
run()  {
  # run <cmd...> — executes or prints, depending on DRY_RUN.
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
  --local-bin <dir>       Install from a local directory containing freshly
                          built `fail2zig` and `fail2zig-client` binaries
                          instead of downloading a release.
  --version <tag>         Version tag to install (default: latest).
                          Equivalent to FAIL2ZIG_VERSION=<tag>.
  -h, --help              Show this help.

Environment overrides:
  FAIL2ZIG_VERSION        Release tag, e.g. v0.1.0 (default: latest).
  FAIL2ZIG_REPO           GitHub owner/repo (default: ul0gic/fail2zig).
  FAIL2ZIG_PREFIX         Install prefix (default: /usr/local).
  FAIL2ZIG_CONFIG_DIR     Config directory (default: /etc/fail2zig).
  FAIL2ZIG_SYSTEMD_DIR    systemd unit directory (default: /etc/systemd/system).
  FAIL2ZIG_GROUP          System group name (default: fail2zig).
USAGE
}

# --- argument parsing ---------------------------------------------------------

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

# --- preflight ----------------------------------------------------------------

require_cmd() {
  command -v "$1" >/dev/null 2>&1 || die "missing required command: $1"
}

require_cmd uname
require_cmd install
require_cmd mktemp
require_cmd sha256sum

# Downloading path needs curl + tooling; skipped for --local-bin.
if [ -z "${LOCAL_BIN}" ]; then
  require_cmd curl
  # `sed` is in POSIX base on every distro we care about; no explicit check.
fi

# Running as root is required to write /usr/local/bin, /etc, and
# /etc/systemd/system. Allow dry-run without root so operators can audit.
if [ "${DRY_RUN}" -ne 1 ]; then
  if [ "${EUID:-$(id -u)}" -ne 0 ]; then
    die "must run as root (try: sudo $0 $*)"
  fi
fi

# --- architecture detection ---------------------------------------------------

detect_target() {
  local arch
  arch="$(uname -m)"
  case "${arch}" in
    x86_64|amd64)       echo "x86_64-linux-musl" ;;
    aarch64|arm64)      echo "aarch64-linux-musl" ;;
    armv7l|armv7|armhf)
      die "armv7 (${arch}) is not yet supported by fail2zig — see SYS-009. Build from source or wait for v0.2.x."
      ;;
    mips|mipsel|mips64|mips64el)
      die "mips (${arch}) is not yet supported by fail2zig — see SYS-009."
      ;;
    *)
      die "unsupported architecture: ${arch}"
      ;;
  esac
}

TARGET="$(detect_target)"
log "detected target: ${TARGET}"

# --- version resolution -------------------------------------------------------

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
    # Accept either "v0.1.0" or "0.1.0" and normalise.
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

# --- staging workspace --------------------------------------------------------

WORKDIR="$(mktemp -d "${TMPDIR_BASE}/fail2zig-install.XXXXXX")"
log "staging in ${WORKDIR}"

# --- download or collect binaries + SHA manifest ------------------------------

stage_from_release() {
  local tag="$1"
  local base="https://github.com/${REPO}/releases/download/${tag}"
  local version="${tag#v}"

  local daemon_asset="fail2zig-v${version}-${TARGET}"
  local client_asset="fail2zig-client-v${version}-${TARGET}"

  log "downloading ${daemon_asset}"
  curl -fsSL --retry 3 -o "${WORKDIR}/${daemon_asset}" "${base}/${daemon_asset}"
  log "downloading ${client_asset}"
  curl -fsSL --retry 3 -o "${WORKDIR}/${client_asset}" "${base}/${client_asset}"
  log "downloading SHA256SUMS"
  curl -fsSL --retry 3 -o "${WORKDIR}/SHA256SUMS" "${base}/SHA256SUMS"
  log "downloading fail2zig.service"
  curl -fsSL --retry 3 -o "${WORKDIR}/fail2zig.service" "${base}/fail2zig.service"
  # Example config is optional — tolerate 404 so old releases still install.
  if curl -fsSL --retry 2 -o "${WORKDIR}/fail2zig.toml.example" "${base}/fail2zig.toml.example"; then
    log "downloaded fail2zig.toml.example"
  else
    log "no fail2zig.toml.example in release; skipping example config"
    rm -f "${WORKDIR}/fail2zig.toml.example"
  fi

  # SHA256 verification — only for binaries we intend to install as root.
  verify_sha "${daemon_asset}"
  verify_sha "${client_asset}"

  echo "${daemon_asset}" > "${WORKDIR}/.daemon_name"
  echo "${client_asset}" > "${WORKDIR}/.client_name"
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
  [ -x "${dir}/fail2zig-client" ] || die "missing executable: ${dir}/fail2zig-client"

  cp "${dir}/fail2zig"        "${WORKDIR}/fail2zig"
  cp "${dir}/fail2zig-client" "${WORKDIR}/fail2zig-client"
  echo "fail2zig"        > "${WORKDIR}/.daemon_name"
  echo "fail2zig-client" > "${WORKDIR}/.client_name"

  # Pick up the systemd unit + example config from the repo tree.
  if [ -f "${REPO_ROOT}/deploy/fail2zig.service" ]; then
    cp "${REPO_ROOT}/deploy/fail2zig.service" "${WORKDIR}/fail2zig.service"
  else
    die "missing deploy/fail2zig.service in repo tree"
  fi
  if [ -f "${REPO_ROOT}/deploy/fail2zig.toml.example" ]; then
    cp "${REPO_ROOT}/deploy/fail2zig.toml.example" "${WORKDIR}/fail2zig.toml.example"
  fi

  log "staged binaries from ${dir}"
}

if [ -n "${LOCAL_BIN}" ]; then
  stage_from_local "${LOCAL_BIN}"
else
  stage_from_release "${RESOLVED_TAG}"
fi

DAEMON_STAGED="${WORKDIR}/$(cat "${WORKDIR}/.daemon_name")"
CLIENT_STAGED="${WORKDIR}/$(cat "${WORKDIR}/.client_name")"

# --- system group -------------------------------------------------------------

if getent group "${SYSTEM_GROUP}" >/dev/null 2>&1; then
  log "group ${SYSTEM_GROUP} already exists"
else
  log "creating system group ${SYSTEM_GROUP}"
  run groupadd --system "${SYSTEM_GROUP}"
fi

# --- install binaries ---------------------------------------------------------

log "installing binaries to ${PREFIX}/bin"
run install -d -o root -g root -m 0755 "${PREFIX}/bin"
run install -o root -g root -m 0755 "${DAEMON_STAGED}" "${PREFIX}/bin/fail2zig"
run install -o root -g root -m 0755 "${CLIENT_STAGED}" "${PREFIX}/bin/fail2zig-client"

# --- config directory ---------------------------------------------------------

log "ensuring ${CONFIG_DIR} exists"
run install -d -o root -g "${SYSTEM_GROUP}" -m 0750 "${CONFIG_DIR}"

if [ -f "${WORKDIR}/fail2zig.toml.example" ]; then
  # Always keep a pristine example alongside operator config for reference.
  run install -o root -g "${SYSTEM_GROUP}" -m 0640 \
    "${WORKDIR}/fail2zig.toml.example" "${CONFIG_DIR}/fail2zig.toml.example"

  if [ -f "${CONFIG_DIR}/config.toml" ]; then
    log "existing ${CONFIG_DIR}/config.toml preserved (no overwrite)"
  else
    log "seeding ${CONFIG_DIR}/config.toml from example"
    run install -o root -g "${SYSTEM_GROUP}" -m 0640 \
      "${WORKDIR}/fail2zig.toml.example" "${CONFIG_DIR}/config.toml"
  fi
fi

# --- systemd unit -------------------------------------------------------------

log "installing ${SYSTEMD_DIR}/fail2zig.service"
run install -o root -g root -m 0644 "${WORKDIR}/fail2zig.service" "${SYSTEMD_DIR}/fail2zig.service"

if command -v systemctl >/dev/null 2>&1; then
  log "reloading systemd"
  run systemctl daemon-reload
else
  log "systemctl not found — skipping daemon-reload"
fi

# --- summary ------------------------------------------------------------------

cat <<SUMMARY

----------------------------------------------------------------------
fail2zig installed successfully.
----------------------------------------------------------------------

  Binaries:     ${PREFIX}/bin/fail2zig
                ${PREFIX}/bin/fail2zig-client
  Config dir:   ${CONFIG_DIR}
  Unit file:    ${SYSTEMD_DIR}/fail2zig.service

Next steps (review the config before starting the daemon):

  sudo "\${EDITOR:-vi}" ${CONFIG_DIR}/config.toml
  sudo systemctl enable --now fail2zig
  sudo systemctl status fail2zig

Verify the daemon sees your jails:

  sudo fail2zig-client status
  sudo fail2zig-client list

Documentation: https://github.com/${REPO}
----------------------------------------------------------------------
SUMMARY
