#!/bin/sh
# Installs the standalone tdxguard executable (no Python needed) on macOS and Linux.
#
#   curl -fsSL https://raw.githubusercontent.com/tda-corp/tdx-guard-ci/main/install.sh | sh
#
# Environment:
#   TDXGUARD_VERSION      the version to install, e.g. 0.2.0 (default: the latest cli-v* release)
#   TDXGUARD_INSTALL_DIR  where the executable goes (default: ~/.local/bin)
#   GITHUB_TOKEN          optional; raises the GitHub API rate limit when resolving the version
#
# The download is verified against the release's checksums.txt (sha256) and refused when it
# does not match. Nothing needs root.
#
# Testing only: TDXGUARD_DOWNLOAD_BASE (instead of the GitHub release download URL),
# TDXGUARD_API_BASE (instead of https://api.github.com), TDXGUARD_UNAME_S and
# TDXGUARD_UNAME_M (instead of `uname -s` and `uname -m`).

set -eu

REPOSITORY="tda-corp/tdx-guard-ci"
API_BASE="${TDXGUARD_API_BASE:-https://api.github.com}"
DOWNLOAD_BASE="${TDXGUARD_DOWNLOAD_BASE:-https://github.com/${REPOSITORY}/releases/download}"
MIN_GLIBC="2.28"

say() {
  printf '%s\n' "$*"
}

fail() {
  printf 'tdxguard install: %s\n' "$1" >&2
  shift
  for line in "$@"; do
    printf '  %s\n' "$line" >&2
  done
  exit 1
}

# --- platform ---

# Prints <os>-<arch> as in the asset names, or fails with a message for unsupported ones.
detect_platform() {
  system="${TDXGUARD_UNAME_S:-$(uname -s)}"
  machine="${TDXGUARD_UNAME_M:-$(uname -m)}"
  case "$system" in
    Darwin)
      os=darwin
      # A shell running under Rosetta reports x86_64 on Apple Silicon; the native build
      # is the right one there.
      if [ "$machine" = "x86_64" ] && [ -z "${TDXGUARD_UNAME_M:-}" ] &&
        [ "$(sysctl -n sysctl.proc_translated 2>/dev/null || echo 0)" = "1" ]; then
        machine=arm64
      fi
      ;;
    Linux)
      os=linux
      check_libc
      ;;
    MINGW* | MSYS* | CYGWIN* | Windows_NT)
      fail "this is the installer for macOS and Linux." \
        "On Windows, run in PowerShell:" \
        "  irm https://raw.githubusercontent.com/${REPOSITORY}/main/install.ps1 | iex"
      ;;
    *)
      fail "no tdxguard executable for ${system} ${machine}." \
        "Install it with Python 3.9+ instead: pipx install \"git+https://github.com/${REPOSITORY}#subdirectory=cli\""
      ;;
  esac
  case "$machine" in
    x86_64 | amd64) arch=x86_64 ;;
    arm64 | aarch64 | armv8* | arm64e) arch=arm64 ;;
    *)
      fail "no tdxguard executable for ${system} ${machine} (only x86_64 and arm64)." \
        "Install it with Python 3.9+ instead: pipx install \"git+https://github.com/${REPOSITORY}#subdirectory=cli\""
      ;;
  esac
  printf '%s-%s\n' "$os" "$arch"
}

# The Linux executable is linked against glibc 2.28; musl (Alpine) cannot run it.
check_libc() {
  [ -n "${TDXGUARD_UNAME_S:-}" ] && return 0
  if ls /lib/ld-musl-* >/dev/null 2>&1 || (ldd --version 2>&1 | grep -qi musl); then
    fail "this Linux uses the musl C library (Alpine?); the tdxguard executable needs glibc ${MIN_GLIBC} or newer." \
      "Install it with Python 3.9+ instead: pipx install \"git+https://github.com/${REPOSITORY}#subdirectory=cli\"" \
      "or run the scanners in Docker: tdxguard scan --engine docker"
  fi
  glibc=$(getconf GNU_LIBC_VERSION 2>/dev/null | awk '{print $2}') || glibc=""
  if [ -n "$glibc" ] && ! version_at_least "$glibc" "$MIN_GLIBC"; then
    fail "this Linux has glibc ${glibc}; the tdxguard executable needs ${MIN_GLIBC} or newer." \
      "Install it with Python 3.9+ instead: pipx install \"git+https://github.com/${REPOSITORY}#subdirectory=cli\""
  fi
}

# version_at_least 2.31 2.28 -> true
version_at_least() {
  have_major=${1%%.*}
  have_minor=${1#*.}
  have_minor=${have_minor%%.*}
  need_major=${2%%.*}
  need_minor=${2#*.}
  [ "$have_major" -gt "$need_major" ] || { [ "$have_major" -eq "$need_major" ] && [ "$have_minor" -ge "$need_minor" ]; }
}

# --- downloads ---

downloader() {
  if command -v curl >/dev/null 2>&1; then
    echo curl
  elif command -v wget >/dev/null 2>&1; then
    echo wget
  else
    fail "neither curl nor wget is installed; install one of them and run this again."
  fi
}

# fetch <url> <file>
fetch() {
  case "$DOWNLOADER" in
    curl)
      case "$1" in
        https://*) curl -fsSL --retry 3 --proto '=https' --tlsv1.2 -o "$2" "$1" ;;
        *) curl -fsSL --retry 3 -o "$2" "$1" ;;
      esac
      ;;
    wget) wget -q -O "$2" "$1" ;;
  esac
}

# fetch_api <url> <file>: the same with GitHub API headers.
fetch_api() {
  case "$DOWNLOADER" in
    curl)
      if [ -n "${GITHUB_TOKEN:-}" ]; then
        curl -fsSL --retry 3 -H "Accept: application/vnd.github+json" -H "Authorization: Bearer ${GITHUB_TOKEN}" -o "$2" "$1"
      else
        curl -fsSL --retry 3 -H "Accept: application/vnd.github+json" -o "$2" "$1"
      fi
      ;;
    wget)
      if [ -n "${GITHUB_TOKEN:-}" ]; then
        wget -q --header "Accept: application/vnd.github+json" --header "Authorization: Bearer ${GITHUB_TOKEN}" -O "$2" "$1"
      else
        wget -q --header "Accept: application/vnd.github+json" -O "$2" "$1"
      fi
      ;;
  esac
}

# The newest published release whose tag starts with cli-v, from a GitHub releases JSON
# list (newest first; drafts are not visible without a token). Prereleases are skipped.
latest_cli_tag() {
  tr ',' '\n' <"$1" | awk '
    /"tag_name"[ ]*:/ {
      tag = $0
      sub(/^.*"tag_name"[ ]*:[ ]*"/, "", tag)
      sub(/".*$/, "", tag)
    }
    /"prerelease"[ ]*:[ ]*false/ {
      if (tag ~ /^cli-v[0-9]/) { print tag; exit }
    }
  '
}

sha256_of() {
  if command -v sha256sum >/dev/null 2>&1; then
    sha256sum "$1" | awk '{print $1}'
  elif command -v shasum >/dev/null 2>&1; then
    shasum -a 256 "$1" | awk '{print $1}'
  elif command -v openssl >/dev/null 2>&1; then
    openssl dgst -sha256 "$1" | awk '{print $NF}'
  else
    fail "no sha256 tool (sha256sum, shasum or openssl) to verify the download; install one and run this again."
  fi
}

# expected_checksum <checksums.txt> <asset>: the sha256 listed for the asset, or nothing.
expected_checksum() {
  awk -v name="$2" '$2 == name || $2 == "*" name { print tolower($1); exit }' "$1"
}

# --- install ---

main() {
  platform=$(detect_platform)
  DOWNLOADER=$(downloader)
  workdir=$(mktemp -d 2>/dev/null || mktemp -d -t tdxguard)
  trap 'rm -rf "$workdir"' EXIT
  trap 'exit 130' INT TERM

  version="${TDXGUARD_VERSION:-}"
  version=${version#cli-v}
  version=${version#v}
  if [ -z "$version" ]; then
    url="${API_BASE}/repos/${REPOSITORY}/releases?per_page=100"
    fetch_api "$url" "$workdir/releases.json" ||
      fail "cannot list the releases of ${REPOSITORY} (${url})." \
        "Check the network, or set TDXGUARD_VERSION to the version you want."
    tag=$(latest_cli_tag "$workdir/releases.json")
    [ -n "$tag" ] || fail "${REPOSITORY} has no cli-v* release yet." "Set TDXGUARD_VERSION, or install with pipx."
    version=${tag#cli-v}
  fi
  case "$version" in
    *[!0-9A-Za-z.+-]*) fail "not a version: ${version}" ;;
  esac
  tag="cli-v${version}"
  asset="tdxguard-${version}-${platform}"
  install_dir="${TDXGUARD_INSTALL_DIR:-${HOME}/.local/bin}"
  target="${install_dir}/tdxguard"

  say "Installing tdxguard ${version} (${platform}) into ${install_dir}"
  fetch "${DOWNLOAD_BASE}/${tag}/checksums.txt" "$workdir/checksums.txt" ||
    fail "cannot download ${DOWNLOAD_BASE}/${tag}/checksums.txt." \
      "Does release ${tag} exist? See https://github.com/${REPOSITORY}/releases"
  expected=$(expected_checksum "$workdir/checksums.txt" "$asset")
  [ -n "$expected" ] || fail "release ${tag} has no ${asset} (not in its checksums.txt)."
  fetch "${DOWNLOAD_BASE}/${tag}/${asset}" "$workdir/$asset" ||
    fail "cannot download ${DOWNLOAD_BASE}/${tag}/${asset}."
  actual=$(sha256_of "$workdir/$asset")
  if [ "$actual" != "$expected" ]; then
    fail "checksum mismatch for ${asset}: expected sha256 ${expected}, got ${actual}." \
      "The download was corrupted or tampered with; nothing was installed."
  fi
  say "  sha256 verified: ${actual}"

  mkdir -p "$install_dir" || fail "cannot create ${install_dir}." "Set TDXGUARD_INSTALL_DIR to a directory you can write."
  chmod 755 "$workdir/$asset"
  if [ "$os_is_darwin" = 1 ] && command -v xattr >/dev/null 2>&1; then
    xattr -d com.apple.quarantine "$workdir/$asset" 2>/dev/null || true
  fi
  # Copy next to the target and rename, so a running tdxguard is never half overwritten.
  cp "$workdir/$asset" "${target}.new" 2>/dev/null ||
    fail "cannot write to ${install_dir}." "Set TDXGUARD_INSTALL_DIR to a directory you can write."
  mv -f "${target}.new" "$target"

  say "  installed ${target}"
  "$target" --version || fail "the installed executable does not run: ${target}"

  case ":${PATH}:" in
    *":${install_dir}:"*) on_path=1 ;;
    *) on_path=0 ;;
  esac
  if [ "$on_path" = 0 ]; then
    say ""
    say "${install_dir} is not on your PATH. Add it, for example:"
    case "$(basename "${SHELL:-sh}")" in
      zsh) say "  echo 'export PATH=\"${install_dir}:\$PATH\"' >> ~/.zshrc && exec zsh" ;;
      bash) say "  echo 'export PATH=\"${install_dir}:\$PATH\"' >> ~/.bashrc && exec bash" ;;
      fish) say "  fish_add_path ${install_dir}" ;;
      *) say "  export PATH=\"${install_dir}:\$PATH\"   (in your shell's startup file)" ;;
    esac
  fi
  say ""
  say "Next steps:"
  say "  tdxguard login     sign in with TDxSSO"
  say "  tdxguard init      write .tdxguard.yml in your repository"
  say "  tdxguard scan      scan it (the scanners are downloaded on first use)"
}

os_is_darwin=0
[ "${TDXGUARD_UNAME_S:-$(uname -s)}" = "Darwin" ] && os_is_darwin=1

# Everything runs from main, so a download cut off half way cannot run half a script.
main "$@"
