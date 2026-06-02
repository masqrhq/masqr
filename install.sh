#!/bin/sh
# Copyright 2026 masqr contributors
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
#
# masqr installer — one-liner bootstrap.
#
#   curl -fsSL https://masqr.dev/install.sh | sh
#
# Downloads the right prebuilt binary for your OS/arch from the latest
# GitHub release, verifies its SHA-256, and drops `masqr` into ~/.local/bin
# (no sudo). Re-running upgrades in place.
#
# Environment overrides:
#   MASQR_VERSION       pin a release tag (e.g. v0.3.1); default: latest
#   MASQR_INSTALL_DIR   install location; default: $HOME/.local/bin
#   MASQR_REPO          owner/repo to pull from; default: masqrhq/masqr
#
# This script is intentionally POSIX sh (no bashisms) so it runs under the
# default /bin/sh on macOS, Debian/Ubuntu (dash), Alpine, etc.

set -eu

REPO="${MASQR_REPO:-masqrhq/masqr}"
INSTALL_DIR="${MASQR_INSTALL_DIR:-$HOME/.local/bin}"
BIN_NAME="masqr"

# ─── Pretty output ───────────────────────────────────────────────────────────
if [ -t 1 ] && [ -z "${NO_COLOR:-}" ]; then
  BOLD=$(printf '\033[1m'); DIM=$(printf '\033[2m'); RED=$(printf '\033[31m')
  GREEN=$(printf '\033[32m'); YELLOW=$(printf '\033[33m'); RESET=$(printf '\033[0m')
else
  BOLD=; DIM=; RED=; GREEN=; YELLOW=; RESET=
fi
info()  { printf '%s\n' "${DIM}masqr:${RESET} $*"; }
ok()    { printf '%s\n' "${GREEN}✓${RESET} $*"; }
warn()  { printf '%s\n' "${YELLOW}!${RESET} $*" >&2; }
die()   { printf '%s\n' "${RED}✗ $*${RESET}" >&2; exit 1; }

need() { command -v "$1" >/dev/null 2>&1 || die "required tool '$1' not found on PATH"; }

# Prefer curl, fall back to wget.
if command -v curl >/dev/null 2>&1; then
  http_get()      { curl -fsSL "$1"; }                       # body to stdout
  http_download() { curl -fsSL -o "$2" "$1"; }               # url -> file
  http_location() { curl -fsSLI -o /dev/null -w '%{url_effective}' "$1"; }
elif command -v wget >/dev/null 2>&1; then
  http_get()      { wget -qO- "$1"; }
  http_download() { wget -qO "$2" "$1"; }
  http_location() { wget -q -S -O /dev/null "$1" 2>&1 | awk '/^  Location: /{u=$2} END{print u}'; }
else
  die "need either curl or wget installed"
fi
need tar

# ─── Detect OS / arch and map to release asset naming ────────────────────────
# Release assets are produced by .github/workflows/release.yml as the bare
# binary  masqr-<tag>-<goos>-<goarch>   (+ .sha256)
os=$(uname -s)
case "$os" in
  Linux)  GOOS=linux  ;;
  Darwin) GOOS=darwin ;;
  MINGW*|MSYS*|CYGWIN*|Windows_NT)
    die "Windows isn't supported by this installer.
    See https://github.com/$REPO#windows for status." ;;
  *) die "unsupported OS: $os" ;;
esac

arch=$(uname -m)
case "$arch" in
  x86_64|amd64)        GOARCH=amd64 ;;
  arm64|aarch64)       GOARCH=arm64 ;;
  *) die "unsupported architecture: $arch" ;;
esac

# masqr only publishes these triples today (CGO + per-platform OCR libs mean
# every target is built on a native runner; see release.yml). Fail early with
# a clear message rather than 404-ing on a download.
supported=0
case "$GOOS/$GOARCH" in
  linux/amd64|linux/arm64|darwin/arm64) supported=1 ;;
esac
if [ "$supported" -ne 1 ]; then
  if [ "$GOOS/$GOARCH" = "darwin/amd64" ]; then
    die "Intel Macs aren't built yet — masqr ships darwin/arm64 (Apple Silicon) only."
  fi
  die "no prebuilt binary for $GOOS/$GOARCH yet."
fi

# CGO binary is glibc-linked; warn (don't block) on musl (Alpine).
if [ "$GOOS" = linux ] && [ -f /lib/libc.musl-x86_64.so.1 -o -f /lib/libc.musl-aarch64.so.1 ]; then
  warn "musl libc detected (Alpine?). Release binaries are glibc-linked and may not run.
    If 'masqr' fails to start, build from source: see https://github.com/$REPO#build."
fi

# ─── Resolve version ─────────────────────────────────────────────────────────
TAG="${MASQR_VERSION:-}"
if [ -z "$TAG" ]; then
  info "resolving latest release…"
  # /releases/latest 302-redirects to /releases/tag/<TAG>; parse the tag off
  # the final URL. Avoids the GitHub API's 60 req/hr unauthenticated limit.
  loc=$(http_location "https://github.com/$REPO/releases/latest" || true)
  TAG=$(printf '%s\n' "$loc" | sed -n 's#.*/releases/tag/##p')
  [ -n "$TAG" ] || die "couldn't determine the latest release tag.
    Set MASQR_VERSION=vX.Y.Z explicitly, or check https://github.com/$REPO/releases."
fi
info "installing ${BOLD}masqr $TAG${RESET} ($GOOS/$GOARCH)"

stem="masqr-${TAG}-${GOOS}-${GOARCH}"
base="https://github.com/$REPO/releases/download/$TAG"
bin_url="$base/${stem}"
sha_url="$base/${stem}.sha256"

# ─── Download + verify in a scratch dir ──────────────────────────────────────
tmp=$(mktemp -d "${TMPDIR:-/tmp}/masqr.XXXXXX") || die "mktemp failed"
trap 'rm -rf "$tmp"' EXIT INT TERM

info "downloading ${stem}…"
http_download "$bin_url" "$tmp/$BIN_NAME" \
  || die "download failed: $bin_url
    Asset may not exist for this platform/version."

# Verify SHA-256 if the sidecar is present (it always should be).
if http_download "$sha_url" "$tmp/${stem}.sha256" 2>/dev/null; then
  expected=$(awk '{print $1; exit}' "$tmp/${stem}.sha256")
  if command -v sha256sum >/dev/null 2>&1; then
    actual=$(sha256sum "$tmp/$BIN_NAME" | awk '{print $1}')
  elif command -v shasum >/dev/null 2>&1; then
    actual=$(shasum -a 256 "$tmp/$BIN_NAME" | awk '{print $1}')
  else
    actual=""; warn "no sha256sum/shasum; skipping checksum verification"
  fi
  if [ -n "$actual" ]; then
    [ "$actual" = "$expected" ] || die "checksum mismatch!
    expected $expected
    got      $actual"
    ok "checksum verified"
  fi
else
  warn "no .sha256 sidecar published; skipping checksum verification"
fi

# The asset is the bare binary — no extraction step.
src="$tmp/$BIN_NAME"

# ─── Install atomically ──────────────────────────────────────────────────────
mkdir -p "$INSTALL_DIR"
dest="$INSTALL_DIR/$BIN_NAME"
chmod +x "$src"
# Move via temp + rename so a running masqr isn't clobbered mid-write.
cp "$src" "$dest.new"
chmod +x "$dest.new"
mv -f "$dest.new" "$dest"
ok "installed to ${BOLD}$dest${RESET}"

# macOS Gatekeeper: strip the quarantine bit so it runs without a prompt.
if [ "$GOOS" = darwin ] && command -v xattr >/dev/null 2>&1; then
  xattr -d com.apple.quarantine "$dest" >/dev/null 2>&1 || true
fi

# Best-effort: run what we just installed so a broken binary (e.g. a glibc/musl
# mismatch) surfaces here instead of on first use. Non-fatal.
if ver=$("$dest" --version 2>/dev/null); then
  ok "$ver"
else
  warn "installed, but '$dest --version' didn't run cleanly here — see https://github.com/$REPO#build if masqr fails to start."
fi

# ─── PATH hint ───────────────────────────────────────────────────────────────
case ":$PATH:" in
  *":$INSTALL_DIR:"*) on_path=1 ;;
  *) on_path=0 ;;
esac
if [ "$on_path" -ne 1 ]; then
  shell_name=$(basename "${SHELL:-sh}")
  case "$shell_name" in
    zsh)  rc="$HOME/.zshrc" ;;
    bash) rc="$HOME/.bashrc" ;;
    fish) rc="$HOME/.config/fish/config.fish" ;;
    *)    rc="$HOME/.profile" ;;
  esac
  warn "$INSTALL_DIR is not on your PATH."
  if [ "$shell_name" = fish ]; then
    printf '  Add it:  %sfish_add_path %s%s\n' "$BOLD" "$INSTALL_DIR" "$RESET"
  else
    printf '  Add it:  %secho '\''export PATH="%s:$PATH"'\'' >> %s%s\n' "$BOLD" "$INSTALL_DIR" "$rc" "$RESET"
    printf '  Then:    %ssource %s%s\n' "$BOLD" "$rc" "$RESET"
  fi
fi

# ─── Done ────────────────────────────────────────────────────────────────────
printf '\n'
ok "${BOLD}masqr $TAG${RESET} is ready."
printf '%s\n' "${DIM}Wrap your coding CLI so secrets never leave your machine:${RESET}"
printf '  masqr claude          %s# Anthropic Claude Code\n' "$DIM"
printf '  masqr codex           %s# OpenAI Codex\n' "$DIM"
printf '  masqr gemini -p "…"   %s# Google Gemini%s\n' "$DIM" "$RESET"
printf '%s\n' "Docs: https://github.com/$REPO"
