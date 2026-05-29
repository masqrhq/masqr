#!/usr/bin/env bash
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

# scripts/install-os-fonts.sh — Install the real OS fonts used by
# scripts/generate-screenshots.py.
#
# Two groups:
#
#   1. OFL / Apache-licensed fonts — installed from the distro
#      repositories. Covers Windows (Inter + Cascadia Mono), Linux
#      (Cantarell + DejaVu), and Android (Roboto). These are the
#      actual system fonts on each OS, with the lone exception of
#      Windows chrome — Microsoft's Segoe UI is proprietary and
#      Selawik (their OFL substitute) only ever shipped as source
#      UFO, so Inter is used (community-accepted metric-compatible
#      replacement, see ArchWiki's "Metric-compatible fonts" page).
#
#   2. Apple's SF Pro & SF Mono — downloaded directly from Apple's
#      developer-resources CDN. The fonts are free under Apple's
#      EULA but cannot be redistributed in source control, so we
#      fetch and unpack them locally per host.
#
# After this script the generator will use SF Pro/Mono for macOS+iOS
# panels; if you skip group 2, Inter + JetBrains Mono are used as
# fallback (already a common SF substitute on Linux).
#
# Usage:
#   scripts/install-os-fonts.sh           # install everything
#   scripts/install-os-fonts.sh --no-apple # skip Apple SF set

set -euo pipefail

APPLE=1
for arg in "$@"; do
    case "$arg" in
        --no-apple) APPLE=0 ;;
        -h|--help)
            sed -n '2,/^set -/p' "$0" | grep '^#'
            exit 0 ;;
    esac
done

echo "→ installing OFL/Apache fonts from apt"
sudo apt-get update -qq
sudo apt-get install -y -qq \
    fonts-inter \
    fonts-cascadia-code \
    fonts-cantarell \
    fonts-roboto \
    fonts-jetbrains-mono \
    fonts-dejavu

if [[ "$APPLE" -ne 1 ]]; then
    echo "✓ skipped Apple SF Pro / SF Mono (per --no-apple)"
    exit 0
fi

echo "→ fetching Apple SF Pro + SF Mono"
need_tool() {
    if ! command -v "$1" >/dev/null 2>&1; then
        echo "  installing $2 (required for extracting Apple DMGs)"
        sudo apt-get install -y -qq "$2"
    fi
}
need_tool 7z p7zip-full
need_tool curl curl

TMP=$(mktemp -d -t sf-fonts-XXXXX)
trap 'rm -rf "$TMP"' EXIT

cd "$TMP"
curl -sL --max-time 120 -o SF-Pro.dmg  https://devimages-cdn.apple.com/design/resources/download/SF-Pro.dmg
curl -sL --max-time 60  -o SF-Mono.dmg https://devimages-cdn.apple.com/design/resources/download/SF-Mono.dmg

unpack_dmg() {
    local dmg="$1" outdir="$2"
    7z x -y -o"$outdir" "$dmg" >/dev/null
    local pkg
    pkg=$(find "$outdir" -name "*.pkg" | head -1)
    7z x -y -o"${outdir}/pkg" "$pkg" >/dev/null
    cd "${outdir}/pkg" && 7z x -y Payload~ >/dev/null && cd - >/dev/null
}

unpack_dmg SF-Pro.dmg  pro
unpack_dmg SF-Mono.dmg mono

DEST=/usr/local/share/fonts/sf-fonts
sudo mkdir -p "$DEST"
sudo cp pro/pkg/Library/Fonts/SF-Pro-Display-{Regular,Medium,Semibold,Bold}.otf "$DEST/"
sudo cp pro/pkg/Library/Fonts/SF-Pro-Text-{Regular,Medium,Semibold,Bold}.otf    "$DEST/"
sudo cp mono/pkg/Library/Fonts/SF-Mono-{Regular,Medium,Semibold,Bold}.otf       "$DEST/"

sudo fc-cache -f >/dev/null

echo "✓ installed Apple SF Pro / SF Mono → $DEST"
ls "$DEST" | sort
