#!/usr/bin/env python3
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

"""Render mock OS-styled screenshots containing canonical test secrets.

These outputs feed Phase E of scripts/test-gemini-e2e.sh, which posts
each PNG through masqr's OCR pipeline and asserts that the expected
rule fires on the recovered text. They are *not* real screenshots —
using actual screenshots with real credentials would itself be a leak.
Instead, each image is a deterministic Pillow render that mimics the
chrome of a popular OS (window title bars, status bars, app frames)
with a known test-vector secret drawn from the same canonical examples
as rules.go and the catalog phase. That way the test exercises mixed
text-plus-chrome OCR (which is closer to a real-world screenshot that
a user might paste into Claude / Gemini) instead of plain text on
white, which Phase D already covers.

Layouts are intentionally chunky — 28-32 pt monospace for terminals,
~30 pt sans for chrome — because PaddleOCR PP-OCRv5's per-character
error rate climbs steeply below ~20 pt. Strict-prefix secrets like
AKIA… / ghp_… are forgiving of single-character errors; PII patterns
with weaker structural constraints (email, credit card) need
proportionally larger text to round-trip reliably.

Run:  scripts/generate-screenshots.py            # writes testdata/screenshots/
      scripts/generate-screenshots.py --check    # verify outputs match committed bytes
"""

from __future__ import annotations

import argparse
import hashlib
import os
import sys
from pathlib import Path
from typing import Iterable

from PIL import Image, ImageDraw, ImageFont

# ─── Per-OS font palettes ───────────────────────────────────────────────────-

# Real fonts shipped by each OS, mapped to file paths we expect on a Linux
# build host. The renderer reaches for the exact OS font where licensing
# allows redistribution (Cantarell — GPL, Cascadia — OFL, Roboto — Apache,
# SF Pro / SF Mono — Apple's free Developer Agreement download) and falls
# through to a documented OFL substitute when the canonical font isn't
# present. The fallback chain matters because:
#
#   - macOS / iOS use SF Pro & SF Mono. Apple's EULA permits use but is
#     awkward about redistribution, so we don't commit the .otf files to
#     the repo. If the host has them in /usr/local/share/fonts/sf-fonts
#     (extracted from Apple's free DMG, see scripts/install-os-fonts.sh)
#     we use them; otherwise Inter / JetBrains Mono — both OFL-licensed
#     and explicitly designed as SF Pro / SF Mono substitutes — are used.
#
#   - Windows chrome uses Segoe UI, which is Microsoft-proprietary and
#     not legally redistributable. Microsoft published Selawik as a
#     metric-compatible OFL substitute but only as source UFO files,
#     never as a binary TTF, so we use Inter instead — same fallback
#     macOS uses, and ArchWiki's "metric-compatible fonts" table
#     specifically lists Inter as a community-accepted Segoe UI swap-in.
#
# Each entry is a list searched in order — first existing file wins.
FONT_PALETTE = {
    # Windows 11
    "win.chrome":      ["/usr/share/fonts/opentype/inter/Inter-Regular.otf"],
    "win.chrome.bold": ["/usr/share/fonts/opentype/inter/Inter-SemiBold.otf"],
    "win.mono":        ["/usr/share/fonts/truetype/cascadia-code/CascadiaMono.ttf"],
    "win.mono.bold":   ["/usr/share/fonts/truetype/cascadia-code/CascadiaMono.ttf"],

    # macOS / iOS — SF Pro & SF Mono if installed, Inter / JetBrains Mono fallback.
    "mac.chrome":      ["/usr/local/share/fonts/sf-fonts/SF-Pro-Text-Regular.otf",
                        "/usr/share/fonts/opentype/inter/Inter-Regular.otf"],
    "mac.chrome.bold": ["/usr/local/share/fonts/sf-fonts/SF-Pro-Text-Semibold.otf",
                        "/usr/share/fonts/opentype/inter/Inter-SemiBold.otf"],
    "mac.mono":        ["/usr/local/share/fonts/sf-fonts/SF-Mono-Regular.otf",
                        "/usr/share/fonts/truetype/jetbrains-mono/JetBrainsMono-Regular.ttf"],
    "mac.mono.bold":   ["/usr/local/share/fonts/sf-fonts/SF-Mono-Bold.otf",
                        "/usr/share/fonts/truetype/jetbrains-mono/JetBrainsMono-Bold.ttf"],

    # Linux (GNOME 45+) — Cantarell for the shell + DejaVu Sans Mono for terminals.
    "linux.chrome":      ["/usr/share/fonts/opentype/cantarell/Cantarell-Regular.otf"],
    "linux.chrome.bold": ["/usr/share/fonts/opentype/cantarell/Cantarell-Bold.otf"],
    "linux.mono":        ["/usr/share/fonts/truetype/dejavu/DejaVuSansMono.ttf"],
    "linux.mono.bold":   ["/usr/share/fonts/truetype/dejavu/DejaVuSansMono-Bold.ttf"],

    # Android — Roboto for everything (system UI + body).
    "android":           ["/usr/share/fonts/truetype/roboto/unhinted/RobotoTTF/Roboto-Regular.ttf"],
    "android.medium":    ["/usr/share/fonts/truetype/roboto/unhinted/RobotoTTF/Roboto-Medium.ttf"],
    "android.bold":      ["/usr/share/fonts/truetype/roboto/unhinted/RobotoTTF/Roboto-Bold.ttf"],

    # iOS — SF Pro Display for chrome + body. Inter fallback if SF not installed.
    "ios":               ["/usr/local/share/fonts/sf-fonts/SF-Pro-Display-Regular.otf",
                          "/usr/share/fonts/opentype/inter/Inter-Regular.otf"],
    "ios.bold":          ["/usr/local/share/fonts/sf-fonts/SF-Pro-Display-Semibold.otf",
                          "/usr/share/fonts/opentype/inter/Inter-SemiBold.otf"],
    "ios.heavy":         ["/usr/local/share/fonts/sf-fonts/SF-Pro-Display-Bold.otf",
                          "/usr/share/fonts/opentype/inter/Inter-Bold.otf"],
}


def _font(key: str, size: int) -> ImageFont.FreeTypeFont:
    """Resolve a font from the per-OS palette.

    Raises a clear error if every candidate is missing — that's almost
    always a packaging issue (`apt install fonts-inter fonts-roboto
    fonts-cantarell fonts-cascadia-code fonts-jetbrains-mono` covers
    the OFL set; SF Pro must be extracted from Apple's DMG separately,
    see scripts/install-os-fonts.sh) and silently falling back to
    Pillow's 10 px bitmap default would produce unreadable OCR input,
    which is a worse failure mode than crashing here.
    """
    candidates = FONT_PALETTE.get(key)
    if not candidates:
        raise KeyError(f"unknown font key {key!r}; check FONT_PALETTE")
    for path in candidates:
        if os.path.exists(path):
            return ImageFont.truetype(path, size)
    raise FileNotFoundError(
        f"no font file found for {key!r}; tried: {', '.join(candidates)}.\n"
        f"Install with:  sudo apt install fonts-inter fonts-roboto "
        f"fonts-cantarell fonts-cascadia-code fonts-jetbrains-mono\n"
        f"And for SF Pro / SF Mono:  scripts/install-os-fonts.sh"
    )


# ─── Drawing helpers ───────────────────────────────────────────────────────-

def _draw_circle(d: ImageDraw.ImageDraw, cx: int, cy: int, r: int, fill: str,
                 outline: str | None = None, width: int = 1) -> None:
    d.ellipse((cx - r, cy - r, cx + r, cy + r),
              fill=fill, outline=outline, width=width)


def _draw_traffic_lights(d: ImageDraw.ImageDraw, x: int, y: int) -> None:
    """macOS-style red / yellow / green window controls at (x,y)."""
    for i, color in enumerate(("#ff5f57", "#febc2e", "#28c840")):
        _draw_circle(d, x + i * 20, y, 6, color)


# ─── Icon primitives ───────────────────────────────────────────────────────-
#
# Material Design / iOS / Windows UIs source most chrome icons (back
# arrow, kebab menu, send button, signal/wifi/battery indicators) from
# dedicated icon fonts (Material Symbols, SF Symbols) rather than Unicode
# glyph blocks. Inter / Roboto / SF Pro all lack reliable coverage for
# U+2190 / U+22EE / U+27A4 — the renders we get back are bare "missing
# glyph" boxes. Drawing them as Pillow primitives keeps the screenshots
# font-independent and visually consistent with how the actual OS
# renders them (an arrow really is just a triangle + a line).


def _icon_back_arrow(d: ImageDraw.ImageDraw, cx: int, cy: int, size: int,
                     color: str) -> None:
    """Material-style left back arrow centred at (cx, cy), bbox `size`."""
    half = size // 2
    # Shaft.
    d.line((cx - half + 2, cy, cx + half - 2, cy), fill=color, width=max(2, size // 10))
    # Arrowhead triangle.
    head = max(4, size // 3)
    d.polygon([
        (cx - half + 2, cy),
        (cx - half + 2 + head, cy - head),
        (cx - half + 2 + head, cy + head),
    ], fill=color)


def _icon_kebab(d: ImageDraw.ImageDraw, cx: int, cy: int, color: str) -> None:
    """Vertical three-dot menu icon centred at (cx, cy)."""
    for dy in (-9, 0, 9):
        _draw_circle(d, cx, cy + dy, 2, color)


def _icon_send(d: ImageDraw.ImageDraw, cx: int, cy: int, size: int,
               color: str) -> None:
    """Right-pointing paper-plane wedge (Material send glyph) at (cx, cy)."""
    half = size // 2
    d.polygon([
        (cx - half, cy - half + 1),
        (cx + half - 1, cy),
        (cx - half, cy + half - 1),
        (cx - half + half // 3, cy),
    ], fill=color)


def _icon_status_bar(d: ImageDraw.ImageDraw, x: int, y: int, color: str) -> None:
    """Tiny signal / wifi / battery indicator stack drawn at (x, y).

    Three glyphs ~6 px tall each — kept abstract because pixel-perfect
    Material You / iOS battery icons add visual noise that distracts
    from the actual test target (the secret in the body).
    """
    # Signal bars.
    for i, h in enumerate((3, 5, 7, 9)):
        d.rectangle((x + i * 3, y + 10 - h, x + i * 3 + 2, y + 10), fill=color)
    # WiFi arc.
    wx = x + 18
    for r, w in ((6, 2), (4, 2), (2, 2)):
        d.arc((wx - r, y + 8 - r, wx + r, y + 8 + r), start=210, end=330,
              fill=color, width=w)
    _draw_circle(d, wx, y + 8, 1, color)
    # Battery.
    bx = x + 30
    d.rectangle((bx, y + 2, bx + 14, y + 10), outline=color, width=1)
    d.rectangle((bx + 14, y + 4, bx + 16, y + 8), fill=color)
    d.rectangle((bx + 2, y + 4, bx + 12, y + 8), fill=color)


def _save(img: Image.Image, path: Path) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    img.save(path, "PNG", optimize=True)


# ─── Windows 11 Notepad ────────────────────────────────────────────────────-

def render_windows(out: Path) -> None:
    """A Notepad window containing an AWS credentials block.

    Why this layout: Windows 11 Notepad is the canonical "I'll paste a
    secret here for a sec" surface — light title bar, light menu strip,
    white body. Rendering it this way is the worst case for OCR on
    Windows (no native dark-mode contrast) so a green run here implies
    the dark-themed terminals are also fine.

    Sizing rationale: PaddleOCR PP-OCRv5's rec model squashes very wide
    single-line crops back to its training aspect ratio, so a 26 pt
    mono line spanning ~700 px gets compressed past readability. We
    render at 1100 × 720 with 32 pt mono-bold and keep each line under
    ~640 px of text width, which keeps every box close to the rec
    model's native aspect ratio.

    Fonts: chrome uses Inter (the de-facto open-source Segoe UI
    substitute); the editor body uses Cascadia Mono, the actual default
    monospace font on Windows 10 / 11 Terminal and the modern Notepad.
    """
    W, H = 1100, 720
    img = Image.new("RGB", (W, H), "#f3f3f3")
    d = ImageDraw.Draw(img)

    # Title bar (light, Win11-style).
    d.rectangle((0, 0, W, 48), fill="#f3f3f3")
    d.text((20, 12), "Untitled - Notepad",
           font=_font("win.chrome", 22), fill="#202020")
    # Min / max / close on the right. U+00D7 × is used for close because
    # Inter ships U+00D7 but lacks U+2715 (heavy multiplication X) —
    # visually equivalent at this size and avoids a NOGLYPH fallback.
    for i, glyph in enumerate(("\u2014", "\u25a1", "\u00d7")):
        d.text((W - 130 + i * 42, 12), glyph,
               font=_font("win.chrome", 22), fill="#202020")

    # Thin separator under the title bar.
    d.line((0, 48, W, 48), fill="#dcdcdc", width=1)

    # Menu strip.
    d.rectangle((0, 49, W, 90), fill="#fafafa")
    menu_fnt = _font("win.chrome", 20)
    x = 24
    for item in ("File", "Edit", "View"):
        d.text((x, 58), item, font=menu_fnt, fill="#202020")
        x += d.textbbox((0, 0), item, font=menu_fnt)[2] + 28

    # Body — bold Cascadia Mono, AWS creds laid out with the long key on
    # its own 36 pt line. Each line is short enough that detection
    # produces a box near the rec model's preferred aspect ratio.
    body_lines = [
        ("# AWS credentials",                              "#404040"),
        ("",                                               "#101010"),
        ("[default]",                                      "#101010"),
        ("aws_access_key_id =",                            "#101010"),
        ("AKIAIOSFODNN7EXAMPLE",                           "#101010"),
        ("region = us-east-1",                             "#101010"),
    ]
    y = 130
    fnt = _font("win.mono.bold", 36)
    for line, color in body_lines:
        d.text((50, y), line, font=fnt, fill=color)
        y += 64

    _save(img, out)


# ─── macOS Terminal ────────────────────────────────────────────────────────-

def render_macos(out: Path) -> None:
    """A zsh prompt exporting a Stripe live secret key into the env.

    macOS Terminal default theme is light, but a dark theme is far more
    common among developers. We pick the dark Pro theme look: near-black
    body, soft contrast title bar, traffic-light buttons.

    Why Anthropic and not GitHub PAT: PP-OCRv5's rec model has a fixed
    input width of 320 px (see `recInputW` in sources_ocr.go). Every
    detected crop is resized to 48×320 before recognition, so any
    single line much wider than ~24 mono characters at any reasonable
    point size gets squashed below the legibility threshold and the
    rec model spits out a 2-3 char prefix — a 40-char ghp_ token is
    fundamentally outside that budget. Anthropic's `sk-ant-…` pattern
    matches at any non-empty `[a-z0-9-]` tail and we keep the body to
    lowercase letters and dashes (no `_` which PP-OCRv5 routinely loses
    against bold mono fonts, no `0` which gets confused with `o`).

    Fonts: SF Pro Text for the window title (real Apple system font
    from /usr/local/share/fonts/sf-fonts; Inter is auto-substituted if
    the SF set isn't installed), SF Mono for the terminal body (same
    fallback chain → JetBrains Mono).
    """
    W, H = 1100, 640
    img = Image.new("RGB", (W, H), "#1e1e1e")
    d = ImageDraw.Draw(img)

    # Title bar.
    d.rectangle((0, 0, W, 44), fill="#3a3a3a")
    _draw_traffic_lights(d, 26, 22)
    title = "alice — -zsh"
    title_fnt = _font("mac.chrome.bold", 16)
    tw = d.textbbox((0, 0), title, font=title_fnt)[2]
    d.text(((W - tw) / 2, 13), title, font=title_fnt, fill="#dddddd")

    # Body. Key on its own bold SF Mono line, kept under ~24 mono chars
    # and OCR-friendly (dashes survive better than underscores at this
    # font weight; pure lowercase avoids 0/O confusion).
    lines = [
        ("$ export ANTHROPIC_KEY=",                                           "#cccccc"),
        ("sk-ant-api-testabcdef",                                             "#ffffff"),
        ("$ claude --version",                                                "#cccccc"),
        ("claude-cli v0.4.2",                                                 "#90ee90"),
        ("$",                                                                 "#cccccc"),
    ]
    y = 90
    fnt = _font("mac.mono.bold", 32)
    for text, color in lines:
        d.text((48, y), text, font=fnt, fill=color)
        y += 58

    _save(img, out)


# ─── Linux GNOME Terminal ──────────────────────────────────────────────────-

def render_linux(out: Path) -> None:
    """A bash session showing /etc/hosts on a Debian box.

    Ubuntu's default purple is too aubergine for OCR — text bleeds into
    background. The community-favourite "GNOME Solarized Dark" is closer
    to what most masqr users actually have open, so that's what we emulate.
    Detection target: the private-ipv4 rule on 10.0.0.5.

    Fonts: Cantarell (the GNOME shell's actual sans-serif since GNOME 3)
    for the header bar, DejaVu Sans Mono Bold for the terminal body —
    DejaVu is the default monospace font on Debian/Ubuntu GNOME Terminal
    and the macOS Liberation Mono fallback we'd otherwise reach for is
    visually wrong here.
    """
    W, H = 900, 520
    img = Image.new("RGB", (W, H), "#1c1c1c")
    d = ImageDraw.Draw(img)

    # GNOME-style header bar.
    d.rectangle((0, 0, W, 40), fill="#2d2d2d")
    title = "alice@server: ~"
    title_fnt = _font("linux.chrome.bold", 16)
    tw = d.textbbox((0, 0), title, font=title_fnt)[2]
    d.text(((W - tw) / 2, 12), title, font=title_fnt, fill="#e0e0e0")
    # Hamburger and close on right. U+00D7 × (multiplication sign) is
    # used instead of U+2715 — Cantarell ships the former but not the
    # latter, and the two are visually equivalent at this point size.
    d.text((W - 70, 11), "\u2261",
           font=_font("linux.chrome.bold", 20), fill="#cccccc")
    d.text((W - 30, 11), "\u00d7",
           font=_font("linux.chrome.bold", 18), fill="#cccccc")

    lines = [
        ("alice@server",     "#8ae234", ":~$ cat /etc/hosts",                  "#e0e0e0"),
        (None,               None,      "127.0.0.1   localhost",               "#e0e0e0"),
        (None,               None,      "10.0.0.5    db-prod.internal",        "#e0e0e0"),
        (None,               None,      "192.168.1.42  bastion.lan",           "#e0e0e0"),
        ("alice@server",     "#8ae234", ":~$ ssh root@10.0.0.5",               "#e0e0e0"),
        (None,               None,      "Welcome to db-prod (Debian 12)",      "#dcdc7a"),
        ("root@db-prod",     "#ff6b6b", ":~#",                                 "#e0e0e0"),
    ]
    y = 72
    fnt = _font("linux.mono.bold", 24)
    for prompt, pcolor, rest, rcolor in lines:
        x = 36
        if prompt is not None:
            d.text((x, y), prompt, font=fnt, fill=pcolor)
            x += d.textbbox((0, 0), prompt, font=fnt)[2]
        d.text((x, y), rest, font=fnt, fill=rcolor)
        y += 44

    _save(img, out)


# ─── Android Messages ──────────────────────────────────────────────────────-

def render_android(out: Path) -> None:
    """An Android Messages bubble containing a 16-digit Visa test card.

    Mobile aspect (420×780). The status bar / nav bar styling is the
    Material You light theme — pale background, dark text. Card test
    vector 4532015112830366 trips the Luhn-validated `credit-card` rule.

    Fonts: Roboto — the actual Android system font since Ice Cream
    Sandwich (4.0). Status-bar / app-bar text uses Roboto Medium for
    contrast against the pale Material You background; message body
    text uses Roboto Medium too because Android Messages renders
    bubble text in a slightly heavier weight than body copy.
    """
    W, H = 420, 780
    img = Image.new("RGB", (W, H), "#fef7ff")
    d = ImageDraw.Draw(img)

    # Status bar. Roboto doesn't ship the signal/wifi/battery glyphs
    # (those come from Material Symbols on a real device), so we draw
    # them as primitives — same visual result, font-independent.
    d.rectangle((0, 0, W, 28), fill="#fef7ff")
    d.text((14, 6), "9:41",
           font=_font("android.bold", 14), fill="#1d1b20")
    _icon_status_bar(d, W - 60, 9, "#1d1b20")

    # App bar.
    d.rectangle((0, 28, W, 90), fill="#fef7ff")
    _icon_back_arrow(d, 28, 60, 22, "#1d1b20")
    d.text((52, 48), "Mom",
           font=_font("android.bold", 22), fill="#1d1b20")
    _icon_kebab(d, W - 30, 60, "#1d1b20")
    d.line((0, 90, W, 90), fill="#e6e0e9", width=1)

    # Conversation bubbles.
    bubbles = [
        ("Hey, here's the family card for that gift", "left",  120),
        ("Card: 4532 0151 1283 0366",                  "left",  220),
        ("Exp 09/29 CVV 123",                          "left",  290),
        ("Got it, thanks!",                            "right", 380),
    ]
    fnt = _font("android.medium", 20)
    for text, side, y in bubbles:
        # Wrap roughly at 320 px wide; these strings are short.
        bbox = d.textbbox((0, 0), text, font=fnt)
        tw = bbox[2] - bbox[0]
        pad = 18
        bw = min(tw + pad * 2, W - 60)
        if side == "left":
            x = 20
            color, fg = "#e8def8", "#1d1b20"
        else:
            x = W - 20 - bw
            color, fg = "#6750a4", "#ffffff"
        d.rounded_rectangle((x, y, x + bw, y + 56), radius=20, fill=color)
        d.text((x + pad, y + 14), text, font=fnt, fill=fg)

    # Bottom input bar.
    d.rectangle((0, H - 70, W, H), fill="#fef7ff")
    d.rounded_rectangle((14, H - 56, W - 70, H - 14), radius=24, fill="#e6e0e9")
    d.text((34, H - 48), "Text message",
           font=_font("android", 18), fill="#79747e")
    _draw_circle(d, W - 35, H - 35, 22, "#6750a4")
    _icon_send(d, W - 35, H - 35, 20, "#ffffff")

    _save(img, out)


# ─── iOS Notes ─────────────────────────────────────────────────────────────-

def render_ios(out: Path) -> None:
    """An iOS Notes page with an email address jotted down.

    Mobile aspect (420×780), iOS 17 / 18-flavoured chrome: notch-era
    status bar with time on the left, signal-indicator glyphs on the
    right; yellow Notes navbar; lined-paper body that mimics the
    default "Note Paper - Yellow" style. The leading paragraph is on
    the cover-letter side just so the OCR has something to chew besides
    a bare email line — that's closer to a real screenshot than a one-
    line image.

    Fonts: SF Pro Display, Apple's real system font (extracted from
    Apple's free SF-Pro.dmg into /usr/local/share/fonts/sf-fonts; Inter
    is auto-substituted if the SF set isn't installed). Heavy weight
    for the status bar time, semibold for nav-bar text, bold for the
    note title — those map to the weights iOS Notes actually uses.
    """
    W, H = 420, 780
    img = Image.new("RGB", (W, H), "#fff8dc")
    d = ImageDraw.Draw(img)

    # Status bar.
    d.text((20, 8), "9:41",
           font=_font("ios.heavy", 16), fill="#000000")
    d.text((W - 90, 8), "\u25cf \u25cf \u25cf",
           font=_font("ios.bold", 14), fill="#000000")

    # Nav bar.
    d.rectangle((0, 36, W, 100), fill="#fff3a0")
    d.text((14, 56), "\u2190 Notes",
           font=_font("ios.bold", 20), fill="#b87900")
    d.text((W - 80, 56), "Done",
           font=_font("ios.bold", 20), fill="#b87900")
    d.line((0, 100, W, 100), fill="#e6d98a", width=1)

    # Note title and body.
    d.text((24, 124), "Vendor contact",
           font=_font("ios.heavy", 26), fill="#1a1a1a")
    body_lines = [
        "Email the supplier today:",
        "",
        "  john.doe@example.com",
        "",
        "(Re: October invoice.)",
    ]
    y = 180
    body_fnt = _font("ios.bold", 22)
    for line in body_lines:
        d.text((24, y), line, font=body_fnt, fill="#1a1a1a")
        y += 48

    # Faint horizontal rules (paper effect).
    for ry in range(180 + 36, H - 80, 48):
        d.line((20, ry, W - 20, ry), fill="#f0e7a8", width=1)

    _save(img, out)


# ─── Manifest ──────────────────────────────────────────────────────────────-

# Each entry: (output filename, renderer, expected_rule_id, secret_excerpt)
# secret_excerpt is what we expect OCR to recover (used only for diagnostics;
# the actual assertion in Phase E is "rule fired" by ID).
MANIFEST = [
    ("windows-notepad-aws.png",     render_windows, "aws-access-key-id", "AKIAIOSFODNN7EXAMPLE"),
    ("macos-terminal-anthropic.png", render_macos,  "anthropic-api-key", "sk-ant-api-testabcdef"),
    ("linux-gnome-private-ip.png",  render_linux,   "private-ipv4",      "10.0.0.5"),
    ("android-messages-card.png",   render_android, "credit-card",       "4532 0151 1283 0366"),
    ("ios-notes-email.png",         render_ios,     "email-address",     "john.doe@example.com"),
]


def render_all(out_dir: Path) -> Iterable[Path]:
    for name, fn, _rule, _secret in MANIFEST:
        target = out_dir / name
        fn(target)
        yield target


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--out", default=None, help="output directory (default: testdata/screenshots)")
    parser.add_argument("--check", action="store_true",
                        help="render to a temp dir and assert hashes match committed bytes")
    args = parser.parse_args()

    repo = Path(__file__).resolve().parent.parent
    default_out = repo / "testdata" / "screenshots"
    out_dir = Path(args.out) if args.out else default_out

    if args.check:
        import tempfile

        with tempfile.TemporaryDirectory() as tmp:
            tmp_dir = Path(tmp)
            ok = True
            for name, fn, _rule, _secret in MANIFEST:
                fn(tmp_dir / name)
                committed = (default_out / name).read_bytes()
                rendered = (tmp_dir / name).read_bytes()
                if committed != rendered:
                    print(f"  MISMATCH  {name}  "
                          f"(committed={hashlib.sha256(committed).hexdigest()[:10]} "
                          f"rendered={hashlib.sha256(rendered).hexdigest()[:10]})",
                          file=sys.stderr)
                    ok = False
                else:
                    print(f"  ok        {name}")
            return 0 if ok else 1

    for path in render_all(out_dir):
        print(f"  wrote     {path.relative_to(repo)} ({path.stat().st_size} bytes)")
    return 0


if __name__ == "__main__":
    sys.exit(main())
