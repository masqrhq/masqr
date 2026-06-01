<p align="center">
  <picture>
    <source media="(prefers-color-scheme: dark)" srcset="assets/banner-dark.svg">
    <img alt="masqr — deep prompt inspection" src="assets/banner.svg" width="100%">
  </picture>
</p>

# masqr

> deep prompt inspection for LLM CLIs

`masqr` is a transparent proxy that sits between an LLM CLI (claude, gemini, codex, agy, vibe) and the upstream API. Every request is parsed, scanned for secrets / PII / attachments / OCR'd image content, logged in full, and **blocked before it leaves your machine** if anything trips. The CLI sees a normal API error telling you what leaked — you fix the prompt and retry. No config, no account, no telemetry.

```
 ▟█▙ ▟█▙   masqr  · deep prompt inspection [google-gemini]
 ▜█▄▄▄█▛   http://127.0.0.1:38219 → https://generativelanguage.googleapis.com
  ▘   ▘    log: masqr-20260518-093142.log
```

📖 [Full reference](docs/reference.md) · 🤝 [Contributing](CONTRIBUTING.md) · 📝 [Changelog](CHANGELOG.md)

<p align="center"><sub><b>WORKS WITH</b></sub></p>
<p align="center">
  <a href="https://antigravity.google/"><img alt="Antigravity" src="https://img.shields.io/badge/Antigravity-4285F4?style=for-the-badge&logo=google&logoColor=white"></a>
  <a href="https://www.anthropic.com/claude-code"><img alt="Claude Code" src="https://img.shields.io/badge/Claude_Code-D97757?style=for-the-badge&logo=anthropic&logoColor=white"></a>
  <a href="https://openai.com/codex/"><img alt="Codex" src="https://img.shields.io/badge/Codex-000000?style=for-the-badge&logoColor=white"></a>
  <a href="https://ai.google.dev/gemini-api/docs"><img alt="Gemini" src="https://img.shields.io/badge/Gemini-1C69FF?style=for-the-badge&logo=googlegemini&logoColor=white"></a>
  <a href="https://github.com/mistralai/mistral-vibe"><img alt="Mistral Vibe" src="https://img.shields.io/badge/Mistral_Vibe-FA520F?style=for-the-badge&logo=mistralai&logoColor=white"></a>
</p>

## Features at a glance

- **Wraps the CLI you already use** — `masqr claude`, `masqr codex`, `masqr gemini`, `masqr agy`, `masqr vibe`. The provider (upstream, env vars, auth redaction) is auto-detected from the command name; no flags needed.
- **Catches secrets before they ship** — 40+ hand-tuned rules (AWS/GCP/Azure/Anthropic/OpenAI/Stripe/Slack/GitHub/GitLab tokens, JWTs, PEM keys) **plus the full gitleaks v8 ruleset**, all graded `critical · high · medium · low`.
- **PII for 16 jurisdictions** — credit cards, IBANs, and country-tagged national IDs (US SSN/NPI, UK NHS, DE Steuer-ID, IN Aadhaar, …), each checksum-validated.
- **Sees through obfuscation** — high-entropy base64 is decoded and re-scanned; JSON-escape artifacts are normalized.
- **Reads images** — optional PaddleOCR pipeline extracts text from inline screenshots and re-feeds it through every rule, so a secret pasted as an image still trips.
- **Block or redact** — return HTTP 451 (upstream never contacted) or rewrite the offending span with a placeholder and restore it in the response.
- **Single self-contained binary** — ONNX Runtime and OCR models are embedded; nothing else to install. Full per-session logging with auto-redaction.

## Install

Prebuilt binaries — one line, no toolchain, no Git LFS:

**macOS / Linux** (Apple Silicon, Linux x86-64 / arm64):

```sh
curl -fsSL https://masqr.dev/install.sh | sh
```

**Windows** (PowerShell — x64 / arm64):

```powershell
irm https://masqr.dev/install.ps1 | iex
```

The installer picks the right build for your OS/CPU, verifies its SHA-256, and drops `masqr` into `~/.local/bin` (`%LOCALAPPDATA%\masqr\bin` on Windows). Pin a version with `MASQR_VERSION=vX.Y.Z` / `$env:MASQR_VERSION`; change the location with `MASQR_INSTALL_DIR` / `$env:MASQR_INSTALL_DIR`.

Prefer to build it yourself? See [Build from source](docs/reference.md#build-from-source) (needs Go + Git LFS).

## Usage

```sh
masqr agy                             # wrap Google Antigravity (transparent TLS)
masqr claude                          # wrap Anthropic Claude Code
masqr codex                           # wrap OpenAI Codex
masqr gemini -p "summarize file.txt"  # wrap Google Gemini
masqr vibe                            # wrap Mistral vibe CLI

masqr --block-on=high claude          # only block high+critical findings
masqr --on-finding redact claude      # redact spans instead of blocking
masqr -k ./keywords.txt claude        # also scan a custom keyword wordlist
```

masqr starts a loopback listener, points the child CLI at it via the right `*_BASE_URL`, and attaches it to your terminal so you interact normally. When the child exits, masqr shuts down cleanly. Positional args after the flags pass straight through to the child — no `--` separator needed.

See the [full reference](docs/reference.md) for provider internals, the complete rule catalog, the 451 envelope shapes, environment variables, logging format, and the E2E test suite.

## Platform support

Self-contained release binaries (OCR included) are published for **linux/amd64**, **linux/arm64**, **darwin/arm64**, **windows/amd64**, and **windows/arm64**. On other targets the proxy and rule engines still work; OCR is a no-op with a startup warning. (Intel Macs aren't built — Microsoft dropped `osx-x86_64` ONNX Runtime in 1.26.)

## License

Apache License 2.0 — see [`LICENSE`](LICENSE). The binary bundles Microsoft ONNX Runtime (MIT) and PaddleOCR PP-OCRv5 models (Apache-2.0); see [`NOTICE`](NOTICE) and [`LICENSES/`](LICENSES) for full attribution.
