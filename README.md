<p align="center">
  <picture>
    <source media="(prefers-color-scheme: dark)" srcset="assets/banner-dark.svg">
    <img alt="masqr — deep prompt inspection" src="assets/banner.svg" width="100%">
  </picture>
</p>

# masqr

> deep prompt inspection for LLM CLIs

`masqr` is a transparent HTTP proxy that sits between an LLM CLI (claude, gemini, codex, …) and the upstream API. Every request is parsed, scanned for secrets / PII / attachments / OCR'd image content, logged in full, and **blocked with HTTP 451** if anything trips. The CLI sees a normal API error and tells you what leaked — you fix the prompt and retry.

```
 ▟█▙ ▟█▙   masqr  · deep prompt inspection [google-gemini]
 ▜█▄▄▄█▛   http://127.0.0.1:38219 → https://generativelanguage.googleapis.com
  ▘   ▘    log: masqr-20260518-093142.log
```

---

## Quick start

```bash
go build -o masqr .

./masqr claude                          # Claude Code (Anthropic)
./masqr gemini -p "summarize file.txt"  # Gemini CLI (Google)
./masqr codex                           # Codex CLI (OpenAI)
./masqr --block-on=high claude          # loosen: only block ≥ high
```

Masqr starts an HTTP listener on a random local port, exports it via the right `*_BASE_URL` env var for the child process (auto-detected from the command name — see [Provider profiles](#provider-profiles)), and PTY-attaches the child so you interact with it normally. When the child exits, masqr shuts down cleanly.

### Provider profiles

Masqr auto-detects the provider from the child command's basename and applies a built-in profile (upstream URL, env-var name, auth-header redaction set, query-param redaction set, and a CLI-native block-response shape). Explicit `--target` / `--env` always win.

| Command | Provider | Upstream(s) | Env var(s) injected | Auth header redacted | Auth query redacted |
|---|---|---|---|---|---|
| `claude`, `claude-code` | `anthropic` | `https://api.anthropic.com` | `ANTHROPIC_BASE_URL` | `x-api-key`, `anthropic-api-key`, `authorization` | — |
| `gemini`, `gemini-cli` | `google-gemini` | `https://generativelanguage.googleapis.com` <br/>`/v1internal*` → `https://cloudcode-pa.googleapis.com` | `GOOGLE_GEMINI_BASE_URL`, `CODE_ASSIST_ENDPOINT` | `x-goog-api-key`, `authorization` | `key`, `api_key`, `apikey`, `access_token` |
| `codex`, `openai` | `openai` | `https://api.openai.com` | `OPENAI_BASE_URL` | `authorization`, `openai-organization`, `openai-project` | — |
| anything else | `generic` | from `--target` | from `--env` (default `ANTHROPIC_BASE_URL`) | universal set | universal set |

**Gemini has two network paths.** The `@google/genai` SDK (API-key mode, set via `GEMINI_API_KEY`) talks to `generativelanguage.googleapis.com` and honours `GOOGLE_GEMINI_BASE_URL`. The OAuth `CodeAssistServer` path (free tier "Signed in with Google /auth", Code Assist for individuals, Google One AI Pro) talks to `cloudcode-pa.googleapis.com/v1internal…` and honours **only** `CODE_ASSIST_ENDPOINT`. The `gemini` profile exports both env vars to a single masqr listener and routes per-request based on URL path, so both auth modes are intercepted off one `masqr gemini` invocation — no special configuration needed.

For Gemini specifically, masqr also **scans the request URL alongside the body**, so a key smuggled into `?key=AIza…` is flagged and blocked just like one in the prompt — and the log line redacts it before it ever hits disk.

To route an unknown CLI through masqr explicitly:

```bash
./masqr --target https://api.together.xyz --env TOGETHER_BASE_URL my-other-cli
```

---

## What gets caught

Three layers run on every request body, in parallel:

| Source | What it finds |
|---|---|
| **Built-in rules** (`rules.go`) | 40+ hand-tuned regexes for AWS / GCP / Azure / Anthropic / OpenAI / Stripe / Slack / GitHub / GitLab tokens, JWTs, PEM keys, Swiss AHV / UID / IBAN, credit cards (Luhn-validated), private IPv4/v6, emails, attachments (image/PDF/audio/video/file refs), generic high-entropy base64 blobs |
| **gitleaks** (`sources_gitleaks.go`) | Full gitleaks v8 default ruleset (every match tagged `gitleaks:<rule>`) |
| **Aho-Corasick keywords** (`sources_keywords.go`) | A user-supplied `<keyword>|<TYPE>` wordlist (typically names, internal hostnames, project codenames). Auto-discovered or set via `-k` / `MASQR_KEYWORDS` |
| **PaddleOCR** (`sources_ocr.go`, opt-in) | Extracts text from inline images and re-feeds it through the rule engine, catching secrets pasted as screenshots |

**Obfuscation handling**
- Any high-entropy base64 blob (≥ 24 chars, tiered Shannon-entropy floor) gets decoded once and re-scanned, so `echo $AWS_KEY | base64` still trips. Decode-and-rescan depth is capped at 1 to avoid base64-of-base64 ratholes.
- JSON-escape artifacts (`\ntest@example.com` in raw bodies) are stripped before snippet extraction so reports show the real value, not the `n` from `\n`.

**Severity tiers**: `critical · high · medium · low`. Every match is graded; the threshold for blocking is configurable.

---

## CLI

```
usage: masqr [flags] <command> [args...]

examples: masqr claude --resume
          masqr gemini -p 'summarize this'
          masqr -a :8080 -l /tmp/c.log claude
          masqr -k ./keywords.txt --block-on=critical claude

flags:
  -a, --addr string             HTTP listen address              (default 127.0.0.1:0)
      --block-on string         severity floor for blocking      (default low)
                                  one of: critical|high|medium|low
  -e, --env string              env var to expose proxy URL      (provider-profile default; overrides profile)
  -k, --keywords string         path to <keyword>|<TYPE> wordlist
  -l, --log string              session log file                 (default masqr-<ts>.log)
      --shutdown-grace duration HTTP graceful shutdown            (default 5s)
  -t, --target string           upstream API                     (provider-profile default; overrides profile)

built-in providers: anthropic, google-gemini, openai
  detected automatically from the child command name.
```

Positional args after the flags are passed straight to the child CLI — no `--` separator needed. Flags are POSIX (short `-x`, long `--xxx`), same as claude/gemini/codex.

---

## How blocking works

When at least one match has severity ≥ `--block-on` (default `low` → any finding), masqr short-circuits before forwarding and returns:

```http
HTTP/1.1 451 Unavailable For Legal Reasons
Content-Type: application/json
X-Masqr-Blocked: 1

{
  "type": "error",
  "error": {
    "type": "masqr_blocked",
    "message": "masqr blocked the request: detected aws-access-key-id. To proceed: edit the prompt or raise --block-on.",
    "findings": [
      {
        "rule_id": "aws-access-key-id",
        "category": "secret",
        "severity": "critical",
        "snippet": "AKIA••••••••••••MPLE",
        "offset": 42
      }
    ]
  }
}
```

The envelope shape **adapts to the active provider** so each CLI surfaces the block reason through its own error renderer:

| Provider | Body shape |
|---|---|
| `anthropic` (default) | `{"type":"error","error":{"type":"masqr_blocked","message":…,"findings":[…]}}` — mirrors Anthropic's error envelope |
| `google-gemini` | `{"error":{"code":451,"message":…,"status":"FAILED_PRECONDITION","details":[{"@type":"type.googleapis.com/masqr.BlockedRequest","findings":[…]}]}}` — `google.rpc.Status` shape parsed natively by `@google/genai` |
| `openai` | `{"error":{"message":…,"type":"masqr_blocked","code":"masqr_blocked","findings":[…]}}` — OpenAI's error envelope |

Upstream is never contacted; nothing leaks.

To loosen: `--block-on=high` (only high+critical block), `--block-on=critical` (only critical blocks). The `low` default is the safest — every finding gets a chance to be a human-in-the-loop decision.

---

## Architecture

```
  ┌────────────┐    stdin/stdout (PTY)     ┌──────────┐
  │  terminal  │ ◄────────────────────────►│  claude  │
  └────────────┘                           └────┬─────┘
                                                │ HTTPS
                                                ▼
                                       ANTHROPIC_BASE_URL=http://127.0.0.1:38219
                                                │
                       ┌────────────────────────▼───────────────────────────┐
                       │                       masqr                         │
                       │                                                    │
                       │  buffer body → scan ───────────────────┐           │
                       │                                        ▼           │
                       │                              ┌──── parallel ────┐  │
                       │                              │ built-in rules   │  │
                       │                              │ gitleaks         │  │
                       │                              │ aho-corasick     │  │
                       │                              │ PaddleOCR        │  │
                       │                              └────────┬─────────┘  │
                       │                                       ▼            │
                       │                              dedupe + threshold    │
                       │                                       │            │
                       │                            ┌──────────┴─────────┐  │
                       │                            ▼                    ▼  │
                       │                  HTTP 451 + JSON       reverse-proxy to upstream
                       │                  (X-Masqr-Blocked:1)              │
                       └──────────────────────────────────────────────────┘
                                                                          │
                                                                          ▼
                                                              https://api.anthropic.com
```

**One Go binary, three goroutines** (managed by `errgroup`):
1. `http.Server` on the loopback listener
2. SIGINT/SIGTERM watcher → triggers graceful shutdown
3. `runCLI` — `exec` the child under a PTY, raw-mode the parent stdin, pipe both directions, handle SIGWINCH for terminal resize

The proxy itself is `httputil.NewSingleHostReverseProxy` with custom `Director` (rewrites `Host`), `ModifyResponse` (logs the response), and `ErrorHandler`. SSE (`text/event-stream`) and Anthropic's `application/vnd.anthropic.stream+json` are pass-through — never buffered.

---

## Files

| File | Role |
|---|---|
| `main.go` | flag parsing, provider auto-detection, signal handling, PTY plumbing, errgroup lifecycle |
| `providers.go` | built-in profile registry (Anthropic/Gemini/OpenAI), basename-based auto-detect |
| `server.go` | reverse proxy, request/response logging, URL key redaction, response decompression (gzip/deflate/brotli/zstd) |
| `policy.go` | block-or-forward decision, HTTP 451 writer, per-provider error envelope (Anthropic / Google / OpenAI) |
| `scanner.go` | orchestration: Aho-Corasick prefilter → per-rule regex → parallel external sources → base64 decode-rescan → dedupe |
| `rules.go` | core built-in rule definitions (secrets, Swiss PII, generic) |
| `rules_presidio.go` | Presidio-derived rules that benefit from keyword anchoring (BTC bech32, generic IBAN, DE VAT, FI HETU) |
| `validators.go` | Luhn, IBAN Mod-97, AHV Mod-10, UID Mod-11, JSON-escape boundary fixup |
| `validators_presidio.go` | ~24 Presidio-derived validators (Verhoeff, NHS Mod-11, PESEL Mod-10, NIF Mod-23, TCKN NVI, ABN Mod-89, NPI/CMS Luhn, DEA split-sum, …) |
| `base64.go` | Shannon entropy, tiered base64 detection, multi-dialect decode, printable-content filter |
| `sources_digit_ids.go` | one regex → ~18 digit-only Presidio recognizers via shared validator dispatch |
| `sources_alnum_ids.go` | one regex → ~22 letter-bearing Presidio recognizers (with dash-aware token normalization) |
| `sources_gitleaks.go` | wraps `zricethezav/gitleaks/v8` |
| `sources_keywords.go` | Aho-Corasick over a user wordlist (`BobuSumisu/aho-corasick`) |
| `sources_ocr.go` | PaddleOCR PP-OCRv5 (det → cls → rec) pipeline via `yalue/onnxruntime_go` |
| `banner.go` | crimson→gold gradient banner |
| `demo/main.go` | log replayer + live tailer for showing what masqr caught |

---

## Environment

| Variable | Effect |
|---|---|
| `ANTHROPIC_BASE_URL` / `GOOGLE_GEMINI_BASE_URL` / `OPENAI_BASE_URL` | the provider profile picks the right one based on the child command name; override with `-e VAR` for unrecognised CLIs |
| `MASQR_KEYWORDS` | path to a `<keyword>|<TYPE>` wordlist (overridden by `-k`) |
| `MASQR_OCR=1` | enables the PaddleOCR source (runtime + models are embedded in the binary; no extra files required) |
| `MASQR_ONNX_LIB` | override path to `libonnxruntime.so` — by default the bundled runtime is extracted to a temp file |
| `MASQR_OCR_DET` | override path to a custom PaddleOCR detection ONNX model |
| `MASQR_OCR_REC` | override path to a custom PaddleOCR recognition ONNX model |
| `MASQR_OCR_CLS` | override path to a custom PaddleOCR angle-classifier ONNX model |
| `MASQR_OCR_VOCAB` | override path to a custom recognition vocab file |
| `MASQR_OCR_WORKERS` | number of OCR session triples to pre-allocate (default `2`); each worker is ~25 MB RAM |
| `MASQR_OCR_DEBUG=1` | dump per-box detection/recognition diagnostics into the session log |

### Platform support

masqr ships with a bundled ONNX Runtime + PP-OCRv5 model set for each platform below. Pre-built release binaries are single-file and self-contained on these targets:

| OS / arch | ONNX Runtime | OCR | Notes |
|---|---|---|---|
| linux / amd64 | ✓ | ✓ | primary target |
| linux / arm64 | ✓ | ✓ | Raspberry Pi 4+, AWS Graviton, ARM servers |
| darwin / arm64 | ✓ | ✓ | Apple Silicon (M1/M2/M3/M4) |
| windows / amd64 | ✓ | ✓ | standard Windows |
| windows / arm64 | ✓ | ✓ | Surface Pro X, Copilot+ PCs |
| darwin / amd64 | — | — | Intel Mac (Microsoft dropped osx-x86_64 builds in ORT 1.26) |
| everything else | — | — | proxy + rule engines still work; OCR is a no-op with a startup warning |

If you set `MASQR_OCR=1` on a non-supported platform, masqr logs a warning at startup and skips the OCR stage. The proxy itself, gitleaks, the built-in rules, and the keyword scanner continue to work on every platform Go supports.

---

## Demo tool

`demo/main.go` is a separate command that replays a masqr log with color and pacing — useful for showing what masqr caught during a session.

```bash
go run ./demo masqr-20260518-093142.log               # step through, space=next, q=quit
go run ./demo --auto 2s masqr.log                     # auto-advance every 2s, then tail forever
go run ./demo --only-alerts masqr.log                 # skip clean scenes
go run ./demo --follow=false masqr.log                # one-shot replay, no tailing
```

`--follow` is on by default. After the existing backlog is rendered, the demo keeps polling the file and renders each new scene (request + alerts + verdict) the moment masqr writes it. Ctrl-C exits.

Each scene shows:
- the method + URL + content-type
- a truncated body preview
- color-coded findings (`[critical]` red · `[high]` orange · `[medium]` gold · `[low]` blue) with rule ID, offset, redacted snippet
- a verdict badge: red **MASQR BLOCKED** (HTTP 451, upstream never contacted) or green **FORWARDED → 200**

---

## Built-in rule catalog

**Secrets (critical/high)** — AWS access key & secret, GitHub PAT (classic & fine-grained), Anthropic, OpenAI, Stripe live, Slack bot/user/webhook, JWT, PEM private keys, GCP API key & service account & OAuth client ID, Azure storage conn-string / account key, Azure Service Bus / Cosmos / SQL conn-strings, GitLab (9 token formats: pat, oauth, pipeline-trigger, runner, deploy, feed, agent, scim, ci-job)

**PII — universal** — emails (with JSON-escape boundary fixup), credit cards (Luhn), Bitcoin (bech32 + legacy base58), IBAN (any country, Mod-97 validated)

**PII — country-tagged** — every match below carries a `pii-<cc>` category so block-policy can target one jurisdiction at a time. Patterns derive from [Microsoft Presidio](https://github.com/microsoft/presidio); checksums are clean-room transcriptions of the published `validate_result` hooks (no AGPL / GPL code imported).

| Jurisdiction | Identifiers |
|---|---|
| Switzerland (`pii-ch`) | AHV / AVS (Mod-10), UID (Mod-11), IBAN (Mod-97), Postfinance |
| United States (`pii-us`) | SSN (structural + famous-fake list), ITIN, NPI (Luhn with `80840` prefix), ABA routing (Mod-10 weighted), Passport book, MBI (dashed + undashed), DEA Certificate (split-sum) |
| Canada (`pii-ca`) | SIN (Luhn) |
| United Kingdom (`pii-uk`) | NHS number (Mod-11), NINO, Passport, Driving Licence |
| Australia (`pii-au`) | TFN (Mod-11), ACN (Mod-10), ABN (Mod-89), Medicare card |
| Germany (`pii-de`) | Steuer-ID (ISO 7064 Mod-11,10), USt-IdNr / VAT, Personalausweis / Reisepass, KVNR, Rentenversicherungsnummer |
| Italy (`pii-it`) | Codice fiscale (omocode), Partita IVA (Luhn variant), Patente, Carta d'identità |
| Spain (`pii-es`) | NIF / DNI (Mod-23 letter), NIE, Passport |
| India (`pii-in`) | Aadhaar (Verhoeff + non-palindrome), PAN, Passport, Voter EPIC, GSTIN |
| Singapore (`pii-sg`) | NRIC / FIN (IRAS letter, S/T/F/G/M prefixes), UEN |
| Korea (`pii-kr`) | RRN (Mod-11 — pre-Oct-2020), Passport |
| Poland (`pii-pl`) | PESEL (date + Mod-10) |
| Turkey (`pii-tr`) | TCKN (two-digit NVI check) |
| Thailand (`pii-th`) | TNIN (Mod-11) |
| Sweden (`pii-se`) | Personnummer (10/12-digit, samordningsnummer-aware), Organisationsnummer |
| Finland (`pii-fi`) | HETU (date + 31-entry control character) |

**Network** — private IPv4 (RFC 1918 + loopback + link-local), private IPv6 (ULA + loopback + link-local)

**Attachments** — inline image / PDF / audio / video data URIs, file references, document blocks, URL sources

**Generic** — high-entropy base64 blobs (≥ 24 chars, tiered entropy floor)

Each match is reported with a **redacted snippet** (first 4 + ≤16 bullets + last 4 chars) — the original value never appears in the log or in the 451 response body.

### How country-tagged rules stay fast

Naively adding ~40 country-specific rules would mean one full-body regex pass per rule. Instead, every numeric identifier (SSN, NPI, ABA, TFN, ACN, ABN, Medicare, SIN, NHS, PESEL, RRN, TCKN, TNIN, IT-VAT, DE-Tax-ID, Aadhaar, SE-personnummer, SE-orgnummer) is dispatched from a **single regex** that finds digit clusters; per-cluster, a cheap algorithmic validator (Luhn, Verhoeff, Mod-11 weighted, etc.) decides which rules fire. The same trick consolidates the letter-bearing IDs (US passport / MBI / DEA, UK NINO / passport / driving licence, DE id card / health / SSN, IT fiscal code, ES NIF / NIE, IN PAN / GSTIN, SG NRIC / UEN, KR passport) behind another single broad scan. Net: adding Presidio's full library costs ~2 full-body regex passes, not ~40.

The keyword prefilter is a literal-set Aho-Corasick trie (`BobuSumisu/aho-corasick`); the body is ASCII-lowercased once per scan so the trie stays case-sensitive. Replacing the prior `(?i)`-flagged RE2 alternation cut scan time on no-hit prose bodies by roughly 3–6× on ARM64.

---

## Logging

One log file per session, named `masqr-<YYYYMMDD-HHMMSS>.log` in the cwd (override with `-l`). Format:

```
2026/05/18 08:17:29.485612
--- [#1] REQUEST POST /v1/messages ---
Content-Type: application/json
... headers ...

<full body, decompressed if encoded>

--- [#1] ALERTS (3) ---
  [critical/secret] aws-access-key-id @42 : AKIA••••••••••••MPLE
  [high/pii-card] credit-card @120 : 4532••••••••0366
  [medium/pii] email-address @200 : test••••••••.com

2026/05/18 08:17:29.486023 [#1] BLOCKED by policy (3 finding(s) >= low)
```

Sensitive headers (`Authorization`, `X-Api-Key`, `Anthropic-Api-Key`, `X-Goog-Api-Key`, `Cookie`, `Set-Cookie`, OpenAI org/project IDs) are written as `<redacted>`. Auth-bearing query parameters in the request URL (`key=`, `api_key=`, `apikey=`, `access_token=`, `token=`, `auth=`) are likewise redacted in the log line — the **request to upstream is unchanged**; redaction is purely log-side. Responses are decompressed before logging (gzip / deflate / brotli / zstd) but forwarded to the client in their original encoding — the wire bytes are never touched.

---

## Testing

```bash
go test ./...           # unit + integration tests (75+)
go vet ./...
```

Coverage includes: every built-in rule firing on a synthetic payload, validator checksums (Luhn, IBAN Mod-97, AHV Mod-10, UID Mod-11), base64 detection / decode / rescan, attachment patterns, keyword Aho-Corasick offset regression, gitleaks integration, multi-source orchestration with body cap & parallel-safety, policy block path (HTTP 451 + structured body + threshold filtering), per-provider error envelopes (Anthropic / Google `rpc.Status` / OpenAI), per-path upstream routing (`/v1internal` → Code Assist vs. `/v1beta` → public Gemini), JSON-escape prefix fixup, email rule edge cases.

### End-to-end Gemini + rule-catalog test

```bash
# Gemini
scripts/test-gemini-e2e.sh                    # all phases (A..E)            ~37s
scripts/test-gemini-e2e.sh --no-live          # skip live Gemini calls       ~12s

# Claude Code (same phases B–E; different Phase A)
scripts/test-claude-e2e.sh                    # all phases (A..E)            ~40s
scripts/test-claude-e2e.sh --no-live          # skip live Claude calls       ~15s

# Codex (same phases B–E; Phase A uses `codex exec` + `-c openai_base_url=…`)
scripts/test-codex-e2e.sh                     # all phases (A..E)            ~45s
scripts/test-codex-e2e.sh --no-live           # skip live Codex calls        ~15s

# Any provider script
scripts/test-gemini-e2e.sh --only=catalog     # rule catalog only            ~2s
scripts/test-claude-e2e.sh --only=ocr         # OCR phase only               ~2s
scripts/test-claude-e2e.sh --only=screenshots # OS-styled screenshot OCR     ~10s
scripts/test-claude-e2e.sh --keep-logs        # retain .e2e-logs/ on success
scripts/test-claude-e2e.sh --rebuild          # `go build -o masqr .` first
```

Phases B–E are shared (`scripts/e2e-common.sh`). Each provider wrapper adds Phase A: live CLI smoke against the real binary. Five independent phases; **82** scenarios without live CLI, **84–85** with live CLI depending on provider (Codex skips one forward scenario — see below). OCR runs unconditionally — `MASQR_OCR=1` is set by the script when it spawns the proxy, and every image used is either a 1574-byte PNG embedded in the script itself (Phase D) or a committed PNG under `testdata/screenshots/` (Phase E). The suite has zero runtime image dependencies (no ImageMagick, no Pillow at run time, no font hunt):

| Phase | What it asserts | Scenarios | Wall time | Needs |
|---|---|---|---|---|
| **A. Live CLI** | `masqr <cli> … "<prompt>"` blocks on critical/low findings and (where supported) forwards a clean prompt. **Gemini:** every log must contain `/v1internal:*` (OAuth Code Assist path). **Claude:** every log must contain `POST /v1/messages` (Anthropic Messages API). **Codex:** `codex -c openai_base_url=http://127.0.0.1:<port> exec …` (ChatGPT-auth Codex ignores `OPENAI_BASE_URL`); every log must contain `POST /responses`; requests are zstd-compressed and masqr decodes them for scanning only. Codex **skips** the clean-forward scenario because session UUIDs in the JSON body trip `gitleaks:generic-api-key` at critical. | 2–3 | ~15–25 s | `gemini`, `claude`, or `codex` CLI + credentials |
| **B. Rule catalog** | Every built-in rule fires on its canonical payload (25 secret formats, 5 universal PII, 36 country-tagged PII, 2 network, 3 attachment rules) via real HTTP through the proxy | 71 | ~2 s | python3 (stdlib) |
| **C. Base64 obfuscation** | A secret wrapped in `base64` still trips the originating rule (decode-and-rescan pass) | 3 | ~1 s | python3 |
| **D. PaddleOCR** | An AWS key rendered onto an embedded PNG, posted as a data-URI attachment, is recovered by the OCR pipeline and tripped via the `/from-image` source tag | 2 | ~2 s | none (PNG bytes inlined, `MASQR_OCR=1` set automatically) |
| **E. OS-screenshot OCR** | Five OS-styled mock screenshots (Windows Notepad / macOS Terminal / GNOME Terminal / Android Messages / iOS Notes) each containing a canonical test-vector secret are recovered from the rendered chrome + body and trip the expected `/from-image` rule | 5 | ~10 s | none at run time (PNGs are committed under `testdata/screenshots/`) |

Phase E PNGs are rendered with each OS's real system font: Cascadia Mono + Inter (Windows, the actual Windows Terminal / Notepad chrome), SF Pro Display + SF Mono (macOS / iOS, extracted from Apple's free [SF Pro DMG](https://developer.apple.com/fonts/) — `scripts/install-os-fonts.sh` automates this), Cantarell + DejaVu Sans Mono (GNOME 45+), and Roboto (Android since Ice Cream Sandwich). Where SF Pro/Mono aren't installed the generator falls back to Inter + JetBrains Mono — both OFL-licensed and explicitly designed as drop-in SF substitutes — so regenerating the screenshots works on a stock Debian/Ubuntu host with just `apt install fonts-inter fonts-roboto fonts-cantarell fonts-cascadia-code fonts-jetbrains-mono`. Regenerate with `scripts/generate-screenshots.py` after font upgrades or visual-style changes.

Phase E additionally fetches a small corpus of real-world test screenshots from sibling open-source projects (currently Microsoft Presidio's MIT-licensed PII test images under `testdata/screenshots/external/`). These are intentionally synthetic (fictional names, reserved-range phone numbers, `@microsoft.com` test addresses) — masqr's E2E intentionally never ingests real leaked screenshots, even publicly-leaked ones, to avoid re-distributing other people's PII or burnt credentials. See [`testdata/screenshots/external/README.md`](testdata/screenshots/external/README.md) for provenance, SHA-256s, and per-image notes on which masqr rules each one exercises.

The catalog and base64 phases stand up masqr as a long-running proxy (with `sleep 86400` as the child) plus a Python HTTP sink as the upstream, then curl-drive synthetic POSTs. This catches the same regressions the Go suite catches, but at the HTTP-boundary level — proving the scanner-to-proxy path itself works, not just the in-memory rule engine. Phase A's universal precondition is provider-specific: Gemini requires at least one `/v1internal:*` request (OAuth traffic must hit `cloudcode-pa.googleapis.com`, not bypass via the public Gemini API alone). Claude requires at least one `/v1/messages` request (traffic must flow through `ANTHROPIC_BASE_URL`, not directly to `api.anthropic.com`). Codex requires at least one `POST /responses` (traffic must hit `openai_base_url` via `-c`, not the default OpenAI host).

---

## Known limitations

- **OCR recognition** is PP-OCRv5 ONNX with the angle classifier wired in (det → cls → rec). Per-character error is ~2–5% on clean screenshots, higher on noisy ones. Mitigated for patterns with strict prefixes (`AKIA…`, `ghp_…`) but a noisy screenshot of a long random secret may slip through.
- **Base64 detection** only catches the standard alphabet (`+/`); URL-safe (`-_`) without padding gets a smaller window via decode-fallback but isn't anchored by the pattern.
- **Body cap**: 2 MiB. Past that, the scanner only sees the first 2 MiB. The full body is still logged and forwarded.
- **External sources**: gitleaks / keywords / OCR are all optional. If a source fails to initialize (missing model, malformed wordlist), it's logged once and the rest keep working.
- **TLS interception** is not in scope. The child must trust whatever the proxy presents on `ANTHROPIC_BASE_URL` (an HTTP URL by default; if you front masqr with HTTPS you handle the cert).

---

## License

masqr is released under the **Apache License 2.0** — see [`LICENSE`](LICENSE).

The binary bundles two third-party components, each shipped under its upstream licence:

| Component | Origin | Licence |
|---|---|---|
| `libonnxruntime.so.1.26.0` | [Microsoft ONNX Runtime](https://github.com/microsoft/onnxruntime) | MIT — [`LICENSES/LICENSE-onnxruntime.txt`](LICENSES/LICENSE-onnxruntime.txt) |
| PP-OCRv5 `det.onnx` / `cls.onnx` / `rec.onnx` + `ppocr_keys_v1.txt` | [PaddleOCR](https://github.com/PaddlePaddle/PaddleOCR), re-exported by [OnnxOCR](https://github.com/jingsongliujing/OnnxOCR) | Apache-2.0 — [`LICENSES/LICENSE-paddleocr.txt`](LICENSES/LICENSE-paddleocr.txt) |

See [`NOTICE`](NOTICE) for the full attribution required by Apache-2.0 §4(d).
