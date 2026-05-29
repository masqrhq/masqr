# Changelog

All notable changes to **masqr** will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added
- **Gemini CLI (and OpenAI/codex) first-class support.** New `providers.go` carries built-in profiles (upstream URL, env-var name(s), auth-header redaction set, auth-query redaction set, optional per-path route table). `masqr gemini` Just Works — no `--target` / `--env` needed. Explicit flags still override the profile so corporate proxies / LiteLLM-style routers keep working.
  - **Provider auto-detection** by basename of the child command. Both `/` and `\` are honoured as path separators so npm-installed and system-installed CLIs both resolve. Recognised: `claude`, `claude-code`, `gemini`, `gemini-cli`, `codex`, `openai`.
  - **Per-request upstream routing.** A new `Provider.Routes` table lets one profile cover multiple upstream hosts, dispatched by URL path prefix. The proxy moved from `httputil.NewSingleHostReverseProxy` to a `Rewrite`-based `httputil.ReverseProxy`; per request, the first matching prefix wins, otherwise the primary `Target` is used.
  - **Gemini OAuth (free tier "Signed in with Google") now works.** The CLI has two completely independent network paths: the `@google/genai` SDK (API-key mode) hits `generativelanguage.googleapis.com` and honours `GOOGLE_GEMINI_BASE_URL`; the `CodeAssistServer` (OAuth / Code Assist for individuals / Google One AI Pro) hits `cloudcode-pa.googleapis.com/v1internal…` and honours **only** `CODE_ASSIST_ENDPOINT`. Previous versions of masqr only redirected the SDK path, so OAuth users' traffic silently bypassed the proxy. The Gemini profile now exports both env vars to the same masqr listener and dispatches `/v1internal*` to Code Assist while letting `/v1beta*` fall through to the public Gemini API — both auth modes intercepted from one invocation.
  - **Multi-env-var injection.** `--env` (and `Provider.EnvVars`) became a list. A single `masqr gemini` exec adds two env vars to the child; future providers can ship as many as the upstream CLI consults. `-e VAR1,VAR2` and `-e VAR1 -e VAR2` are both accepted.
  - **Provider-aware block envelope.** A blocked request now returns the body shape the upstream CLI expects: Anthropic's `{"type":"error",…}` for Claude, `google.rpc.Status` for Gemini (`@google/genai` parses this natively), OpenAI's `{"error":{…,"code":"masqr_blocked"}}` for codex. HTTP 451 + `X-Masqr-Blocked: 1` are unchanged across all three.
  - **URL scanning + URL redaction.** The scanner now sees the request URI alongside the body, so a key smuggled in `?key=AIza…` is flagged and blocked just like one in the prompt. The log line redacts every value of `key`, `api_key`, `apikey`, `access_token`, `token`, `auth` before writing — the request to upstream is **byte-for-byte unchanged**, redaction is purely log-side.
  - **`x-goog-api-key` (+ `openai-organization`, `openai-project`) added to the redaction header set.** New providers automatically contribute to the global set, so adding a fourth profile in `providers.go` can never accidentally leak its key.
  - **Banner now shows the active provider** as `[google-gemini]` (or `[anthropic]`, `[openai]`) and, when the profile carries Routes, an extra line like `+ /v1internal → https://cloudcode-pa.googleapis.com` so the secondary upstream isn't invisible.
- **Claude Code E2E harness** at `scripts/test-claude-e2e.sh`. Mirrors the Gemini suite: Phase A drives `./masqr claude -p "<prompt>"` with three live scenarios (AWS key block, email block, clean forward) and asserts every session log contains `POST /v1/messages` (Anthropic API regression guard). Phases B–E are shared with Gemini via `scripts/e2e-common.sh` (82 scenarios, ~15 s without live CLI).
- **Codex E2E harness** at `scripts/test-codex-e2e.sh`. Same phases B–E; Phase A drives `./masqr -a 127.0.0.1:<port> codex -c openai_base_url=http://127.0.0.1:<port> exec --dangerously-bypass-approvals-and-sandbox "<prompt>"` with stdin closed (`</dev/null`). Asserts `POST /responses` in every session log (OpenAI Responses API regression guard). Two live block scenarios (AWS key, email); clean-forward is skipped because Codex session UUIDs in the request body trip `gitleaks:generic-api-key` at critical. masqr decodes `Content-Encoding: zstd` on requests for scanning only (wire bytes forwarded unchanged).
- **End-to-end test harness** at `scripts/test-gemini-e2e.sh` (refactored to source `scripts/e2e-common.sh` for phases B–E). Five independent phases, 84 scenarios, ~37s wall: (A) live Gemini CLI scenarios that drive `./masqr gemini -p "<prompt>"` and assert both the CLI exit code and that at least one `/v1internal:*` call appears in the log (the OAuth-routing regression guard); (B) 71 catalog scenarios that stand up masqr + a Python HTTP sink and curl-drive synthetic POSTs covering every secret type (AWS, GitHub, Anthropic, OpenAI, Stripe, JWT, PEM, GCP, Azure ×4, GitLab ×9, Slack ×2), universal PII (email, credit card, Bitcoin, IBAN), country-tagged PII (CH/US/CA/UK/AU/DE/IT/ES/IN/SG/KR/PL/TR/TH/SE/FI ~36 identifiers), network (private IPv4/IPv6), and attachment patterns; (C) base64-obfuscation scenarios proving the decode-and-rescan pass still flags wrapped secrets; (D) **always-on PaddleOCR scenario** — a 1574-byte PNG rendering `AKIAIOSFODNN7EXAMPLE` is embedded directly in the script (no ImageMagick / Pillow / font hunt required), `MASQR_OCR=1` is forced on internally, and the test asserts the `/from-image` source recovers + flags the key; (E) **OS-styled screenshot OCR** — five mock screenshots (Windows Notepad / macOS Terminal / Linux GNOME Terminal / Android Messages / iOS Notes), generated by `scripts/generate-screenshots.py` and committed under `testdata/screenshots/`, each containing a canonical test-vector secret rendered at a font size + canvas dimension picked to land inside PP-OCRv5's 320 px rec-input window — exercise OCR-on-real-world-chrome (window decorations, status bars, mixed-color terminal output) and the `/from-image` source tag. `--no-live`, `--only=<phase>`, `--keep-logs`, `--rebuild`, `--verbose` flags. Auto-heals architecture mismatches (rebuilds when the on-disk binary's ELF `e_machine` doesn't match `uname -m`).
- **External real-world screenshot corpus** at `testdata/screenshots/external/`. Two intentionally-synthetic PII test images sourced from Microsoft Presidio (MIT-licensed, committed verbatim with SHA-256 and full attribution) extend Phase E with non-mock content: `presidio-pii_verify.png` is asserted to trip `email-address/from-image` on `opencode@microsoft.com`; `presidio-ocr_test.png` is committed as a sample-only manual fixture to document a known wide-line OCR recall limitation (PaddleOCR PP-OCRv5's `recInputW=320` squashes >24-char single-line crops, causing the same email to be missed on the un-annotated image). The harness explicitly does not fetch real leaked screenshots from the wild — re-distributing other people's PII or burnt credentials is not a tradeoff masqr's test corpus makes. See `testdata/screenshots/external/README.md` for the full rationale.
- **Phase E screenshots now use each OS's real system font.** Windows mockups render in Cascadia Mono + Inter (the actual Windows Terminal / modern Notepad mono and a community-accepted Segoe UI metric substitute — Microsoft's open-source Selawik never shipped as a binary TTF, only source UFOs); macOS + iOS use Apple's SF Pro Display + SF Mono (downloaded from Apple's free [SF Pro DMG](https://developer.apple.com/fonts/) into `/usr/local/share/fonts/sf-fonts/`, with Inter + JetBrains Mono — both OFL-licensed, both explicitly designed as SF substitutes — as fallback when the Apple set isn't installed); GNOME renders in Cantarell + DejaVu Sans Mono (the actual GNOME shell + Debian/Ubuntu GNOME-Terminal defaults); Android uses Roboto (the system font since Ice Cream Sandwich). New `scripts/install-os-fonts.sh` automates the apt install + Apple DMG unpack on a stock Debian/Ubuntu host. The Pillow `_font()` helper became a documented per-OS palette (`FONT_PALETTE`) so a missing TTF now fails fast with a clear apt-install hint instead of silently falling back to Pillow's unreadable 10 px bitmap default. Icon-class glyphs (back arrow, kebab menu, send button, status-bar signal/wifi/battery) are now drawn as Pillow primitives because Roboto / Inter / Cantarell lack the Unicode code points Material Symbols / SF Symbols supply on a real device — visually identical, font-independent.
- **Microsoft Presidio rule set.** ~40 new recognizers across 16 jurisdictions, ported as clean-room regex + checksum transcriptions of `microsoft/presidio`'s `predefined_recognizers` tree (no AGPL / GPL code imported).
  - **Generic:** Bitcoin (bech32 + legacy base58), IBAN (any ISO 3166-1 country, Mod-97 validated, severity tier below `ch-iban` so the country-specific match wins dedupe).
  - **United States:** SSN (area / group / serial structural rules + famous-fake list), ITIN, NPI (Luhn with 80840 prefix per CMS), ABA routing (Mod-10 weighted), Passport book (letter + 8 digits), MBI (CMS 11-char format, both dashed and undashed), DEA Certificate (Mod-10 split-sum).
  - **Canada:** SIN (Luhn).
  - **United Kingdom:** NHS number (Mod-11), NINO, Passport, Driving Licence (16-char DVLA format).
  - **Australia:** TFN (Mod-11), ACN (Mod-10), ABN (Mod-89), Medicare card (Mod-10).
  - **Germany:** Steuer-ID (ISO 7064 Mod-11,10 with the post-2016 ≤3-repeats rule), USt-IdNr (VAT), Personalausweis / Reisepass body, Krankenversicherung (KVNR), Rentenversicherungsnummer.
  - **Italy:** Codice fiscale (16-char omocode form), Partita IVA (11-digit Luhn variant), Patente di guida, Carta d'identità.
  - **Spain:** NIF / DNI (Mod-23 letter), NIE (X/Y/Z prefix mapping + NIF letter), Passport.
  - **India:** Aadhaar (Verhoeff + non-palindrome + leading-≥2 guard), PAN, Passport, Voter EPIC, GSTIN.
  - **Singapore:** NRIC / FIN (IRAS check-letter algorithm, all 5 prefixes including post-2022 `M`), UEN.
  - **Korea:** RRN (Mod-11 — pre-October-2020 numbering), Passport.
  - **Poland:** PESEL (embedded-date sanity + Mod-10 weighted).
  - **Turkey:** TCKN (NVI two-digit check).
  - **Thailand:** TNIN (Mod-11).
  - **Sweden:** Personnummer (10/12-digit forms, samordningsnummer-aware), Organisationsnummer.
  - **Finland:** Henkilötunnus / HETU (date sanity + 31-entry control-character lookup; accepts `+`, `-`, post-2023 `A-F` / `Y-X-W-V-U` century separators).
- **Two new consolidating scan sources** (architectural change, no behavioural difference visible to users):
  - `digitIDSource` — one regex pass finds digit clusters; per-cluster cheap validators dispatch ~18 numeric identifiers. Replaces what would have been ~18 keywordless full-body regex passes.
  - `alnumIDSource` — one regex pass finds alphanumeric clusters (with optional internal dashes for US MBI); per-token anchored regexes plus optional checksums dispatch ~22 letter-bearing identifiers.
- Each match now carries a per-jurisdiction category (`pii-us`, `pii-uk`, `pii-de`, `pii-au`, …) so block-policy operators can ratchet a single country up without touching the others.

### Performance
- **Prefilter switched from RE2 case-insensitive alternation to Aho-Corasick** (`BobuSumisu/aho-corasick`, already a transitive dependency). One ASCII lowercase pass over the body lets the trie stay case-sensitive; the Unicode case-fold cost (`unicode.SimpleFold`) that dominated `pprof` on no-hit prose bodies is gone.
- **Dedupe key now includes `category`** so genuinely-different interpretations (e.g., a Luhn-valid 9-digit number tagged both `us-ssn` and `ca-sin`) coexist; gitleaks-vs-built-in duplicates still collapse because they share `category = "secret"`.
- `sort.SliceStable` replaces `sort.Slice` inside `dedupeMatches` so equal-rank matches retain their input order, making behaviour deterministic across runs.
- Internal `tested` map in `Scanner.scanRecursive` replaced with a bool slice indexed by rule position.
- Net: prose-body scan goes from ~0.4 MB/s to ~2.3 MB/s on Raspberry Pi 5; bodies with hits go from ~0.4 MB/s to ~1.7 MB/s. `BenchmarkScanProse` / `BenchmarkScanWithHits` / `BenchmarkDigitIDSourceAlone` lock these numbers in.

## [0.1.0] - 2026-05-27

First public release.

### Added
- Transparent HTTP proxy that sits between an LLM CLI and the upstream API; buffers, scans, logs, and optionally blocks every request.
- Built-in rule engine (~50 rules across credentials, PII, Swiss-specific IDs, internal IPs, PEM blocks, etc.).
- gitleaks integration as an additional secret detector.
- Aho-Corasick keyword scanner (`MASQR_KEYWORDS` or `-k`) for org-specific terms.
- PaddleOCR PP-OCRv5 pipeline (`det → cls → rec`) with the runtime + models embedded in the binary — set `MASQR_OCR=1` to scan inline image attachments.
- Worker pool for OCR concurrency (`MASQR_OCR_WORKERS`, default 2).
- Multi-provider image-attachment regex: Anthropic Messages, Google Gemini, OpenAI Vision.
- ORT shared library cached by sha256 under `$XDG_CACHE_HOME/masqr/` — no `/tmp` leak per process.
- Block policy via `--block-on=critical|high|medium|low`, returning HTTP 451 with a structured body.
- Demo replayer (`go run ./demo …`) for stepping through a captured session log.

### Removed
- TruffleHog integration (AGPL-3.0 incompatible with permissive licensing). The 9 detector flows it provided are now covered by the built-in rule engine and gitleaks.

### Licence
- Released under **Apache License 2.0**.
- Bundled `libonnxruntime.so` ships under MIT (Microsoft); bundled PP-OCRv5 models ship under Apache-2.0 (PaddlePaddle Authors). See `NOTICE` and `LICENSES/`.

[Unreleased]: https://github.com/masqrhq/masqr/compare/v0.1.0...HEAD
[0.1.0]: https://github.com/masqrhq/masqr/releases/tag/v0.1.0
