# Changelog

All notable changes to **masqr** will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Changed
- **OCR is now enabled by default.** The PaddleOCR pipeline that recognizes secrets baked into inline image attachments used to be gated behind `MASQR_OCR=1` (off by default), so `masqr agy` — which forwards screenshots — silently missed credentials carried inside Anthropic base64 images (`image/png`, `image/jpeg`) and Gemini `inline_data` images out of the box. The source is now attached automatically on supported platforms; matches are reported with the existing `/from-image` suffix (e.g. `aws-access-key-id/from-image`). Set `MASQR_OCR=0` (or `false`/`no`/`off`) to opt out. Startup still degrades gracefully when the OCR runtime/models can't be loaded (the source is skipped with a single log line instead of failing), and on platforms outside the bundled matrix masqr now warns only when OCR has not been explicitly disabled.

### Added
- **GitHub Copilot CLI (`copilot`) support via the `COPILOT_API_URL` env var.** The `@github/copilot` CLI normally resolves its API base from the signed-in user's `copilotUser.endpoints.api`, but honors `COPILOT_API_URL` as a full endpoint override that wins over everything else (the `Wa()` endpoint resolver in `app.js` v1.0.63 returns `process.env.COPILOT_API_URL` first). An `http://` value makes its fetch/SDK clients speak plaintext, so `masqr copilot` exports `COPILOT_API_URL=http://<listener>` and takes the same ordinary plaintext reverse-proxy path as every other provider — no TLS intercept. Its agent loop is multi-wire: the conversation turn rides the OpenAI Responses API for OpenAI models (`gpt-5-mini` POSTs `/responses`) or the Anthropic Messages API for Claude models (`claude-haiku-4.5` POSTs `/v1/messages`), selected by the active model; `/chat/completions` is auxiliary (session-title generation), `/agents/sessions/{id}/events` is telemetry, and `/models` + MCP (`/mcp`) all share the single `api.githubcopilot.com` host. The bearer token rides in `Authorization` (added to the redaction set), and the interactive surface dispatches by path: a blocked `/responses` or `/v1/messages` turn is delivered as a synthetic assistant turn in that wire's own shape, so the block advice (rule, `mask` offer, `/clear`, threshold tips) renders inline and the interactive `mask` reply works regardless of model; other endpoints fall back to the OpenAI 451 envelope. Recognised aliases: `copilot`, `github-copilot`.

## [0.3.0] - 2026-06-16

### Added
- **Unicode-obfuscated key detection.** The scanner now decodes contiguous `\uXXXX` escape runs and rescans the decoded text, so a Google/Maps API key smuggled as `AIz…` is caught (as `gcp-api-key/unicode-decoded`) instead of slipping through as inert text.

### Changed
- Building from source now requires **Go 1.26.4** (was 1.26.3). The bump clears three Go standard-library advisories — `GO-2026-5037` (`crypto/x509`), `GO-2026-5038` (`mime`), `GO-2026-5039` (`net/textproto`) — that `govulncheck` began flagging in CI; no masqr code was affected.

### Fixed
- **Far fewer false positives on benign code.** Several high-noise recognizers are now keyword-gated, firing only when a relevant keyword sits near the candidate:
  - `aws-access-key-id` is restricted to genuine `AKIA`/`ASIA` access-key prefixes; the session/role STS prefixes (`AGPA`, `AIDA`, `AROA`, …) that matched high-entropy strings in source snippets were dropped.
  - `us-ssn`, `ca-sin`, `au-tfn`, `au-acn`, `us-aba-routing`, and `uk-nhs` now require contextual keywords, so bare digit clusters in code no longer block clean prompts.
  - `se-orgnummer` requires `orgnr`/`orgnummer` context within ±64 bytes, so bare 10-digit Luhn numbers in CLI metadata stop blocking.
- **Interactive mask-and-continue on external matches.** The gitleaks, digit-id, alnum-id, and keyword sources now populate `Match.Identity`, so the redact-on-repeat / mask-and-continue flow is offered for those findings instead of always hard-blocking.
- Windows installer (`install.ps1`) aborted on Windows PowerShell 5.x with `Unable to find type [Net.SecurityProtocol]` — the TLS-1.2 line referenced the wrong enum (it's `SecurityProtocolType`). It now `-bor`s TLS 1.2 onto the current protocols inside a `try/catch` (no-op on PowerShell 7+) and silences the progress bar that otherwise throttles the binary download on PS 5.x.

## [0.2.0] - 2026-06-02

### Changed
- The default per-session log moved out of the current directory and into the OS-native user cache dir (`os.UserCacheDir()`) — `$XDG_CACHE_HOME/masqr/` (else `~/.cache/masqr/`) on Linux, `~/Library/Caches/masqr/` on macOS, `%LocalAppData%\masqr\` on Windows — created on demand, so masqr no longer drops `masqr-<timestamp>.log` files wherever it's launched. The bundled OCR runtime cache now hangs off the same root. Override the full log path with `-l`.
- Release assets are the bare per-platform binary (`masqr-<tag>-<os>-<arch>[.exe]`) plus a `.sha256`, instead of a `.tar.gz`/`.zip` archive; the install scripts were updated to match.

### Fixed
- Release pages no longer repeat the changelog once per build target — the 5-job matrix used a static release body instead of each job regenerating notes. The upload action also moved to a node24 runtime.

### Added
- Antigravity (`agy`) end-to-end test harness (`scripts/test-agy-e2e.sh`).

## [0.1.0] - 2026-06-02

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
- `--on-finding redact` mode to blank matched spans in place instead of blocking the request.
- Demo replayer (`go run ./demo …`) for stepping through a captured session log.
- **Gemini CLI (and OpenAI/codex) first-class support.** New `providers.go` carries built-in profiles (upstream URL, env-var name(s), auth-header redaction set, auth-query redaction set, optional per-path route table). `masqr gemini` Just Works — no `--target` / `--env` needed. Explicit flags still override the profile so corporate proxies / LiteLLM-style routers keep working.
  - **Provider auto-detection** by basename of the child command. Both `/` and `\` are honoured as path separators so npm-installed and system-installed CLIs both resolve. Recognised: `claude`, `claude-code`, `gemini`, `gemini-cli`, `codex`, `openai`, `agy`, `antigravity`, `vibe`, `mistral`, `mistral-vibe`.
  - **Per-request upstream routing.** A new `Provider.Routes` table lets one profile cover multiple upstream hosts, dispatched by URL path prefix. The proxy moved from `httputil.NewSingleHostReverseProxy` to a `Rewrite`-based `httputil.ReverseProxy`; per request, the first matching prefix wins, otherwise the primary `Target` is used.
  - **Gemini OAuth (free tier "Signed in with Google") now works.** The CLI has two completely independent network paths: the `@google/genai` SDK (API-key mode) hits `generativelanguage.googleapis.com` and honours `GOOGLE_GEMINI_BASE_URL`; the `CodeAssistServer` (OAuth / Code Assist for individuals / Google One AI Pro) hits `cloudcode-pa.googleapis.com/v1internal…` and honours **only** `CODE_ASSIST_ENDPOINT`. Previous versions of masqr only redirected the SDK path, so OAuth users' traffic silently bypassed the proxy. The Gemini profile now exports both env vars to the same masqr listener and dispatches `/v1internal*` to Code Assist while letting `/v1beta*` fall through to the public Gemini API — both auth modes intercepted from one invocation.
  - **Multi-env-var injection.** `--env` (and `Provider.EnvVars`) became a list. A single `masqr gemini` exec adds two env vars to the child; future providers can ship as many as the upstream CLI consults. `-e VAR1,VAR2` and `-e VAR1 -e VAR2` are both accepted.
  - **Provider-aware block response.** On a chat/generation endpoint a blocked request comes back as a synthetic assistant *turn* in the CLI's own wire shape, so the reason renders inline like a normal model reply (see the interactive mask-and-continue flow below). Non-chat endpoints and unknown providers fall back to the provider-shaped error envelope — Anthropic's `{"type":"error",…}` for Claude, `google.rpc.Status` for Gemini (`@google/genai` parses this natively), OpenAI's `{"error":{…,"code":"masqr_blocked"}}` for codex (HTTP 451). Every blocked response carries `X-Masqr-Blocked: 1`.
  - **URL scanning + URL redaction.** The scanner now sees the request URI alongside the body, so a key smuggled in `?key=AIza…` is flagged and blocked just like one in the prompt. The log line redacts every value of `key`, `api_key`, `apikey`, `access_token`, `token`, `auth` before writing — the request to upstream is **byte-for-byte unchanged**, redaction is purely log-side.
  - **`x-goog-api-key` (+ `openai-organization`, `openai-project`) added to the redaction header set.** New providers automatically contribute to the global set, so adding a fourth profile in `providers.go` can never accidentally leak its key.
  - **Banner now shows the active provider** as `[google-gemini]` (or `[anthropic]`, `[openai]`, `[antigravity]`, `[mistral]`) and, when the profile carries Routes, an extra line like `+ /v1internal → https://cloudcode-pa.googleapis.com` so the secondary upstream isn't invisible.
- **Google Antigravity (`agy`) support via the `CLOUD_CODE_URL` env var.** Antigravity has no `*_BASE_URL` override and its Code Assist client ignores `HTTPS_PROXY`, but it honors `CLOUD_CODE_URL` as a full endpoint override (recovered from `(*CLIAuthProvider).UpdateEndpointURL` in the v1.0.3 binary). An `http://` value makes the client speak plaintext, so `masqr agy` exports `CLOUD_CODE_URL=http://<listener>` and takes the same ordinary plaintext reverse-proxy path as every other provider — no transparent-TLS intercept, forged CA, hostname redirect, `/etc/hosts` edit, or `:443`/sudo. Works identically on Linux and macOS with no per-platform setup.
  - **Synthetic-SSE block path + interactive consent flow** for the streaming Code Assist endpoint (`/v1internal:streamGenerateContent`), plus opaque-field blanking on the request bodies.
- **Interactive mask-and-continue for every supported CLI.** Originally agy-only, the in-chat consent flow now spans Claude, Codex, Gemini, agy, and vibe. A blocked turn explains what tripped (rule · category · severity, redacted snippet) and offers `mask`; replying `mask` redacts the flagged value(s) for the rest of the session — a placeholder swap the model never sees through — instead of blocking, so the conversation keeps moving. Both the block explanation and the consent ack are delivered as a synthetic assistant turn in each provider's own protocol: Anthropic Messages SSE, OpenAI Responses SSE, OpenAI `chat.completion` SSE, and Gemini / Code Assist `generateContent` (nested under `response` for `/v1internal`), each with a single-JSON fallback for non-streaming requests. Codex's zstd-compressed `/responses` body is decoded to detect the reply and to redact the consented value, then forwarded uncompressed.
- **Mistral `vibe` support via a rewritten `config.toml`.** vibe is the one supported CLI with no base-URL environment override — its upstream lives in the `api_base` field of a `[[providers]]` entry in `config.toml`, which isn't addressable from the environment. `masqr vibe` builds a throwaway `VIBE_HOME`: a temp dir that symlinks every entry of the real `~/.vibe` (the `.env` carrying `MISTRAL_API_KEY`, `trusted_folders.toml`, history, logs — so auth and trust survive untouched) **except** `config.toml`, which it copies with the Mistral chat provider's `api_base` rewritten to `http://<listener>/v1`. The trailing `/v1` is required (vibe strips a `/v<N>` segment to derive the SDK `server_url`); an `http://` value keeps the SDK on the plaintext transport, so this stays an ordinary reverse-proxy path — no TLS interception. The real `~/.vibe` is never modified and the temp dir is removed on exit. `vibe@mistral.ai` (vibe's agent/metadata address) is suppressed from the email-address rule.
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
- **End-to-end test harnesses** for Claude (`scripts/test-claude-e2e.sh`), Codex (`scripts/test-codex-e2e.sh`), and Gemini (`scripts/test-gemini-e2e.sh`), sharing phases B–E via `scripts/e2e-common.sh`. Phase A drives the live CLI and asserts the provider-specific API path appears in every session log (`POST /v1/messages`, `POST /responses`, `/v1internal:*`); phases B–E run ~84 offline scenarios covering every secret type, universal + country-tagged PII, base64-obfuscation decode-and-rescan, and the PaddleOCR `/from-image` source.
- **OS-styled screenshot OCR corpus** under `testdata/screenshots/` (Windows / macOS / Linux / Android / iOS mockups rendered in each OS's real system font, generated by `scripts/generate-screenshots.py`), plus an **external** corpus of two intentionally-synthetic Microsoft Presidio PII images (MIT-licensed, committed verbatim with SHA-256 and attribution). See `testdata/screenshots/external/README.md` for the rationale on not redistributing real leaked screenshots.

### Fixed
- **PII leak: every occurrence of a flagged value is now redacted.** `dedupeMatches` keyed findings on the matched *value* (`category | snippet | severity`) with no byte offset, so a value appearing more than once in a request — e.g. an email repeated across accumulated conversation history — collapsed to a single match and only the **first** occurrence was masked; the rest were forwarded to the upstream model in cleartext. The key now carries the byte range, so co-located cross-rule overlaps still collapse while every distinct occurrence is masked.
- **Anthropic extended-thinking turns no longer 400.** The signed `thinking` text and `signature` of a thinking block (and the `data` of a `redacted_thinking` block) are skipped during scanning — masking those bytes mutated the signed payload and the API rejected the next turn with "Invalid `signature` in `thinking` block". The scoping is structure-aware: a field merely *named* `signature` elsewhere is still scanned.

### Performance
- **Prefilter switched from RE2 case-insensitive alternation to Aho-Corasick** (`BobuSumisu/aho-corasick`, already a transitive dependency). One ASCII lowercase pass over the body lets the trie stay case-sensitive; the Unicode case-fold cost (`unicode.SimpleFold`) that dominated `pprof` on no-hit prose bodies is gone.
- **Dedupe key is `(offset, end, category, severity)`** so genuinely-different interpretations (e.g., a Luhn-valid 9-digit number tagged both `us-ssn` and `ca-sin`) coexist and the same value repeated at different offsets is masked at *every* occurrence (see Fixed); gitleaks-vs-built-in duplicates at the same span still collapse because they share `category = "secret"`.
- `sort.SliceStable` replaces `sort.Slice` inside `dedupeMatches` so equal-rank matches retain their input order, making behaviour deterministic across runs.
- Internal `tested` map in `Scanner.scanRecursive` replaced with a bool slice indexed by rule position.
- Net: prose-body scan goes from ~0.4 MB/s to ~2.3 MB/s on Raspberry Pi 5; bodies with hits go from ~0.4 MB/s to ~1.7 MB/s. `BenchmarkScanProse` / `BenchmarkScanWithHits` / `BenchmarkDigitIDSourceAlone` lock these numbers in.

### Removed
- TruffleHog integration (AGPL-3.0 incompatible with permissive licensing). The 9 detector flows it provided are now covered by the built-in rule engine and gitleaks.

### Licence
- Released under **Apache License 2.0**.
- Bundled `libonnxruntime.so` ships under MIT (Microsoft); bundled PP-OCRv5 models ship under Apache-2.0 (PaddlePaddle Authors). See `NOTICE` and `LICENSES/`.

[Unreleased]: https://github.com/masqrhq/masqr/compare/v0.3.0...HEAD
[0.3.0]: https://github.com/masqrhq/masqr/compare/v0.2.0...v0.3.0
[0.2.0]: https://github.com/masqrhq/masqr/compare/v0.1.0...v0.2.0
[0.1.0]: https://github.com/masqrhq/masqr/releases/tag/v0.1.0
