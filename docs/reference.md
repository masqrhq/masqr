# masqr — reference

The full reference for masqr: building from source, provider internals, the
rule catalog, architecture, environment variables, logging, and testing. For
the quick pitch and install one-liners, see the [README](../README.md).

---

## Build from source

> [!IMPORTANT]
> masqr bundles its PP-OCRv5 models and ONNX Runtime libraries (~125 MB across platforms) via **Git LFS**. You must install Git LFS and pull them *before* building. If you skip this, the `.ocr/*.onnx` and runtime-library files stay as ~130-byte LFS pointer stubs — `go build` still **succeeds without error**, but `go:embed` bakes the stubs into the binary instead of the real models. The result is a much smaller executable (~16 MB instead of ~52 MB) whose OCR silently fails at runtime.

**1. Install the Git LFS binary** (once per machine — this is separate from `git lfs install`, which only wires up the hooks and fails if the binary is missing):

<details open>
<summary><strong>Linux</strong></summary>

```bash
sudo apt-get install git-lfs        # Debian / Ubuntu
sudo dnf install git-lfs            # Fedora / RHEL / CentOS Stream
sudo pacman -S git-lfs             # Arch / Manjaro
sudo zypper install git-lfs        # openSUSE
sudo apk add git-lfs               # Alpine
```

If your distro's package is missing or too old, use the official [`packagecloud` script](https://github.com/git-lfs/git-lfs/blob/main/INSTALLING.md) or grab a binary from the [releases page](https://github.com/git-lfs/git-lfs/releases).
</details>

<details>
<summary><strong>Windows</strong></summary>

```powershell
winget install GitHub.GitLFS      # winget (Windows 10/11)
choco install git-lfs             # or Chocolatey
scoop install git-lfs             # or Scoop
```

Git for Windows already bundles Git LFS — if you installed Git via [git-scm.com](https://git-scm.com/download/win), leave the "Git LFS" component checked and you're done.
</details>

<details>
<summary><strong>WSL</strong> (Ubuntu / Debian)</summary>

```bash
sudo apt-get update
sudo apt-get install -y git-lfs
```

WSL uses its own Linux Git, so the Windows install above does **not** carry over — install it inside the distro. For non-Debian WSL distros, use the matching command from the Linux section.
</details>

<details>
<summary><strong>macOS</strong></summary>

```bash
brew install git-lfs               # Homebrew
sudo port install git-lfs          # or MacPorts
```
</details>

Verify it's on your `PATH`:

```bash
git lfs version                    # e.g. git-lfs/3.4.1
```

**2. Clone and pull the LFS objects:**

```bash
git lfs install                              # configure the LFS hooks (once)
git clone https://github.com/masqrhq/masqr.git
cd masqr
git lfs pull                                 # fetch the real .ocr/ models + runtime libs
```

**3. Verify the models are real, not pointer stubs**, then build:

```bash
du -h .ocr/rec.onnx          # expect ~16M, NOT 130 bytes
go build -o masqr .          # ~52 MB binary on a supported platform
```

```bash
./masqr claude                          # Claude Code (Anthropic)
./masqr gemini -p "summarize file.txt"  # Gemini CLI (Google)
./masqr codex                           # Codex CLI (OpenAI)
./masqr vibe                            # vibe CLI (Mistral)
./masqr --block-on=high claude          # loosen: only block ≥ high
```

Already cloned without LFS? Just run `git lfs install && git lfs pull` in the existing checkout and rebuild — no need to re-clone.

Masqr starts an HTTP listener on a random local port, exports it via the right `*_BASE_URL` env var for the child process (auto-detected from the command name — see [Provider profiles](#provider-profiles)), and PTY-attaches the child so you interact with it normally. When the child exits, masqr shuts down cleanly.

---

## Provider profiles

Masqr auto-detects the provider from the child command's basename and applies a built-in profile (upstream URL, env-var name, auth-header redaction set, query-param redaction set, and a CLI-native block-response shape). Explicit `--target` / `--env` always win.

| Command | Provider | Upstream(s) | Env var(s) injected | Auth header redacted | Auth query redacted |
|---|---|---|---|---|---|
| `claude`, `claude-code` | `anthropic` | `https://api.anthropic.com` | `ANTHROPIC_BASE_URL` | `x-api-key`, `anthropic-api-key`, `authorization` | — |
| `gemini`, `gemini-cli` | `google-gemini` | `https://generativelanguage.googleapis.com` <br/>`/v1internal*` → `https://cloudcode-pa.googleapis.com` | `GOOGLE_GEMINI_BASE_URL`, `CODE_ASSIST_ENDPOINT` | `x-goog-api-key`, `authorization` | `key`, `api_key`, `apikey`, `access_token` |
| `codex`, `openai` | `openai` | `https://api.openai.com` | `OPENAI_BASE_URL` | `authorization`, `openai-organization`, `openai-project` | — |
| `agy`, `antigravity` | `antigravity` | `https://daily-cloudcode-pa.googleapis.com` <br/>(transparent TLS interception — see below) | _none_ (no base-URL override exists) | `authorization`, `x-goog-api-key` | — |
| `vibe`, `mistral`, `mistral-vibe` | `mistral` | `https://api.mistral.ai` | _none_ — redirected via a rewritten `config.toml` under a temp `VIBE_HOME` (see below) | `authorization` | — |
| anything else | `generic` | from `--target` | from `--env` (default `ANTHROPIC_BASE_URL`) | universal set | universal set |

**Gemini has two network paths.** The `@google/genai` SDK (API-key mode, set via `GEMINI_API_KEY`) talks to `generativelanguage.googleapis.com` and honours `GOOGLE_GEMINI_BASE_URL`. The OAuth `CodeAssistServer` path (free tier "Signed in with Google /auth", Code Assist for individuals, Google One AI Pro) talks to `cloudcode-pa.googleapis.com/v1internal…` and honours **only** `CODE_ASSIST_ENDPOINT`. The `gemini` profile exports both env vars to a single masqr listener and routes per-request based on URL path, so both auth modes are intercepted off one `masqr gemini` invocation — no special configuration needed.

For Gemini specifically, masqr also **scans the request URL alongside the body**, so a key smuggled into `?key=AIza…` is flagged and blocked just like one in the prompt — and the log line redacts it before it ever hits disk.

**Mistral (`vibe`) is redirected through its config file, not an env var.** vibe is the one supported CLI with **no base-URL environment override**: its upstream lives in the `api_base` field of a `[[providers]]` entry in `config.toml`, and that list isn't addressable from the environment — `VibeConfig` sets no `env_nested_delimiter` and `providers` is a list, so a `VIBE_PROVIDERS__MISTRAL__API_BASE` is silently dropped (`extra="ignore"`). The only lever is the config file. So `masqr vibe` builds a **throwaway `VIBE_HOME`**: it makes a temp dir, symlinks every entry of the real `~/.vibe` (the `.env` carrying `MISTRAL_API_KEY`, `trusted_folders.toml`, history, logs — so auth and trust survive untouched) **except** `config.toml`, which it copies with the Mistral chat provider's `api_base` rewritten to `http://<listener>/v1`, then exports `VIBE_HOME=<tempdir>` and removes it on exit. The real `~/.vibe` is never modified. The trailing `/v1` is required: vibe derives the Mistral SDK `server_url` by stripping a `/v<N>` segment (`get_server_url_from_api_base`) and rejects a value without one as `Invalid API base URL`; an `http://` value makes the SDK speak plaintext (like agy's `CLOUD_CODE_URL`), so this stays the ordinary plaintext reverse-proxy path — no TLS interception. Only the top-level `[[providers]]` Mistral entry with the `mistral` backend is rewritten — the separate `transcribe_providers` / `tts_providers` arrays (voice, `wss://` and a non-`/v1` host) are left alone. A blocked request returns the default 451 envelope, whose `error.message` vibe surfaces through its own error renderer (`ErrorResponse.primary_message`); vibe's SDK raises on the non-2xx for both streaming and non-streaming calls, so no synthetic-SSE block is needed.

> vibe injects a large project-context preamble (file tree, git status) into every prompt, so the default `--block-on=low` can trip on a benign value in that context (e.g. an `email-address` in a path or commit). If a normal session blocks, use `--on-finding redact` or `--block-on=high` — the 451 message vibe prints names the rule and says exactly this.

**Antigravity (`agy`) uses transparent TLS interception, not a base-URL override.** Google's Antigravity CLI has no `*_BASE_URL` knob, hardcodes `daily-cloudcode-pa.googleapis.com` by build channel, and its Code Assist client ignores `HTTPS_PROXY` — so masqr can't redirect it the way it does the other CLIs. Instead `masqr agy` runs a **transparent TLS proxy**: it stands up a local listener on `127.0.0.1:443`, generates a short-lived CA that `agy` trusts via `SSL_CERT_FILE` (system roots **+** the masqr CA, so `agy`'s other TLS calls still validate), redirects the hostname to the listener, and forwards to the real upstream — running the same scan/redact/block engine over the decrypted `/v1internal:*` traffic (including `streamGenerateContent` prompts).

The hostname redirect is **no-sudo by default**: masqr compiles a tiny `getaddrinfo` `LD_PRELOAD` shim (needs a C compiler — `cc`/`gcc`) and launches `agy` with `GODEBUG=netdns=cgo` so its resolver goes through the shim, scoped to that process only — nothing global changes. If no compiler is present it falls back to a reversible `/etc/hosts` edit (one `sudo` step, restored on exit; force either path with `MASQR_INTERCEPT_REDIRECT=ldpreload|hosts`). Binding `:443` needs no privilege where `net.ipv4.ip_unprivileged_port_start ≤ 443`; otherwise `setcap cap_net_bind_service=+ep ./masqr`.

**macOS** is supported with a one-time trust step (Go on macOS reads the Keychain, not `SSL_CERT_FILE`). On first run masqr writes a **persistent** CA to `~/.masqr/ca.pem`; trust it once — `sudo security add-trusted-cert -d -r trustRoot -k /Library/Keychains/System.keychain ~/.masqr/ca.pem` (approve the dialog; reverse with `security delete-certificate -c "masqr local CA"`). Then pick one of:

- **No per-session sudo (recommended):** `sudo masqr --macos-setup` once — installs a persistent `/etc/hosts` redirect + a pf `rdr :443→:8443` anchor + a LaunchDaemon (so it survives reboot). Thereafter just **`masqr agy`** with **no sudo** (masqr binds the unprivileged `:8443`). Undo with `sudo masqr --macos-teardown`.
- **Ad-hoc:** **`sudo masqr agy`** each time — root binds `:443` and edits `/etc/hosts` per session; masqr drops the `agy` child back to your user so it keeps your OAuth/Keychain.

(Windows is not yet supported.) Because `agy`'s prompts are large, the default `--block-on=low` may trip on benign findings; use `--on-finding redact` if a normal session gets blocked.

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
- Any high-entropy base64 blob (≥ 24 chars, tiered Shannon-entropy floor) gets decoded once and re-scanned, so `echo $AWS_KEY | base64` still trips. Decode-and-rescan depth is capped to avoid base64-of-base64 ratholes.
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
      --on-finding string       block (default) | redact
      --shutdown-grace duration HTTP graceful shutdown            (default 5s)
  -t, --target string           upstream API                     (provider-profile default; overrides profile)
  -V, --version                 print masqr version and exit

built-in providers: anthropic, antigravity, google-gemini, mistral, openai
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

To loosen: `--block-on=high` (only high+critical block), `--block-on=critical` (only critical blocks). The `low` default is the safest — every finding gets a chance to be a human-in-the-loop decision. `--on-finding redact` rewrites each span with a `__LABEL_N__` placeholder and restores it in the response instead of blocking.

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
3. `runCLI` — `exec` the child (under a PTY on Unix with raw-mode stdin + SIGWINCH resize; inherited stdio on Windows), pipe both directions

The proxy itself is `httputil.NewSingleHostReverseProxy` with custom `Director` (rewrites `Host`), `ModifyResponse` (logs the response), and `ErrorHandler`. SSE (`text/event-stream`) and Anthropic's `application/vnd.anthropic.stream+json` are pass-through — never buffered.

### Files

| File | Role |
|---|---|
| `main.go` | flag parsing, provider auto-detection, signal handling, errgroup lifecycle |
| `runcli_unix.go` / `runcli_windows.go` | child execution: PTY + SIGWINCH (Unix) / inherited stdio (Windows) |
| `providers.go` | built-in profile registry (Anthropic/Gemini/OpenAI/Antigravity/Mistral), basename-based auto-detect, per-provider `Prepare` hook |
| `vibe.go` | Mistral `vibe` redirect: builds a temp `VIBE_HOME` mirror with `config.toml`'s Mistral `api_base` rewritten to the listener (vibe has no base-URL env var) |
| `server.go` | reverse proxy, request/response logging, URL key redaction, response decompression (gzip/deflate/brotli/zstd) |
| `policy.go` | block-or-forward decision, HTTP 451 writer, per-provider error envelope (Anthropic / Google / OpenAI) |
| `intercept.go` / `intercept_macos.go` | transparent TLS interception for `agy` (LD_PRELOAD/hosts redirect, persistent CA, macOS pf setup) |
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
| `MASQR_INTERCEPT_REDIRECT` | force the `agy` hostname-redirect path: `ldpreload` or `hosts` |
| `VIBE_HOME` | read to locate vibe's real config dir (default `~/.vibe`); `masqr vibe` then re-exports it pointing at a temp mirror with a rewritten `config.toml` |
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

Phase E additionally fetches a small corpus of real-world test screenshots from sibling open-source projects (currently Microsoft Presidio's MIT-licensed PII test images under `testdata/screenshots/external/`). These are intentionally synthetic (fictional names, reserved-range phone numbers, `@microsoft.com` test addresses) — masqr's E2E intentionally never ingests real leaked screenshots, even publicly-leaked ones, to avoid re-distributing other people's PII or burnt credentials. See [`testdata/screenshots/external/README.md`](../testdata/screenshots/external/README.md) for provenance, SHA-256s, and per-image notes on which masqr rules each one exercises.

The catalog and base64 phases stand up masqr as a long-running proxy (with `sleep 86400` as the child) plus a Python HTTP sink as the upstream, then curl-drive synthetic POSTs. This catches the same regressions the Go suite catches, but at the HTTP-boundary level — proving the scanner-to-proxy path itself works, not just the in-memory rule engine. Phase A's universal precondition is provider-specific: Gemini requires at least one `/v1internal:*` request (OAuth traffic must hit `cloudcode-pa.googleapis.com`, not bypass via the public Gemini API alone). Claude requires at least one `/v1/messages` request (traffic must flow through `ANTHROPIC_BASE_URL`, not directly to `api.anthropic.com`). Codex requires at least one `POST /responses` (traffic must hit `openai_base_url` via `-c`, not the default OpenAI host).

---

## Known limitations

- **OCR recognition** is PP-OCRv5 ONNX with the angle classifier wired in (det → cls → rec). Per-character error is ~2–5% on clean screenshots, higher on noisy ones. Mitigated for patterns with strict prefixes (`AKIA…`, `ghp_…`) but a noisy screenshot of a long random secret may slip through.
- **Base64 detection** only catches the standard alphabet (`+/`); URL-safe (`-_`) without padding gets a smaller window via decode-fallback but isn't anchored by the pattern.
- **Body cap**: 2 MiB. Past that, the scanner only sees the first 2 MiB. The full body is still logged and forwarded.
- **External sources**: gitleaks / keywords / OCR are all optional. If a source fails to initialize (missing model, malformed wordlist), it's logged once and the rest keep working.
- **TLS interception** for non-`agy` providers is out of scope; they take an HTTP base-URL override. `agy` is the exception (see [Provider profiles](#provider-profiles)).

---

## License

masqr is released under the **Apache License 2.0** — see [`LICENSE`](../LICENSE).

The binary bundles two third-party components, each shipped under its upstream licence:

| Component | Origin | Licence |
|---|---|---|
| `libonnxruntime.so.1.26.0` | [Microsoft ONNX Runtime](https://github.com/microsoft/onnxruntime) | MIT — [`LICENSES/LICENSE-onnxruntime.txt`](../LICENSES/LICENSE-onnxruntime.txt) |
| PP-OCRv5 `det.onnx` / `cls.onnx` / `rec.onnx` + `ppocr_keys_v1.txt` | [PaddleOCR](https://github.com/PaddlePaddle/PaddleOCR), re-exported by [OnnxOCR](https://github.com/jingsongliujing/OnnxOCR) | Apache-2.0 — [`LICENSES/LICENSE-paddleocr.txt`](../LICENSES/LICENSE-paddleocr.txt) |

See [`NOTICE`](../NOTICE) for the full attribution required by Apache-2.0 §4(d).
