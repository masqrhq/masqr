# Antigravity (`agy`) interception — `CLOUD_CODE_URL` endpoint override

How masqr intercepts Google Antigravity's `agy` CLI, on **every** platform, with
the same plaintext reverse-proxy path it uses for the other CLIs — no TLS MITM,
no forged CA, no hostname redirect, no `:443`, no sudo.

## The lever

`agy`'s Code Assist client talks to `{daily-,}cloudcode-pa.googleapis.com` over a
path (`/v1internal:streamGenerateContent` etc.) identical to Gemini CLI's OAuth
surface. It exposes **no** `*_BASE_URL` knob and ignores `HTTPS_PROXY` — so the
redirect trick the other providers use doesn't obviously apply.

It does, however, honor a single environment variable as a **full endpoint
override**: **`CLOUD_CODE_URL`** (recovered from
`(*CLIAuthProvider).UpdateEndpointURL` in the v1.0.3 binary). Two properties make
it sufficient on its own:

1. **It's a complete base URL**, so masqr can point the client at a loopback
   listener without touching DNS or `/etc/hosts`.
2. **The URL scheme selects the transport.** An `http://` value puts the client
   on a *plaintext* HTTP transport — no TLS handshake, nothing to terminate.

## What masqr does

`masqr agy` sets:

```
CLOUD_CODE_URL=http://<listener>
```

and runs as an ordinary reverse proxy, exactly like `claude`, `gemini`, and
`codex`. The single `Route` (`/v1internal → https://daily-cloudcode-pa.googleapis.com`)
mirrors the `Target` so request rewriting in `newProxy` stays uniform. The full
scan/redact/block engine runs over `agy`'s `/v1internal:*` traffic, including
`streamGenerateContent` prompts; a blocked turn comes back as a synthetic
Code-Assist SSE turn (see the interactive consent flow). The `authorization` and
`x-goog-api-key` headers are redacted from logs.

## Why there's no TLS interception

Earlier masqr revisions intercepted `agy` with a transparent-TLS proxy (a
local `:443` listener, an on-the-fly CA trusted via `SSL_CERT_FILE`, an
`LD_PRELOAD` `getaddrinfo` shim or `/etc/hosts` edit for the hostname, and a
macOS-specific Keychain/pf/LaunchDaemon dance). The `CLOUD_CODE_URL` discovery
made all of that unnecessary: masqr is now **plaintext-only** and the TLS-MITM
implementation was removed (`refactor: delete dead TLS-MITM implementation`). The
upshot is that `agy` needs no privilege, no trust step, and no per-platform
setup — `masqr agy` behaves the same on Linux and macOS.
