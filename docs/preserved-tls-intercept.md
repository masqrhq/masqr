# Preserved: transparent-TLS intercept machinery

As of the agy `CLOUD_CODE_URL` switch (see `agy-endpoint-override.md`), agy is
intercepted via masqr's ordinary **plaintext reverse-proxy** path — agy honors
`CLOUD_CODE_URL=http://<listener>` and speaks plaintext HTTP, so no TLS MITM is
needed. That left masqr's transparent-TLS intercept code **unused in
production**: no provider sets `Provider.Intercept` anymore.

**This code is deliberately kept, not deleted.** It is reserved for intercepting
codex's WebSocket (`ws:`) transport, which the plaintext HTTP reverse proxy
cannot 101-upgrade. Do not remove it as "dead code."

## Two TLS-MITM mechanisms (both preserved)

1. **Transparent intercept** (`runIntercept`, `intercept.go` / `intercept_macos.go`)
   — redirects the provider's *hardcoded* hostname to a privileged `:443`
   listener via an `LD_PRELOAD` getaddrinfo shim (Linux) or `/etc/hosts`
   (fallback / macOS), and trusts the forged leaf via `SSL_CERT_FILE` (Linux) or
   a persistent Keychain CA (macOS). Needs sudo/setcap for `:443`. Selected by
   `Provider.Intercept = true` (currently no provider sets it).

2. **`--tls-intercept` random-port path** (`runInterceptEnv`, `intercept_env.go`)
   — the no-sudo evolution. Binds a **random free loopback port** and points the
   child straight at it through an `https://` **endpoint-override env var**
   (agy's `CLOUD_CODE_URL`, codex's `-c openai_base_url`, etc.), so no hostname
   redirect, no `/etc/hosts`, no C shim, no `:443`. Still a full TLS MITM (masqr
   terminates TLS, sees decrypted request **and** response), trusting the leaf
   via `SSL_CERT_FILE`. Opt-in via the `--tls-intercept` flag. **This is the path
   to extend for codex `ws:`.**

   Verified end-to-end 2026-05-31:
   - `masqr --tls-intercept agy -p 'hi'` → TLS MITM on a random port, real reply,
     bearer redacted.
   - `masqr --tls-intercept codex exec '…'` (chatgpt auth) → decrypted
     `POST /responses` → 200, auth redacted, no token leak. codex used HTTPS (its
     WebSocket transport is disabled by the openai profile's ExtraArgs:
     `--disable responses_websockets_v2 --disable responses_websockets`).

## What is preserved (and what each piece does)

| Location | Symbol(s) | Role |
|---|---|---|
| `providers.go` | `Provider.Intercept` field | Per-provider flag that routes `run()` to `runIntercept()` instead of the plaintext proxy. Currently `false` for every provider. |
| `main.go` | `if policy.Provider.Intercept { return runIntercept(...) }` | The branch in `run()` that selects the transparent intercept path. |
| `main.go` | `--tls-intercept` flag + `if tlsIntercept { return runInterceptEnv(...) }` | Selects mechanism #2 — the no-sudo random-port TLS MITM via endpoint-override env. |
| `intercept_env.go` | `runInterceptEnv` | The `--tls-intercept` path: random free loopback port, TLS termination, child redirected via `https://` endpoint-override env + ExtraArgs, forwards to pinned upstream. Reuses `certFactory` / `writeTrustBundle` / `pinnedTransport`. |
| `main.go` | `--macos-setup` / `--macos-teardown` flags + their handler block | One-time privileged macOS install/uninstall (persistent `/etc/hosts` + pf rdr `:443->:8443` + LaunchDaemon). |
| `main.go` | `runCLI` drop-privileges block (`SUDO_UID`/`SUDO_GID` → child `Credential`) | Lets `sudo masqr …` bind `:443` while the child runs as the invoking user (its OAuth/Keychain live there). |
| `intercept.go` | `runIntercept` | Stands up the transparent TLS proxy, redirects the upstream host to the local listener, PTY-attaches the child. |
| `intercept.go` | `certFactory`, `newCertFactory`, `getCertificate`, `leafFor` | On-the-fly CA + per-SNI leaf certs the intercepted client trusts. |
| `intercept.go` | `pinnedTransport` | Forwards to the real upstream IP so a loopback redirect can't loop back into our own listener. |
| `intercept.go` | `writeTrustBundle`, `systemCABundleFiles` | (Linux) builds `system roots ++ masqr CA` and exposes it via `SSL_CERT_FILE`. |
| `intercept.go` | `Redirector`, `selectRedirector`, `ldPreloadResolver`, `hostsBind443`, `shellSingleQuote` | Redirect strategies: no-sudo `LD_PRELOAD` getaddrinfo shim (Linux), or `/etc/hosts` fallback. |
| `intercept.go` | `embedsrc/resolver_shim.c` (`//go:embed`) | C source for the `getaddrinfo` interposer, compiled at runtime by `ldPreloadResolver`. |
| `intercept_macos.go` | `newInterceptCA`, `generatePersistentCA`, `loadPersistentCA`, `chownToInvokingUser` | macOS persistent, Keychain-trusted CA under `~/.masqr` (Go on darwin ignores `SSL_CERT_FILE`). |
| `intercept_macos.go` | `darwinRedirector`, `noopRedirector`, `macosSetup`, `macosTeardown`, pf/LaunchDaemon consts | macOS redirect + one-time `--macos-setup` install. |
| `intercept_macos.go` | `resolveUpstreamIP`, `digA`, `resolveIPv4`, `mustHostname` | Resolve the real upstream IP, bypassing any `/etc/hosts` redirect. |
| `intercept_test.go` | `TestCertFactoryLeafVerifies`, `TestTrustBundleIncludesCAAndSystemRoots`, `TestLDPreloadResolver`, `TestPersistentCARoundTrip`, `TestShellSingleQuote` | Cover the intercept primitives; keep them passing. |

## How to activate

- **Mechanism #2 (`--tls-intercept`, preferred):** just pass the flag, e.g.
  `masqr --tls-intercept agy …` or `masqr --tls-intercept codex exec …`. Works
  for any provider whose profile carries an `https`-capable endpoint override
  (EnvVars and/or ExtraArgs). No code change, no sudo.
- **Mechanism #1 (transparent):** set `Intercept: true` on the provider profile
  (with upstream `Target`/`Routes`). `run()` then calls `runIntercept()`,
  terminating TLS on the target host with the on-the-fly/persistent CA,
  redirecting the hostname to the local `:443` listener, and forwarding to the
  pinned real upstream.

## Path to actual codex `ws:` interception

Today both intercept paths reuse `newProxy`, an HTTP reverse proxy that does
**not** relay a WebSocket 101 upgrade — and the openai profile currently
*disables* codex's WebSocket transport (`--disable responses_websockets_v2
--disable responses_websockets`) so codex falls back to plain HTTPS, which masqr
handles fine. To intercept the real `ws:` transport instead:

1. Drop (or make conditional) those two `--disable` flags in `openAIProfileFor`
   so codex actually opens the WebSocket.
2. Add WebSocket relay to the proxy handler: detect `Upgrade: websocket`,
   `http.Hijack` the client conn, dial the upstream `wss://`, and pump frames
   both ways (optionally parsing the Responses protocol frames for
   scan/redact/block, the masqr value-add).
3. Run it under `--tls-intercept` (mechanism #2) so the whole session is
   TLS-terminated locally on a random port — no sudo, no hostname redirect.

`runInterceptEnv` is the place to build this; the TLS termination + endpoint
redirect are already done.

## Note

`TestAntigravityProfileUsesCloudCodeURL` asserts "no provider sets `Intercept`"
— that reflects the **current** state only. It is not a ban on the field; when a
provider (codex ws) re-enables intercept, update that assertion accordingly.
