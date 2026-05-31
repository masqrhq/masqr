# Antigravity (`agy`) interception on macOS — design & findings

How masqr intercepts Google Antigravity's `agy` CLI on macOS, and the empirical
results behind the design. `agy` exposes no base-URL override and its Code
Assist client ignores `HTTPS_PROXY`, so masqr intercepts it with a **transparent
TLS proxy**: terminate TLS on the target host with an on-the-fly CA the client
trusts, decrypt, run the scan/redact/block engine, and forward to the real
upstream (`daily-cloudcode-pa.googleapis.com`).

The interception has three pieces: **trust** (client must accept masqr's leaf),
**name → loopback** (get the hostname to resolve to masqr), and **port** (get
`:443` to masqr's listener). macOS makes each harder than Linux.

## Empirical findings (verified on macOS 15.5, Apple Silicon; Go 1.25)

| Question | Result | Evidence |
|---|---|---|
| Does Go on macOS honor `SSL_CERT_FILE` / `SSL_CERT_DIR`? | **No** | A Go client with `SSL_CERT_FILE`/`SSL_CERT_DIR` set still failed `x509: certificate signed by unknown authority`. Go on darwin verifies against the **Keychain**. |
| Can a Keychain-trusted CA make a Go client accept masqr's leaf? | **Yes** | After `security add-trusted-cert -d -r trustRoot -k System.keychain`, a Go client trusted masqr's leaf for `daily-cloudcode-pa…`. |
| Can Keychain trust be set **headless** (over SSH / no GUI)? | **No** | `SecTrustSettingsSetTrustSettings: The authorization was denied since no user interaction was possible.` The cert *imports* but the **trust setting** requires a console/GUI auth. (MDM `.mobileconfig` is the only fully-silent path.) |
| Correct trust flag for masqr's **self-signed root** CA? | **`-r trustRoot`** (the default) | `man`: `trustRoot|trustAsRoot|deny|unspecified`. `trustAsRoot` is for **non-root** certs; using it for a self-signed root is wrong. |
| Is `DYLD_INSERT_LIBRARIES` (the `LD_PRELOAD` equivalent) usable on `agy`? | **No** | `agy` is **hardened runtime** (`codesign` flags `0x10000(runtime)`), Developer-ID-signed by Google, with **no** `allow-dyld-environment-variables` / `disable-library-validation` entitlements → DYLD env vars stripped, library validation enforced. |
| Is there a `setcap` / `ip_unprivileged_port_start` to bind `:443` unprivileged? | **No** | macOS reserves ports <1024; binding (or pf-redirecting) `:443` needs root. |
| Does pf `rdr` redirect loopback `:443 → :8443`? | **Yes** | `rdr pass on lo0 … port 443 -> 127.0.0.1 port 8443` loaded via a `com.masqr` anchor; a loopback poke to `:443` reached the `:8443` listener. |

**Consequences:** trust must be a **one-time, locally-approved** step (like
`mkcert`/`mitmproxy`/Charles); the CA must be **persistent** (`~/.masqr/ca.pem`),
not ephemeral; and `:443` needs root, but via a one-time pf setup masqr can then
run on an unprivileged `:8443` with no per-session sudo.

## Shipped modes

Both require the **one-time CA trust** first (GUI auth, not sudo):
```
sudo security add-trusted-cert -d -r trustRoot -k /Library/Keychains/System.keychain ~/.masqr/ca.pem
```
(masqr generates `~/.masqr/ca.pem` on first run if absent; reverse with
`security delete-certificate -c "masqr local CA"`.)

### 1. No per-session sudo (recommended)
```
sudo masqr --macos-setup      # one-time
masqr agy                     # thereafter, NO sudo
sudo masqr --macos-teardown   # undo
```
`--macos-setup` installs, persistently:
- `/etc/hosts`: `127.0.0.1 daily-cloudcode-pa.googleapis.com # masqr-intercept`
- pf anchor `/etc/pf.anchors/com.masqr` (`rdr … :443 -> :8443`) wired into
  `/etc/pf.conf` (after the `com.apple` anchors; backed up + `pfctl -nf` validated)
- a `com.masqr.pf` LaunchDaemon that re-enables pf at boot

Then `masqr agy` detects the setup, binds the unprivileged `127.0.0.1:8443`, and
runs as your user. Because the `/etc/hosts` entry persistently points the host at
loopback, masqr resolves the real upstream via `dig @8.8.8.8` (bypassing
`/etc/hosts`) so it doesn't forward to itself.

### 2. Ad-hoc (per-session sudo)
```
sudo masqr agy
```
Root binds `:443` and edits `/etc/hosts` for the session; masqr drops the `agy`
child back to the invoking user (`SUDO_UID`) so it keeps your OAuth/Keychain.

## Avoiding `/etc/hosts` (alternatives to the name→loopback step)

`/etc/hosts` is the simplest name override. pf can't match DNS names (it's IP
layer), so dropping `/etc/hosts` means overriding DNS another way or redirecting
by IP:

- **`/etc/resolver/<fqdn>` + a local DNS responder** *(most surgical)*: macOS
  scoped-resolver file routes just that FQDN to a loopback DNS server masqr runs,
  answering `A = 127.0.0.1`; pf still does the port. Precise, rotation-proof.
  Costs: one-time root (the resolver file), masqr runs a DNS responder, and it
  **only works if `agy` uses the system/cgo resolver** (mDNSResponder honors
  `/etc/resolver`; Go's *pure* resolver ignores it) — **unverified, needs a spike.**
- **pf `rdr` by destination IP** *(no DNS change)*: redirect packets `to
  <google-IPs> :443 -> :8443` and recover the original dest via `/dev/pf`
  `DIOCNATLOOK`. Costs: Google IPs rotate (need a refreshed pf table), loop
  avoidance (exempt masqr's uid or it redirects its own forward), root for natlook.
- **Network Extension** (DNS-proxy / transparent-proxy provider): system-wide, no
  `/etc/hosts`, no per-session root after install — but needs a signed, notarized
  app + user approval. Heavyweight.

## What can't be avoided
- **One-time CA trust** — a Go binary on macOS trusts via the Keychain; there is
  no env-var override (`SSL_CERT_FILE` ignored), and the trust set needs a
  console/GUI auth once (or MDM `.mobileconfig`).
- **One privileged setup step** — `:443` binding or pf install needs root once.

After those two one-time steps, runtime is sudo-free (mode 1).

## Caveats
- The persistent redirect (mode 1) means `agy` routes to masqr's `:8443` always —
  run `agy` via `masqr agy` (which brings the listener up). `--macos-teardown`
  fully reverses it.
- Interactive PTY + child privilege-drop (mode 2) wasn't exercised with a real
  interactive `agy` session — verified with a Go HTTPS client stand-in and a
  non-TTY `id` check.
- `agy`'s prompts are large; the default `--block-on=low` can trip on benign
  findings — use `--on-finding redact` if a normal session gets blocked.
- Windows is not yet supported (same Keychain-style trust-store issue).
