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

# scripts/fullproxy_check.sh — proof that masqr's forward-proxy + MITM mode
# inspects ARBITRARY HTTPS egress, not just the one reverse-proxied upstream.
#
# It builds ./masqr, launches it as a forward proxy in front of a do-nothing
# child (`sleep 30`), then sends an HTTPS POST whose body carries the
# documentation-only sample key AKIAIOSFODNN7EXAMPLE to https://example.com
# THROUGH masqr. It asserts that:
#   1. masqr BLOCKED the request (HTTP 451 + X-Masqr-Blocked: 1), and
#   2. masqr's session log records the `aws-access-key-id` rule firing.
#
# Exit 0 on success (printing the masqr log path), non-zero otherwise.

set -uo pipefail

SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
REPO_DIR="$(dirname "$SCRIPT_DIR")"
cd "$REPO_DIR"

WORK="$(mktemp -d)"
CA="$WORK/ca.pem"
MASQR_ERR="$WORK/masqr.err"
RESP_HDR="$WORK/resp.hdr"
RESP_BODY="$WORK/resp.body"
MASQR_PID=""

# The documentation-only AWS example key (never a live credential).
SAMPLE_KEY="AKIAIOSFODNN7EXAMPLE"

red()   { printf '\033[31m%s\033[0m\n' "$*"; }
green() { printf '\033[32m%s\033[0m\n' "$*"; }
info()  { printf '%s\n' "$*"; }

cleanup() {
    [[ -n "$MASQR_PID" ]] && kill "$MASQR_PID" 2>/dev/null
    [[ -n "$MASQR_PID" ]] && wait "$MASQR_PID" 2>/dev/null
    rm -rf "$WORK"
}
trap cleanup EXIT

fail() { red "FAIL: $*"; exit 1; }

# ── 1. Build ────────────────────────────────────────────────────────────────
info "building ./masqr ..."
go build -o ./masqr . || fail "go build failed"

# ── 2. Pick a free loopback port ────────────────────────────────────────────
find_free_port() {
    local p
    for _ in $(seq 1 50); do
        p=$(( (RANDOM % 20000) + 20000 ))
        # A failed connect means nothing is listening → the port is free.
        if ! (exec 3<>"/dev/tcp/127.0.0.1/$p") 2>/dev/null; then
            echo "$p"; return 0
        fi
        exec 3>&- 2>/dev/null || true
    done
    return 1
}
PORT="$(find_free_port)" || fail "could not find a free port"
ADDR="127.0.0.1:$PORT"
info "masqr forward proxy will listen on $ADDR"

# ── 3. Launch masqr as a forward proxy in front of `sleep 30` ──────────────
# NO_COLOR keeps the banner ANSI-free so we can parse the log path from stderr.
NO_COLOR=1 MASQR_CA_FILE="$CA" ./masqr -a "$ADDR" sleep 30 >"$MASQR_ERR" 2>&1 &
MASQR_PID=$!

# Wait for the proxy port to accept connections and the CA file to appear.
ready=0
for _ in $(seq 1 100); do
    if [[ -s "$CA" ]] && (exec 3<>"/dev/tcp/127.0.0.1/$PORT") 2>/dev/null; then
        exec 3>&- 2>/dev/null || true
        ready=1; break
    fi
    sleep 0.1
done
[[ "$ready" == 1 ]] || { cat "$MASQR_ERR"; fail "masqr did not become ready"; }

# Discover the session log path from the banner ("log: <path>").
LOG_PATH="$(sed -n 's/.*log: //p' "$MASQR_ERR" | head -1 | tr -d '\r' | sed 's/[[:space:]]*$//')"
[[ -n "$LOG_PATH" ]] || fail "could not determine masqr log path from banner"
info "masqr log: $LOG_PATH"

# ── 4. Send an HTTPS request carrying the sample key to an ARBITRARY host ────
# Routed through masqr (HTTPS_PROXY) and trusting the masqr CA (--cacert).
HTTP_CODE="$(curl -sS \
    --proxy "http://$ADDR" \
    --cacert "$CA" \
    -o "$RESP_BODY" -D "$RESP_HDR" \
    -w '%{http_code}' \
    -H 'Content-Type: application/json' \
    --data "{\"prompt\":\"deploy with $SAMPLE_KEY\"}" \
    https://example.com/v1/messages 2>"$WORK/curl.err")" || {
        cat "$WORK/curl.err"; fail "curl through masqr failed (TLS/MITM problem?)"
    }

# ── 5. Assert: blocked on the wire ──────────────────────────────────────────
info "upstream HTTP status via masqr: $HTTP_CODE"
if [[ "$HTTP_CODE" != "451" ]]; then
    info "--- response headers ---"; cat "$RESP_HDR"
    info "--- response body ---";    cat "$RESP_BODY"
    fail "expected HTTP 451 (blocked), got $HTTP_CODE — egress was NOT inspected/blocked"
fi
if ! grep -qi '^X-Masqr-Blocked: 1' "$RESP_HDR"; then
    info "--- response headers ---"; cat "$RESP_HDR"
    fail "missing X-Masqr-Blocked: 1 header — block did not come from masqr"
fi
green "✓ masqr BLOCKED the HTTPS request to example.com (HTTP 451, X-Masqr-Blocked: 1)"

# ── 6. Assert: the rule fired in the log ────────────────────────────────────
if ! grep -q 'aws-access-key-id' "$LOG_PATH"; then
    info "--- tail of masqr log ---"; tail -40 "$LOG_PATH"
    fail "masqr log does not show the 'aws-access-key-id' rule"
fi
green "✓ masqr log shows the 'aws-access-key-id' rule firing"

info ""
green "PASS: forward-proxy MITM inspected and blocked arbitrary HTTPS egress."
info "masqr log path: $LOG_PATH"
exit 0
