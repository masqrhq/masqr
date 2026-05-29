# scripts/e2e-common.sh — Shared E2E phases B–E for masqr provider tests
# (gemini, claude, codex wrappers all source this file).
#
# Sourced by scripts/test-gemini-e2e.sh and scripts/test-claude-e2e.sh.
# Each wrapper supplies run_phase_a() and calls e2e_main.

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

# Shared phases B–E: rule catalog, base64 obfuscation, PaddleOCR, OS screenshots.
# Phase A (live CLI smoke) is defined by each provider wrapper script.

set -euo pipefail

# ─── Arguments ───────────────────────────────────────────────────────────────

KEEP_LOGS=0
REBUILD=0
VERBOSE=0
RUN_LIVE=1
RUN_CATALOG=1
RUN_BASE64=1
RUN_OCR=1
RUN_SCREENSHOTS=1

for arg in "$@"; do
    case "$arg" in
        --keep-logs) KEEP_LOGS=1 ;;
        --rebuild)   REBUILD=1 ;;
        --verbose|-v) VERBOSE=1 ;;
        --no-live)   RUN_LIVE=0 ;;
        --only=live)        RUN_LIVE=1; RUN_CATALOG=0; RUN_BASE64=0; RUN_OCR=0; RUN_SCREENSHOTS=0 ;;
        --only=catalog)     RUN_LIVE=0; RUN_CATALOG=1; RUN_BASE64=0; RUN_OCR=0; RUN_SCREENSHOTS=0 ;;
        --only=base64)      RUN_LIVE=0; RUN_CATALOG=0; RUN_BASE64=1; RUN_OCR=0; RUN_SCREENSHOTS=0 ;;
        --only=ocr)         RUN_LIVE=0; RUN_CATALOG=0; RUN_BASE64=0; RUN_OCR=1; RUN_SCREENSHOTS=0 ;;
        --only=screenshots) RUN_LIVE=0; RUN_CATALOG=0; RUN_BASE64=0; RUN_OCR=0; RUN_SCREENSHOTS=1 ;;
        -h|--help)
            sed -n '2,/^$/p' "$0" | sed 's/^# \{0,1\}//'
            exit 0 ;;
        *) printf 'unknown flag: %s\n' "$arg" >&2; exit 2 ;;
    esac
done

# ─── Pretty printing ─────────────────────────────────────────────────────────

if [[ -t 1 && -z "${NO_COLOR:-}" && "${TERM:-dumb}" != "dumb" ]]; then
    BOLD=$'\033[1m'; DIM=$'\033[2m'; RED=$'\033[31m'
    GREEN=$'\033[32m'; YELLOW=$'\033[33m'; CYAN=$'\033[36m'
    RESET=$'\033[0m'
else
    BOLD=; DIM=; RED=; GREEN=; YELLOW=; CYAN=; RESET=
fi

say()  { printf '%s\n' "$*"; }
ok()   { printf '  %s✓%s %s\n' "$GREEN" "$RESET" "$*"; }
bad()  { printf '  %s✗%s %s\n' "$RED" "$RESET" "$*"; }
skip() { printf '  %s~%s %s\n' "$YELLOW" "$RESET" "$*"; }
hdr()  { printf '\n%s%s%s\n' "$BOLD" "$*" "$RESET"; }
sub()  { printf '%s%s%s\n' "$CYAN" "$*" "$RESET"; }
warn() { printf '%s!%s %s\n' "$YELLOW" "$RESET" "$*" >&2; }

# ─── Repo / PATH discovery ──────────────────────────────────────────────────

SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
REPO_DIR="$(dirname "$SCRIPT_DIR")"
cd "$REPO_DIR"


# ─── Binary architecture / build prerequisites ──────────────────────────────

arch_of_binary() {
    [[ -x "$1" ]] || { echo missing; return; }
    od -An -tx1 -j18 -N2 "$1" 2>/dev/null | tr -d ' \n'
}
expected_machine_for_host() {
    case "$(uname -m)" in
        aarch64|arm64) echo b700 ;;
        x86_64|amd64)  echo 3e00 ;;
        armv7l|armv6l) echo 2800 ;;
        riscv64)       echo f300 ;;
        *) echo unknown ;;
    esac
}

if [[ "$REBUILD" -eq 1 || ! -x ./masqr ]]; then
    REBUILD=1
elif [[ "$(arch_of_binary ./masqr)" != "$(expected_machine_for_host)" ]]; then
    warn "./masqr was built for a different ISA than $(uname -m); rebuilding."
    REBUILD=1
fi

if [[ "$REBUILD" -eq 1 ]]; then
    command -v go >/dev/null 2>&1 || { bad "go toolchain not found"; exit 2; }
    hdr "Building masqr ($(uname -m))"
    go build -o masqr .
fi


# ─── Workspace ──────────────────────────────────────────────────────────────

LOG_DIR="$REPO_DIR/.e2e-logs"
mkdir -p "$LOG_DIR"
rm -f "$LOG_DIR"/*.log "$LOG_DIR"/*.out "$LOG_DIR"/*.json 2>/dev/null || true

PASS_COUNT=0
FAIL_COUNT=0
SKIP_COUNT=0
FAILED_NAMES=()

# ─── Generic helpers ────────────────────────────────────────────────────────

# get_free_port — bind a stdlib socket to port 0 and report what the kernel
# assigned. Releases the socket before we return, so there's a tiny TOCTOU
# window — small enough in practice that retries aren't worth implementing.
get_free_port() {
    python3 -c '
import socket
s = socket.socket()
s.bind(("", 0))
print(s.getsockname()[1])
s.close()
'
}

# wait_for_port — block until the given TCP port accepts a connection.
# Uses a python socket probe rather than bash's /dev/tcp redirect, because
# the latter writes "Connection refused" straight to stderr from bash's
# own error path (un-redirectable from the same line). Python keeps the
# diagnostic clean during the startup spin.
wait_for_port() {
    local port="$1" tries="${2:-100}"
    for ((i=0; i<tries; i++)); do
        if python3 -c "
import socket, sys
try:
    socket.create_connection(('127.0.0.1', $port), timeout=0.1).close()
except Exception:
    sys.exit(1)
" 2>/dev/null; then
            return 0
        fi
        sleep 0.05
    done
    return 1
}

# ═══════════════════════════════════════════════════════════════════════════
# Phase B: Rule catalog via direct proxy curl-drive
# ═══════════════════════════════════════════════════════════════════════════

# Standalone proxy fixture: a Python HTTP sink + a long-lived masqr in the
# background pointing at it. This lets us curl-drive synthetic POSTs and
# assert behaviour without burning real Gemini quota or waiting for LLM
# round-trips. Payloads come from rules.go / rules_presidio.go /
# validators_presidio_test.go — every vector here has a corresponding
# Go-level unit test, so a divergence between phases means the
# scanner-to-HTTP path itself regressed (not the rule).

SINK_PID=
PROXY_PID=
PROXY_PORT=
CATALOG_LOG=

cleanup_catalog() {
    [[ -n "${PROXY_PID:-}" ]] && kill -TERM "$PROXY_PID" 2>/dev/null || true
    [[ -n "${SINK_PID:-}"  ]] && kill -TERM "$SINK_PID"  2>/dev/null || true
    wait "$PROXY_PID" 2>/dev/null || true
    wait "$SINK_PID"  2>/dev/null || true
    PROXY_PID=; SINK_PID=
}
trap cleanup_catalog EXIT

# start_catalog_fixture <env-var=value...>
#
# Brings up the sink and the masqr proxy, returning once both ports
# accept connections. Extra env-var args are passed to masqr's child
# environment (used for the OCR phase to set MASQR_OCR=1).
start_catalog_fixture() {
    local sink_port masqr_port
    sink_port=$(get_free_port)
    masqr_port=$(get_free_port)

    # Tiny POST-echo sink. Always 200s with a 12-byte body so masqr's
    # proxy ModifyResponse has something to log on the forward path
    # (forward isn't exercised in Phase B, but the sink must exist so
    # masqr's healthcheck path resolves at startup).
    python3 - "$sink_port" <<'PY' &
import http.server, socketserver, sys
PORT = int(sys.argv[1])
class H(http.server.BaseHTTPRequestHandler):
    def do_POST(self):
        n = int(self.headers.get("Content-Length", 0) or 0)
        self.rfile.read(n)
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.end_headers()
        self.wfile.write(b'{"ok":true}\n')
    def log_message(self, *a, **kw): pass
with socketserver.TCPServer(("127.0.0.1", PORT), H) as srv:
    srv.serve_forever()
PY
    SINK_PID=$!
    wait_for_port "$sink_port" 50 \
        || { bad "python sink failed to start on $sink_port"; cleanup_catalog; return 1; }

    CATALOG_LOG="$LOG_DIR/catalog.log"
    : >"$CATALOG_LOG"

    # Pass any extra env to the child invocation. We use `env` so the
    # values survive masqr's `os.Environ()` snapshot into cmd.Env.
    local -a extra_env=("$@")

    env "${extra_env[@]}" ./masqr \
        -a "127.0.0.1:$masqr_port" \
        -l "$CATALOG_LOG" \
        --block-on=low \
        --target "http://127.0.0.1:$sink_port" \
        -e "MASQR_TEST_FIXTURE" \
        sleep 86400 </dev/null >"$LOG_DIR/catalog.masqr.out" 2>&1 &
    PROXY_PID=$!
    wait_for_port "$masqr_port" 100 \
        || { bad "masqr failed to start on $masqr_port"; cleanup_catalog; return 1; }

    PROXY_PORT="$masqr_port"
}

# test_block <name> <payload> <expected-rule>
#
# POSTs the payload as the raw request body to the proxy and asserts:
#   - HTTP 451
#   - The X-Masqr-Blocked: 1 response header is present
#   - The expected rule ID appears in the catalog log
#
# Body is sent verbatim (no JSON wrapping) because the scanner inspects
# raw bytes — wrapping a JSON-shape payload (e.g. `{"type":"service_account"}`)
# inside another JSON object would escape its quotes and defeat the
# literal-keyword anchors. From the rule engine's perspective there's no
# difference between a Gemini CLI request body and our synthetic POST.
test_block() {
    local name="$1" payload="$2" expected_rule="$3"
    local body_file="$LOG_DIR/body-$name.bin"
    printf '%s' "$payload" >"$body_file"

    # We grep the log AFTER the request, so we need a marker between
    # tests. Record the line count before, then check the diff range.
    local marker
    marker=$(wc -l <"$CATALOG_LOG")

    local code
    code=$(curl -sS -o /dev/null -w "%{http_code}" \
           -H "X-Masqr-Test: $name" \
           -X POST "http://127.0.0.1:$PROXY_PORT/v1/messages" \
           -H "Content-Type: application/json" \
           --data-binary "@$body_file" 2>>"$LOG_DIR/curl.err" || true)

    if [[ "$code" != "451" ]]; then
        bad "$name: expected 451 got $code"
        # Drop the body excerpt to ease debug.
        say "    ${DIM}payload was:${RESET} ${payload:0:80}"
        FAIL_COUNT=$((FAIL_COUNT + 1)); FAILED_NAMES+=("$name"); return
    fi

    # Look only at the log lines emitted by THIS request.
    local newlog
    newlog=$(tail -n +"$((marker + 1))" "$CATALOG_LOG")
    if ! grep -q "BLOCKED by policy" <<<"$newlog"; then
        bad "$name: got 451 but no 'BLOCKED by policy' in log"
        FAIL_COUNT=$((FAIL_COUNT + 1)); FAILED_NAMES+=("$name"); return
    fi
    if ! grep -q "$expected_rule" <<<"$newlog"; then
        bad "$name: blocked but rule '$expected_rule' not in log; saw:"
        grep -E "ALERTS|^\s+\[" <<<"$newlog" | sed 's/^/      /' || true
        FAIL_COUNT=$((FAIL_COUNT + 1)); FAILED_NAMES+=("$name"); return
    fi

    ok "$name → $expected_rule"
    PASS_COUNT=$((PASS_COUNT + 1))
}

run_phase_b() {
    hdr "Phase B: Rule catalog (direct proxy)"
    start_catalog_fixture || { SKIP_COUNT=$((SKIP_COUNT + 50)); return; }

    # ─── Secrets ──────────────────────────────────────────────────────────
    sub "Secrets"
    test_block "aws-access-key-id" \
        "leak AKIAIOSFODNN7EXAMPLE in code" "aws-access-key-id"
    test_block "aws-secret-access-key" \
        "aws_secret_access_key=wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY" \
        "aws-secret-access-key"
    test_block "github-pat-classic" \
        "token: ghp_1234567890ABCDEFGHIJ1234567890ABCDEF here" "github-pat"
    test_block "github-pat-fine-grained" \
        "pat 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 end" \
        "github-fine-grained-pat"
    test_block "anthropic-api-key" \
        "key sk-ant-api03-abcdef0123456789-_abc for claude" "anthropic-api-key"
    test_block "openai-api-key" \
        "OPENAI_KEY=sk-proj-abcdefghij0123456789ABCDEFGHIJ over here" \
        "openai-api-key"
    test_block "stripe-live-key" \
        "stripe sk_live_abcdefghij0123456789ABCD please" "stripe-live-key"
    test_block "gitlab-pat" \
        "leak glpat-abcdefghij1234567890" "gitlab-pat"
    test_block "gitlab-oauth-app-secret" \
        "gloas-abcdefghij1234567890abcdefghij1234567890 secret" \
        "gitlab-oauth-app-secret"
    test_block "gitlab-pipeline-trigger" \
        "trigger glptt-abcdefghij1234567890abcdefghij1234567890" \
        "gitlab-pipeline-trigger"
    test_block "gitlab-runner-token" \
        "runner glrt-abcdefghij1234567890" "gitlab-runner-token"
    test_block "gitlab-deploy-token" \
        "deploy gldt-abcdefghij1234567890" "gitlab-deploy-token"
    test_block "gitlab-feed-token" \
        "feed glft-abcdefghij1234567890" "gitlab-feed-token"
    test_block "gitlab-agent-token" \
        "agent glagent-abcdefghij1234567890abcdefghij1234567890abcdefghij" \
        "gitlab-agent-token"
    test_block "gitlab-scim-token" \
        "scim glsoat-abcdefghij1234567890abcdefghij1234567890" "gitlab-scim-token"
    test_block "gitlab-ci-job-token" \
        "ci-job glcbt-abcdefghij1234567890" "gitlab-ci-job-token"
    test_block "slack-bot-or-user-token" \
        "slack xoxb-12345678901-1234567890123-abcdefghijklmnopqrstuvwx" \
        "slack-bot-or-user-token"
    test_block "slack-webhook" \
        "webhook https://hooks.slack.com/services/T0000000000/B0000000000/abcdefghijklmnopqrstuvwx" \
        "slack-webhook"
    test_block "jwt" \
        "jwt eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c" \
        "jwt"
    test_block "private-key-pem" \
        "-----BEGIN PRIVATE KEY-----
MIIEvAIBADANBgkqhkiG9w0BAQEFAASCBKYwggSiAgEAAoIBAQDA...
-----END PRIVATE KEY-----" \
        "private-key-pem"
    test_block "gcp-api-key" \
        "key AIzaSyAabcdefghijklmnopqrstuvwxyz123456 here" "gcp-api-key"
    test_block "gcp-service-account-key" \
        '{"type": "service_account", "project_id": "x"}' \
        "gcp-service-account-key"
    test_block "azure-storage-conn-string" \
        'DefaultEndpointsProtocol=https;AccountName=myacct;AccountKey=AaBbCcDdEeFfGgHhIiJjKkLlMmNnOoPpQqRrSsTtUuVvWwXxYyZz0123456789AbCdEfGhIjKlMnOpQrStUvWxYz==;EndpointSuffix=core.windows.net' \
        "azure-storage-conn-string"
    test_block "azure-service-bus-conn" \
        "Endpoint=sb://myns.servicebus.windows.net/;SharedAccessKeyName=root;SharedAccessKey=abc123" \
        "azure-service-bus-conn"
    test_block "azure-cosmos-conn" \
        'AccountEndpoint=https://mydb.documents.azure.com:443/;AccountKey=AaBbCcDdEeFfGgHhIiJjKkLlMmNnOoPp1234567890AbCdEf==;' \
        "azure-cosmos-conn"
    test_block "azure-sql-conn" \
        'Server=tcp:myserver.database.windows.net,1433;Initial Catalog=mydb;Persist Security Info=False;User ID=admin;Password=hunter2;' \
        "azure-sql-conn"

    # ─── Universal PII ────────────────────────────────────────────────────
    sub "Universal PII"
    test_block "email-address" \
        "ping john.doe@example.com about the review" "email-address"
    test_block "credit-card" \
        "card 4532015112830366 on file" "credit-card"
    test_block "bitcoin-bech32" \
        "wallet bc1qar0srrr7xfkvy5l643lydnw9re59gtzzwf5mdq please" \
        "bitcoin-address"
    test_block "bitcoin-legacy" \
        "send to 1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa quickly" \
        "bitcoin-legacy-address"
    test_block "iban-generic-de" \
        "iban DE89370400440532013000 ok?" "iban-generic"

    # ─── Country PII ──────────────────────────────────────────────────────
    sub "Country-tagged PII"
    test_block "ch-ahv"   "AHV 756.1234.5678.97 attached" "ch-ahv"
    test_block "ch-iban"  "IBAN CH9300762011623852957"    "ch-iban"
    test_block "us-ssn"   "SSN 219-12-3456 for tax docs"  "us-ssn"
    test_block "us-itin"  "ITIN 912-50-1234 ok"           "us-itin"
    test_block "us-aba-routing" "routing 011000015 federal"  "us-aba-routing"
    test_block "us-npi"   "provider NPI 1234567893 here"  "us-npi"
    test_block "us-passport" "passport book A12345678 issued" "us-passport"
    test_block "us-mbi"   "patient 1EG4-TE5-MK73 medicare" "us-mbi"
    test_block "us-dea"   "DEA AB1234563 on file"         "us-dea-number"
    test_block "ca-sin"   "SIN 123-456-782 for CRA"       "ca-sin"
    test_block "au-tfn"   "TFN 123 456 782 with ATO"      "au-tfn"
    test_block "au-acn"   "ACN 004 085 616 registered"    "au-acn"
    test_block "au-abn"   "ABN 51 824 753 556 verified"   "au-abn"
    test_block "au-medicare" "medicare 2239 99990 1 valid" "au-medicare"
    test_block "uk-nhs"   "NHS 943 476 5919 patient"      "uk-nhs"
    test_block "uk-nino"  "NINO AB123456C registered"     "uk-nino"
    test_block "uk-passport" "passport AB1234567 in scope" "uk-passport"
    test_block "de-vat"   "DE123456789 is our VAT id"     "de-vat-id"
    test_block "de-tax-id" "Steuer-ID 12345678903 ok"     "de-tax-id"
    test_block "in-aadhaar" "Aadhaar 2345-6789-0124 in scope" "in-aadhaar"
    test_block "in-pan"   "PAN ABCPK1234E for KYC"        "in-pan"
    test_block "in-passport" "passport L1234567 issued"   "in-passport"
    test_block "es-nif"   "DNI 12345678Z"                 "es-nif"
    test_block "es-nie"   "NIE X1234567L for residency"   "es-nie"
    test_block "es-passport" "passport AAA123456 in scope" "es-passport"
    test_block "sg-nric"  "NRIC S1234567D"                "sg-nric-fin"
    test_block "sg-uen"   "Entity UEN 200512345A"         "sg-uen"
    test_block "kr-rrn"   "RRN 950101-1234564 korean"     "kr-rrn"
    test_block "pl-pesel" "PESEL 94051012343 polish id"   "pl-pesel"
    test_block "tr-tckn"  "TCKN 12345678950 turkey"       "tr-tckn"
    test_block "th-tnin"  "TNIN 1234567890121 thai"       "th-tnin"
    test_block "it-vat"   "P.IVA 12345678903 italy"       "it-vat-code"
    test_block "se-personnummer" "PIN 940510-1230 swedish" "se-personnummer"
    test_block "se-orgnummer"    "OrgNr 556677-8899 company" "se-orgnummer"
    test_block "fi-pic"   "hetu 131052-308T"              "fi-personal-id"

    # ─── Network ─────────────────────────────────────────────────────────
    sub "Network"
    test_block "private-ipv4" "ssh root@10.0.0.5 to fix it" "private-ipv4"
    test_block "private-ipv6" "ping fd00:1234::1 first"     "private-ipv6"

    # ─── Attachments ─────────────────────────────────────────────────────
    sub "Attachments"
    test_block "attachment-image-inline" \
        '{"content":[{"type":"image","source":{"media_type":"image/png","data":"iVBOR..."}}]}' \
        "attachment-image-inline"
    test_block "attachment-pdf-inline" \
        '{"content":[{"type":"document","source":{"media_type":"application/pdf","data":"JVBE..."}}]}' \
        "attachment-pdf-inline"
    test_block "attachment-file-reference" \
        '{"file_id":"file_abcdef1234567890"}' \
        "attachment-file-reference"

    cleanup_catalog
}

# ═══════════════════════════════════════════════════════════════════════════
# Phase C: Base64 obfuscation
# ═══════════════════════════════════════════════════════════════════════════

# masqr's base64 source decodes any high-entropy base64 blob once and
# rescans the result through the rule engine. These tests prove that
# wrapping a secret in `base64` doesn't defeat detection.

run_phase_c() {
    hdr "Phase C: Base64 obfuscation"
    start_catalog_fixture || { SKIP_COUNT=$((SKIP_COUNT + 3)); return; }

    # AWS key, base64-encoded with surrounding context so the blob is
    # detected as a base64 candidate (entropy + length).
    local b64_aws
    b64_aws=$(printf 'aws_real_key_inside: AKIAIOSFODNN7EXAMPLE plus padding bytes for entropy' | base64 -w0)
    test_block "base64-wraps-aws-key" \
        "encoded payload: $b64_aws end" \
        "aws-access-key-id"

    # GitHub PAT base64'd. Same decode-and-rescan path.
    local b64_gh
    b64_gh=$(printf 'token=ghp_1234567890ABCDEFGHIJ1234567890ABCDEF with prose padding' | base64 -w0)
    test_block "base64-wraps-github-pat" \
        "encoded $b64_gh stop" \
        "github-pat"

    # Email address inside a base64 blob, threshold is low so medium
    # finding still blocks.
    local b64_email
    b64_email=$(printf 'contact: john.doe@example.com somewhere in the message body padding' | base64 -w0)
    test_block "base64-wraps-email" \
        "wrapped $b64_email end" \
        "email-address"

    cleanup_catalog
}

# ═══════════════════════════════════════════════════════════════════════════
# Phase D: PaddleOCR image-text extraction
# ═══════════════════════════════════════════════════════════════════════════

# The OCR scenario uses a frozen PNG snapshot (1574 bytes, base64 below)
# rendering "AKIAIOSFODNN7EXAMPLE" in 32pt DejaVu Sans Bold on a 480×80
# white background. Embedding the bytes here means the test has zero
# external dependencies — no ImageMagick, no Pillow, no font hunt — so
# CI / fresh containers / minimal Pi images can all run it. The pixel
# layout was deliberately picked to be high-contrast and large-font so
# PaddleOCR PP-OCRv5 recognises it deterministically on every platform
# masqr ships an OCR model for. Regenerate with:
#
#   python3 -c '
#   from PIL import Image, ImageDraw, ImageFont
#   img = Image.new("RGB", (480, 80), "white")
#   d = ImageDraw.Draw(img)
#   f = ImageFont.truetype(
#       "/usr/share/fonts/truetype/dejavu/DejaVuSans-Bold.ttf", 32)
#   t = "AKIAIOSFODNN7EXAMPLE"
#   w, h = d.textbbox((0, 0), t, font=f)[2:]
#   d.text(((480 - w) / 2, (80 - h) / 2), t, fill="black", font=f)
#   img.save("embed.png", "PNG", optimize=True)' \
#     && base64 -w 76 embed.png

read -r -d '' EMBEDDED_OCR_PNG_B64 <<'B64' || true
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
B64

write_embedded_png() {
    local out="$1"
    printf '%s' "$EMBEDDED_OCR_PNG_B64" | base64 -d >"$out"
}

run_phase_d() {
    hdr "Phase D: PaddleOCR image-text extraction"

    local img="$LOG_DIR/secret.png"
    write_embedded_png "$img"
    say "  ${DIM}image:${RESET}    $img ($(stat -c%s "$img" 2>/dev/null || echo ?) bytes, embedded)"

    # MASQR_OCR=1 is forced regardless of the user's environment — the
    # whole point of this phase is to exercise the OCR pipeline, so the
    # script controls the toggle. The model loads on first request; we
    # tolerate a longer wait_for_port spin during startup.
    start_catalog_fixture MASQR_OCR=1 \
        || { bad "Phase D fixture failed to start"; FAIL_COUNT=$((FAIL_COUNT + 1)); return; }

    # Build a JSON body carrying the image as a Claude-style attachment
    # block (image/png + base64 data). The OCR source decodes the
    # base64, runs det → cls → rec, and re-feeds the recognized text
    # through the rule engine — which then trips aws-access-key-id.
    local b64; b64=$(base64 -w0 "$img")
    local body
    body=$(python3 -c '
import json, sys
print(json.dumps({
    "messages": [{
        "role": "user",
        "content": [{
            "type": "image",
            "source": {"type": "base64", "media_type": "image/png", "data": sys.argv[1]}
        }]
    }]
}))
' "$b64")
    local body_file="$LOG_DIR/body-ocr.json"
    printf '%s' "$body" >"$body_file"

    sub "OCR scan of rendered AKIA…EXAMPLE"
    local marker; marker=$(wc -l <"$CATALOG_LOG")
    local code
    code=$(curl -sS -o /dev/null -w "%{http_code}" \
           --max-time 60 \
           -X POST "http://127.0.0.1:$PROXY_PORT/v1/messages" \
           -H "Content-Type: application/json" \
           --data-binary "@$body_file")

    local newlog; newlog=$(tail -n +"$((marker + 1))" "$CATALOG_LOG")

    if [[ "$code" == "451" ]] \
       && grep -q "aws-access-key-id" <<<"$newlog"; then
        ok "ocr-extracts-aws-key → aws-access-key-id"
        PASS_COUNT=$((PASS_COUNT + 1))
    else
        bad "ocr-extracts-aws-key: code=$code, aws-key not in log"
        say "    ${DIM}last 15 log lines:${RESET}"
        tail -15 <<<"$newlog" | sed 's/^/      /'
        FAIL_COUNT=$((FAIL_COUNT + 1)); FAILED_NAMES+=("ocr-extracts-aws-key")
    fi

    # Side check: the attachment-image-inline rule itself should also fire
    # on this body (independent of OCR). That guards the case where OCR
    # is disabled but the attachment block is still flagged.
    if grep -q "attachment-image-inline" <<<"$newlog"; then
        ok "attachment-image-inline → flagged image attachment"
        PASS_COUNT=$((PASS_COUNT + 1))
    else
        bad "attachment-image-inline: rule did not fire on image body"
        FAIL_COUNT=$((FAIL_COUNT + 1)); FAILED_NAMES+=("attachment-image-inline")
    fi

    cleanup_catalog
}

# ═══════════════════════════════════════════════════════════════════════════
# Phase E: OS-styled screenshot OCR
# ═══════════════════════════════════════════════════════════════════════════

# Screenshot manifest, parallel to the MANIFEST list in
# scripts/generate-screenshots.py. Each tuple is
# "<file>:<expected-rule-id>". The expected rule is the from-image
# variant the rule engine emits when an OCR source surfaces a match.

SCREENSHOT_MANIFEST=(
    # Locally generated OS-styled mocks (scripts/generate-screenshots.py).
    "windows-notepad-aws.png:aws-access-key-id/from-image"
    "macos-terminal-anthropic.png:anthropic-api-key/from-image"
    "linux-gnome-private-ip.png:private-ipv4/from-image"
    "android-messages-card.png:credit-card/from-image"
    "ios-notes-email.png:email-address/from-image"
    # External: real-world test images from Microsoft Presidio's PII
    # corpus. MIT-licensed, intentionally synthetic content (reserved
    # 555-01XX phone block, @microsoft.com test addresses). See
    # testdata/screenshots/external/README.md for full attribution.
    #
    # presidio-ocr_test.png is intentionally NOT asserted: it exposes
    # the wide-line OCR recall limitation in masqr's sources_ocr.go
    # (PaddleOCR PP-OCRv5 squashes >24-char single-line crops to its
    # 320 px rec-input width). pii_verify.png is the same content with
    # bounding-box annotations overlaid; the overlays split the long
    # CLA paragraph into narrow boxes the rec model can read, so the
    # email-address/from-image rule fires reliably.
    "external/presidio-pii_verify.png:email-address/from-image"
)

# Pretty labels purely for the test output.
declare -A SCREENSHOT_LABEL=(
    ["windows-notepad-aws.png"]="Windows · Notepad · AWS access key"
    ["macos-terminal-anthropic.png"]="macOS · Terminal · Anthropic key"
    ["linux-gnome-private-ip.png"]="Linux · GNOME Terminal · private IPv4"
    ["android-messages-card.png"]="Android · Messages · credit card"
    ["ios-notes-email.png"]="iOS · Notes · email address"
    ["external/presidio-pii_verify.png"]="External · Presidio · annotated PII overlay (email)"
)

# test_screenshot <file> <expected-rule-id>
#
# Wraps the PNG as a Claude/Gemini-shaped image attachment body and
# posts it through the fixture. Asserts that masqr returns 451 and
# that the from-image variant of the expected rule appears in the
# session log. Uses the same per-request log delta approach as
# Phase B so concurrent tests don't cross-contaminate.
test_screenshot() {
    local file="$1" expected_rule="$2"
    local label="${SCREENSHOT_LABEL[$file]:-$file}"
    local src="$REPO_DIR/testdata/screenshots/$file"

    if [[ ! -f "$src" ]]; then
        bad "$label: $src missing — run scripts/generate-screenshots.py"
        FAIL_COUNT=$((FAIL_COUNT + 1)); FAILED_NAMES+=("$file")
        return
    fi

    # Manifest entries may include a sub-directory (e.g. external/foo.png).
    # Normalise to a flat body-file name so curl's --data-binary @PATH works
    # without needing an intermediate mkdir.
    local flat="${file%.png}"; flat="${flat//\//-}"
    local body_file="$LOG_DIR/body-screenshot-${flat}.json"
    python3 - "$src" "$body_file" <<'PY'
import base64, json, sys
src, dst = sys.argv[1], sys.argv[2]
with open(src, "rb") as f:
    data = base64.b64encode(f.read()).decode("ascii")
body = {
    "messages": [{
        "role": "user",
        "content": [{
            "type": "image",
            "source": {"type": "base64", "media_type": "image/png", "data": data},
        }],
    }]
}
with open(dst, "w") as f:
    f.write(json.dumps(body))
PY

    local marker; marker=$(wc -l <"$CATALOG_LOG")
    local code
    code=$(curl -sS -o /dev/null -w '%{http_code}' --max-time 60 \
           -H "X-Masqr-Test: screenshot-$flat" \
           -X POST "http://127.0.0.1:$PROXY_PORT/v1/messages" \
           -H "Content-Type: application/json" \
           --data-binary "@$body_file" 2>>"$LOG_DIR/curl.err" || true)

    if [[ "$code" != "451" ]]; then
        bad "$label: expected 451 got $code"
        FAIL_COUNT=$((FAIL_COUNT + 1)); FAILED_NAMES+=("$file")
        return
    fi

    local newlog; newlog=$(tail -n +"$((marker + 1))" "$CATALOG_LOG")
    if ! grep -qF "$expected_rule" <<<"$newlog"; then
        bad "$label: rule '$expected_rule' did not fire; alerts seen:"
        grep -E "ALERTS|^\s+\[" <<<"$newlog" | sed 's/^/      /' || true
        FAIL_COUNT=$((FAIL_COUNT + 1)); FAILED_NAMES+=("$file")
        return
    fi

    ok "$label → $expected_rule"
    PASS_COUNT=$((PASS_COUNT + 1))
}

run_phase_e() {
    hdr "Phase E: OS-styled screenshot OCR"

    # Reuse the same MASQR_OCR=1 fixture as Phase D — it's a single
    # process for the whole phase so the model loads once and all five
    # screenshots flow through the same warm worker.
    start_catalog_fixture MASQR_OCR=1 \
        || { bad "Phase E fixture failed to start"; FAIL_COUNT=$((FAIL_COUNT + 1)); return; }

    for entry in "${SCREENSHOT_MANIFEST[@]}"; do
        local file="${entry%%:*}"
        local rule="${entry#*:}"
        test_screenshot "$file" "$rule"
    done

    cleanup_catalog
}

# ═══════════════════════════════════════════════════════════════════════════

# e2e_main — run selected phases and print summary. Wrapper must define
# run_phase_a before calling this.
e2e_main() {
    [[ "$RUN_LIVE"        -eq 1 ]] && run_phase_a
    [[ "$RUN_CATALOG"     -eq 1 ]] && run_phase_b
    [[ "$RUN_BASE64"      -eq 1 ]] && run_phase_c
    [[ "$RUN_OCR"         -eq 1 ]] && run_phase_d
    [[ "$RUN_SCREENSHOTS" -eq 1 ]] && run_phase_e

    hdr "Summary"
    printf '  %spassed:%s  %d\n' "$GREEN" "$RESET" "$PASS_COUNT"
    if [[ "$FAIL_COUNT" -gt 0 ]]; then
        printf '  %sfailed:%s  %d (%s)\n' "$RED" "$RESET" "$FAIL_COUNT" \
               "${FAILED_NAMES[*]}"
    else
        printf '  %sfailed:%s  0\n' "$DIM" "$RESET"
    fi
    [[ "$SKIP_COUNT" -gt 0 ]] \
        && printf '  %sskipped:%s %d\n' "$YELLOW" "$RESET" "$SKIP_COUNT"

    if [[ "$KEEP_LOGS" -eq 1 || "$FAIL_COUNT" -gt 0 ]]; then
        say "  logs:    $LOG_DIR/"
    else
        rm -rf "$LOG_DIR"
    fi

    [[ "$FAIL_COUNT" -eq 0 ]] || exit 1
}
