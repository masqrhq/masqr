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

# scripts/test-agy-e2e.sh — Comprehensive E2E for masqr + Google Antigravity.
#
# Five phases (A live CLI + B–E shared). See scripts/e2e-common.sh for
# phases B–E. Phase A drives `./masqr agy -p "<prompt>"` and asserts every
# session log contains at least one `/v1internal:*` request (CLOUD_CODE_URL
# plaintext-redirect regression guard).
#
# Note: agy's streaming print path swallows masqr's synthetic block message and
# can still exit 0, so a blocked scenario is verified against masqr's own log
# ("BLOCKED by policy") rather than the CLI exit code.
#
# Usage:
#   scripts/test-agy-e2e.sh                # all phases (A..E)
#   scripts/test-agy-e2e.sh --no-live      # phases B,C,D,E only
#   scripts/test-agy-e2e.sh --only=live    # Phase A only
#   scripts/test-agy-e2e.sh --keep-logs --rebuild --verbose
#
# Exit: 0 iff every executed scenario passes.

SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=scripts/e2e-common.sh
source "$SCRIPT_DIR/e2e-common.sh"

if ! grep -aq CLOUD_CODE_URL ./masqr; then
    bad "./masqr is missing the Antigravity provider profile (CLOUD_CODE_URL)."
    bad "rebuild with: go build -o masqr ."
    exit 2
fi

# run_live_scenario <name> <expected: block|forward> <block-on> <prompt> [rule]
run_live_scenario() {
    local name="$1" expected="$2" block_on="$3" prompt="$4" expected_rule="${5:-}"
    local logfile="$LOG_DIR/$name.log"
    local cli_out="$LOG_DIR/$name.out"
    local exit_code=0
    local started ended elapsed

    sub "▸ $name"
    say "  ${DIM}prompt:${RESET}    $prompt"
    say "  ${DIM}block-on:${RESET}  $block_on"
    say "  ${DIM}expected:${RESET}  $expected${expected_rule:+ (rule: $expected_rule)}"

    started=$(date +%s)
    set +e
    timeout 150 ./masqr -l "$logfile" --block-on="$block_on" \
        agy -p "$prompt" >"$cli_out" 2>&1
    exit_code=$?
    set -e
    ended=$(date +%s)
    elapsed=$((ended - started))

    say "  ${DIM}cli exit:${RESET}  $exit_code  ${DIM}(${elapsed}s)${RESET}"
    [[ "$VERBOSE" -eq 1 ]] && sed 's/^/      /' "$cli_out" | tail -25

    if [[ ! -s "$logfile" ]]; then
        bad "masqr log empty — process never wrote anything"
        FAIL_COUNT=$((FAIL_COUNT + 1)); FAILED_NAMES+=("$name"); return
    fi

    if ! grep -q "REQUEST POST /v1internal:" "$logfile"; then
        bad "no /v1internal:* request recorded — agy bypassed masqr"
        sed -n '1,20p' "$logfile" | sed 's/^/      /'
        FAIL_COUNT=$((FAIL_COUNT + 1)); FAILED_NAMES+=("$name"); return
    fi

    local v1count
    v1count=$(grep -cE "REQUEST POST /v1internal:" "$logfile" || true)

    case "$expected" in
        block)
            # agy can swallow the block message and exit 0; trust the masqr log.
            if ! grep -q "BLOCKED by policy" "$logfile"; then
                bad "expected 'BLOCKED by policy' in log, none found"
                FAIL_COUNT=$((FAIL_COUNT + 1)); FAILED_NAMES+=("$name"); return
            fi
            if [[ -n "$expected_rule" ]] && ! grep -q "$expected_rule" "$logfile"; then
                bad "expected rule '$expected_rule'; alerts seen:"
                grep -E "ALERTS|^\s+\[" "$logfile" | sed 's/^/      /' || true
                FAIL_COUNT=$((FAIL_COUNT + 1)); FAILED_NAMES+=("$name"); return
            fi
            local blocks; blocks=$(grep -cE "BLOCKED by policy" "$logfile" || true)
            ok "blocked $blocks call(s) over $v1count proxied request(s)${expected_rule:+ — rule $expected_rule fired}"
            PASS_COUNT=$((PASS_COUNT + 1))
            ;;
        forward)
            if [[ $exit_code -ne 0 ]]; then
                bad "expected exit 0 (forward), got $exit_code"
                tail -20 "$cli_out" | sed 's/^/      /'
                FAIL_COUNT=$((FAIL_COUNT + 1)); FAILED_NAMES+=("$name"); return
            fi
            if grep -q "BLOCKED by policy" "$logfile"; then
                bad "unexpected block in log:"
                grep -E "ALERTS|^\s+\[|BLOCKED" "$logfile" | sed 's/^/      /'
                FAIL_COUNT=$((FAIL_COUNT + 1)); FAILED_NAMES+=("$name"); return
            fi
            if ! grep -qE "RESPONSE 200 /v1internal:" "$logfile"; then
                bad "no 200 response on a /v1internal:* call"
                FAIL_COUNT=$((FAIL_COUNT + 1)); FAILED_NAMES+=("$name"); return
            fi
            ok "forwarded $v1count call(s) to cloudcode-pa, model replied 200"
            PASS_COUNT=$((PASS_COUNT + 1))
            ;;
    esac
}

run_phase_a() {
    hdr "Phase A: Live Antigravity (agy) CLI"

    if ! command -v agy >/dev/null 2>&1; then
        skip "agy CLI not installed"
        SKIP_COUNT=$((SKIP_COUNT + 3))
        return
    fi

    run_live_scenario "A1-critical-aws-key" block critical \
        "Hello, my AWS access key is AKIAIOSFODNN7EXAMPLE, please remember it" \
        "aws-access-key-id"

    run_live_scenario "A2-pii-email-low-floor" block low \
        "Please email me a recap at user@example.com" \
        "email-address"

    run_live_scenario "A3-clean-forward" forward critical \
        "What is two plus two? Reply with just the number."
}

e2e_main
