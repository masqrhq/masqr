/*
Copyright 2026 masqr contributors

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

package main

import (
	"encoding/json"
	"fmt"
	"net/http"
	"regexp"
	"strings"
)

// Policy is the request-time enforcement decision surface. Masqr always blocks
// on a triggering match — Threshold controls how loud a match has to be.
// Provider lets writeBlockResponse pick a body shape the upstream CLI knows
// how to render (Anthropic envelope by default, google.rpc.Status for the
// Gemini family, OpenAI envelope for codex/openai).
type Policy struct {
	Threshold Severity
	Provider  Provider
	OnFinding OnFinding
}

// OnFinding controls what masqr does when a request contains one or more
// triggering matches.
//
//   - OnFindingBlock (default): return 451 on any finding, never rewrite
//     anything. Fail-closed posture — the upstream API is never contacted
//     when masqr sees something it flagged.
//   - OnFindingRedact: rewrite the request body in place, replacing each
//     finding's span with a stable placeholder (`__EMAIL_1__`,
//     `__CARD_2__`, …) and forward the rewritten body upstream. The
//     placeholder ↔ original mapping is held in a per-session memo, and
//     the proxy substitutes originals back into the response stream
//     before it reaches the CLI. The LLM sees a sanitised prompt; the
//     user sees their own values in the answer; blocked history doesn't
//     stall the conversation. Opt in with `--on-finding=redact`.
//
// In redact mode, if a triggering match can't be safely rewritten in
// place — a URL-borne key, a compressed request body — masqr falls back
// to block for that request. Better a visible 451 than a torn rewrite.
type OnFinding string

const (
	OnFindingBlock  OnFinding = "block"
	OnFindingRedact OnFinding = "redact"
)

func ParseSeverity(s string) (Severity, error) {
	switch Severity(strings.ToLower(strings.TrimSpace(s))) {
	case SevCritical:
		return SevCritical, nil
	case SevHigh:
		return SevHigh, nil
	case SevMedium:
		return SevMedium, nil
	case SevLow:
		return SevLow, nil
	}
	return "", fmt.Errorf("unknown severity %q (want: critical|high|medium|low)", s)
}

// ParseOnFinding accepts "block" or "redact" (case-insensitive, trimmed).
// An empty string maps to the default OnFindingBlock so callers can pass
// the raw flag value without a nil-check.
func ParseOnFinding(s string) (OnFinding, error) {
	switch OnFinding(strings.ToLower(strings.TrimSpace(s))) {
	case OnFindingBlock, "":
		return OnFindingBlock, nil
	case OnFindingRedact:
		return OnFindingRedact, nil
	}
	return "", fmt.Errorf("unknown on-finding %q (want: block|redact)", s)
}

// triggering returns the subset of matches at or above the policy threshold.
func (p Policy) triggering(ms []Match) []Match {
	if len(ms) == 0 {
		return nil
	}
	floor := severityRank(p.Threshold)
	out := make([]Match, 0, len(ms))
	for _, m := range ms {
		if severityRank(m.Severity) >= floor {
			out = append(out, m)
		}
	}
	return out
}

// blockedError is the Anthropic-shaped JSON body returned to Claude-family
// CLIs on a blocked request. The shape lets Claude Code's existing error
// renderer surface it with no special-casing.
type blockedError struct {
	Type  string             `json:"type"`
	Error blockedErrorDetail `json:"error"`
}

type blockedErrorDetail struct {
	Type     string         `json:"type"`
	Message  string         `json:"message"`
	Findings []blockFinding `json:"findings"`
}

// googleBlockedError mirrors the google.rpc.Status envelope that the
// @google/genai SDK (and therefore the Gemini CLI) parses for failed
// requests. Returning this shape lets the Gemini CLI print the masqr
// reason through its native error renderer.
type googleBlockedError struct {
	Error googleBlockedDetail `json:"error"`
}

type googleBlockedDetail struct {
	Code    int                       `json:"code"`
	Message string                    `json:"message"`
	Status  string                    `json:"status"`
	Details []googleBlockedDetailItem `json:"details"`
}

type googleBlockedDetailItem struct {
	Type     string         `json:"@type"`
	Findings []blockFinding `json:"findings"`
}

// openAIBlockedError mirrors OpenAI's error response envelope so codex /
// openai CLIs render the masqr message natively.
type openAIBlockedError struct {
	Error openAIBlockedDetail `json:"error"`
}

type openAIBlockedDetail struct {
	Message  string         `json:"message"`
	Type     string         `json:"type"`
	Param    *string        `json:"param"`
	Code     string         `json:"code"`
	Findings []blockFinding `json:"findings"`
}

type blockFinding struct {
	RuleID   string   `json:"rule_id"`
	Category string   `json:"category"`
	Severity Severity `json:"severity"`
	Snippet  string   `json:"snippet"`
	Offset   int      `json:"offset"`
}

func writeBlockResponse(w http.ResponseWriter, matches []Match, provider Provider) {
	findings := make([]blockFinding, 0, len(matches))
	ids := make([]string, 0, len(matches))
	seen := map[string]bool{}
	for _, m := range matches {
		findings = append(findings, blockFinding{
			RuleID:   m.RuleID,
			Category: m.Category,
			Severity: m.Severity,
			Snippet:  m.Snippet,
			Offset:   m.Offset,
		})
		if !seen[m.RuleID] {
			seen[m.RuleID] = true
			ids = append(ids, m.RuleID)
		}
	}
	msg := fmt.Sprintf(
		"masqr blocked the request: detected %s. To proceed: edit the prompt or raise --block-on.",
		strings.Join(ids, ", "),
	)

	status := http.StatusUnavailableForLegalReasons

	var body any
	switch provider.Name {
	case "google-gemini", "google-vertex":
		body = googleBlockedError{
			Error: googleBlockedDetail{
				Code:    status,
				Message: msg,
				Status:  "FAILED_PRECONDITION",
				Details: []googleBlockedDetailItem{{
					Type:     "type.googleapis.com/masqr.BlockedRequest",
					Findings: findings,
				}},
			},
		}
	case "openai":
		body = openAIBlockedError{
			Error: openAIBlockedDetail{
				Message:  msg,
				Type:     "masqr_blocked",
				Code:     "masqr_blocked",
				Findings: findings,
			},
		}
	default: // anthropic, generic
		body = blockedError{
			Type: "error",
			Error: blockedErrorDetail{
				Type:     "masqr_blocked",
				Message:  msg,
				Findings: findings,
			},
		}
	}

	buf, err := json.Marshal(body)
	if err != nil {
		// json.Marshal can't fail on these concrete struct shapes; fall back
		// to a minimal envelope to avoid a half-written response.
		buf = []byte(`{"error":{"message":"masqr blocked the request"}}`)
	}
	if provider.Name == "google-gemini" || provider.Name == "google-vertex" {
		buf = neutralizeForGaxios(buf)
	}

	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("X-Masqr-Blocked", "1")
	w.WriteHeader(status)
	_, _ = w.Write(buf)
}

// gaxiosTriggerWords matches case-insensitive substrings that trigger
// gaxios's defaultErrorRedactor on the response body. The redactor calls
// `redactString(data.response, "data")` which replaces the entire response
// body string with `<<REDACTED> - See errorRedactor option in gaxios for
// configuration>.` whenever the body matches /grant_type=/i, /assertion=/i,
// or /secret/i — the third clause hits masqr because the literal word
// "secret" appears in rule IDs (aws-secret-access-key, …) and the
// "secret" category. Without rewriting, the Gemini CLI displays
// "<<REDACTED>>" instead of masqr's actual block reason.
var gaxiosTriggerWords = regexp.MustCompile(`(?i)secret`)

// neutralizeForGaxios rewrites occurrences of the trigger substring in
// the already-marshalled JSON body. The replacement is intentionally
// shorter than the trigger ("credntl" — no `e` between c and r, no
// trailing `t` containing the trigger) so a substring match can never
// reassemble it. The masqr session log records the unmodified findings.
func neutralizeForGaxios(b []byte) []byte {
	return gaxiosTriggerWords.ReplaceAllFunc(b, func(m []byte) []byte {
		if m[0] >= 'A' && m[0] <= 'Z' {
			return []byte("Credntl")
		}
		return []byte("credntl")
	})
}
