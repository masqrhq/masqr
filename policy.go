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

// googleBlockedDetailItem is one entry in the google.rpc.Status details array.
// masqr emits its own `masqr.BlockedRequest` (carrying the structured findings)
// for every Google-family provider, and additionally — for agy — a
// `google.rpc.ErrorInfo` whose metadata.uiMessage agy renders as a custom
// message (see custom-error-message.md). The Reason/Metadata fields are
// omitempty so they only appear on the ErrorInfo item.
type googleBlockedDetailItem struct {
	Type     string             `json:"@type"`
	Reason   string             `json:"reason,omitempty"`
	Metadata *errorInfoMetadata `json:"metadata,omitempty"`
	Findings []blockFinding     `json:"findings,omitempty"`
}

// errorInfoMetadata is the metadata map of a google.rpc.ErrorInfo detail. agy's
// showErrorMessageInUI (recovered from the v1.0.3 binary) reads uiMessage from
// here and displays it verbatim instead of the generic "Agent execution
// terminated due to error" banner.
type errorInfoMetadata struct {
	UIMessage string `json:"uiMessage,omitempty"`
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
		"masqr blocked this prompt: detected %s. To proceed, edit the prompt, or rerun masqr with --on-finding redact (mask the value) or --block-on=<higher severity> (allow it).",
		strings.Join(ids, ", "),
	)

	status := http.StatusUnavailableForLegalReasons
	if provider.Name == "antigravity" {
		// agy's Code Assist client renders a standard Google API error with its
		// message; a 400 INVALID_ARGUMENT surfaces cleanly, whereas the 451 the
		// other providers use shows up as a generic "terminated due to error".
		status = http.StatusBadRequest
	}

	var body any
	switch provider.Name {
	case "google-gemini", "google-vertex", "antigravity":
		// agy (antigravity) hits the same Code Assist backend as the Gemini
		// OAuth path, so it expects the Google error envelope — not the
		// Anthropic-shaped default, which it can't parse (hence the opaque
		// "Agent execution terminated due to error").
		gstatus := "FAILED_PRECONDITION"
		details := []googleBlockedDetailItem{{
			Type:     "type.googleapis.com/masqr.BlockedRequest",
			Findings: findings,
		}}
		if provider.Name == "antigravity" {
			gstatus = "INVALID_ARGUMENT"
			// agy doesn't surface error.message in its rich error UI; it renders
			// details[].metadata.uiMessage from a google.rpc.ErrorInfo
			// (showErrorMessageInUI). Prepend that item so the user sees masqr's
			// block reason as a custom message instead of the generic banner.
			// reason="CUSTOM" sidesteps agy's canned reason→message overrides
			// (e.g. quota, verification). See custom-error-message.md.
			details = append([]googleBlockedDetailItem{{
				Type:     "type.googleapis.com/google.rpc.ErrorInfo",
				Reason:   "CUSTOM",
				Metadata: &errorInfoMetadata{UIMessage: msg},
			}}, details...)
		}
		body = googleBlockedError{
			Error: googleBlockedDetail{
				Code:    status,
				Message: msg,
				Status:  gstatus,
				Details: details,
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

// isAgyStreamRequest reports whether this is agy's streaming Code Assist call
// (…/v1internal:streamGenerateContent). On that path agy silently swallows a
// JSON error envelope, so the block has to be delivered as a synthetic SSE
// "model" turn instead (see writeAgyStreamBlock).
func isAgyStreamRequest(p Provider, path string) bool {
	return p.Name == "antigravity" && strings.Contains(path, "streamGenerateContent")
}

// writeAgyStreamBlock answers a blocked agy streaming request with a 200
// text/event-stream carrying one synthetic GenerateContentResponse (Code Assist
// nests it under "response"). agy renders the text as a normal assistant reply —
// so the user sees what tripped and how to keep working, rather than the
// generic "Agent execution terminated due to error" the swallowed JSON 4xx
// produces. The real block is still recorded in the session log.
func writeAgyStreamBlock(w http.ResponseWriter, matches []Match, offerMask bool) {
	writeAgyStreamText(w, blockAdvice(matches, offerMask))
}

// maskAckText confirms a `mask` consent reply.
func maskAckText(n int) string {
	switch {
	case n <= 0:
		return "✓ Masking is on for this chat. Resend your message and I’ll continue normally."
	case n == 1:
		return "✓ Masking enabled — I’ll mask that value for the rest of this chat; it won’t reach the model.\n\nResend your message and I’ll pick up normally."
	default:
		return fmt.Sprintf("✓ Masking enabled — I’ll mask those %d values for the rest of this chat; they won’t reach the model.\n\nResend your message and I’ll pick up normally.", n)
	}
}

// writeAgyStreamText emits one synthetic Code Assist SSE event (a model turn
// carrying text) at HTTP 200 — the response shape agy renders on its streaming
// endpoint. Used for both the block explanation and the mask ack.
func writeAgyStreamText(w http.ResponseWriter, text string) {
	type part struct {
		Text string `json:"text"`
	}
	type content struct {
		Role  string `json:"role"`
		Parts []part `json:"parts"`
	}
	type candidate struct {
		Content      content `json:"content"`
		FinishReason string  `json:"finishReason"`
		Index        int     `json:"index"`
	}
	env := struct {
		Response struct {
			Candidates []candidate `json:"candidates"`
		} `json:"response"`
	}{}
	env.Response.Candidates = []candidate{{
		Content:      content{Role: "model", Parts: []part{{Text: text}}},
		FinishReason: "STOP",
	}}

	buf, err := json.Marshal(env)
	if err != nil {
		buf = []byte(`{"response":{"candidates":[{"content":{"role":"model","parts":[{"text":"masqr blocked this prompt; it never left your machine."}]},"finishReason":"STOP"}]}}`)
	}

	w.Header().Set("Content-Type", "text/event-stream")
	w.Header().Set("Cache-Control", "no-cache")
	w.Header().Set("X-Masqr-Blocked", "1")
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write([]byte("data: "))
	_, _ = w.Write(buf)
	_, _ = w.Write([]byte("\n\n"))
	if f, ok := w.(http.Flusher); ok {
		f.Flush()
	}
}

// blockAdvice renders the user-facing explanation for a blocked prompt: what
// tripped (rule · category · severity, with the already-redacted snippet) and
// concrete next steps for continuing the work — tailored to whether secrets,
// PII, or both were involved.
func blockAdvice(matches []Match, offerMask bool) string {
	var b strings.Builder
	// agy renders no markdown and no ANSI colour, but it DOES colour emoji —
	// so the red marker is an inherently-red glyph (no red-shield emoji exists).
	// ⛔ is red and reads as "blocked".
	b.WriteString("⛔ masqr blocked this prompt — nothing was sent; it never left your machine.\n\n")
	b.WriteString("What I caught:\n")
	seen := map[string]bool{}
	var hasSecret, hasPII bool
	var exampleSnippet, exampleLabel string // first maskable finding, for the placeholder demo
	for _, m := range matches {
		switch {
		case strings.HasPrefix(m.Category, "pii"):
			hasPII = true
		case m.Category != "attachment" && m.Category != "internal-ip":
			hasSecret = true
		}
		if seen[m.RuleID] {
			continue
		}
		seen[m.RuleID] = true
		snip := ""
		if m.Snippet != "" {
			snip = " — “" + m.Snippet + "”"
		}
		fmt.Fprintf(&b, "  • %s (%s · %s)%s\n", m.RuleID, m.Category, m.Severity, snip)
		if exampleLabel == "" && m.Identity != "" && m.Snippet != "" {
			exampleSnippet, exampleLabel = m.Snippet, placeholderLabel(m.RuleID)
		}
	}
	b.WriteString("\nHeads-up: your CLI resends the whole conversation each turn, so this value is now in the chat history — masqr will keep blocking until it's masked or gone.\n")
	b.WriteString("\nHow to continue:\n")
	n := 1
	if offerMask {
		fmt.Fprintf(&b, "  %d. Reply `mask` to mask the flagged value(s) for the rest of this chat, then resend.", n)
		if exampleLabel != "" {
			fmt.Fprintf(&b, " Masking swaps the value for a placeholder — e.g. “%s” → `__%s_1__` — so the model only ever sees the placeholder, while you still see your real value in my replies.", exampleSnippet, exampleLabel)
		} else {
			b.WriteString(" The value is swapped for a placeholder the model can't read back.")
		}
		b.WriteByte('\n')
		n++
		fmt.Fprintf(&b, "  %d. Want that on every prompt automatically? Relaunch with `--on-finding=redact` (e.g. `masqr --on-finding=redact agy`) — same masking, no need to reply each time.\n", n)
		n++
	}
	fmt.Fprintf(&b, "  %d. Or clear the conversation so the flagged turn drops out of history — type `/clear` (or `?` for your CLI's shortcuts) — then leave the value out.\n", n)
	n++
	fmt.Fprintf(&b, "  %d. False positive? Raise the threshold: `masqr --block-on=high agy` blocks only high/critical findings.\n", n)
	switch {
	case hasSecret && hasPII:
		b.WriteString("\nA credential and personal data were involved: rotate the credential if it was real, keep secrets in environment variables or a secrets manager, and use a synthetic value for the personal data.")
	case hasSecret:
		b.WriteString("\nA credential was involved: if it was a real one, rotate it — and pass secrets via environment variables or a secrets manager rather than pasting them into prompts.")
	case hasPII:
		b.WriteString("\nThis is personal data: prefer a synthetic or anonymized value (or describe it abstractly) — the model rarely needs the real thing.")
	}
	return b.String()
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
