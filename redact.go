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
	"bytes"
	"fmt"
	"io"
	"sort"
	"sync"
)

// findingMemo is masqr's session-local state for the redact mode. It
// assigns a stable placeholder (e.g. `__EMAIL_1__`) the first time it
// sees a finding identity, reuses that placeholder on subsequent
// requests, and exposes the reverse map so the response restorer can
// replace placeholders with the user's original values before the bytes
// reach the CLI.
//
// Lifetime is process-local. Restarting masqr resets every mapping,
// which matters because the LLM upstream has no memory of prior masqr
// sessions either.
type findingMemo struct {
	mu sync.Mutex
	// idToPlaceholder maps an identityOf(rule, raw) result to the
	// placeholder we picked for it.
	idToPlaceholder map[string]string
	// placeholderToOriginal is the inverse map used by restoreBytes.
	placeholderToOriginal map[string]string
	// nextN[label] is the next counter for a given placeholder LABEL.
	nextN map[string]int
}

func newFindingMemo() *findingMemo {
	return &findingMemo{
		idToPlaceholder:       map[string]string{},
		placeholderToOriginal: map[string]string{},
		nextN:                 map[string]int{},
	}
}

// placeholderFor returns the placeholder masqr will swap in for this
// match. raw is the verbatim matched text from the request body; the
// memo holds onto it so restoreBytes can put it back in responses.
// First call with a given identity allocates a new __LABEL_N__ token;
// subsequent calls return the same one so the same value redacts to
// the same placeholder for the whole session.
//
// Sources that don't pre-populate Match.Identity (gitleaks, presidio,
// keywords, OCR) get one synthesized here from (rule_id, raw) — the
// raw bytes are always available at this point in the pipeline, so
// there's no reason to refuse them a stable placeholder.
func (m *findingMemo) placeholderFor(match Match, raw string) string {
	if raw == "" {
		return ""
	}
	identity := match.Identity
	if identity == "" {
		identity = identityOf(match.RuleID, raw)
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	if p, ok := m.idToPlaceholder[identity]; ok {
		return p
	}
	label := placeholderLabel(match.RuleID)
	m.nextN[label]++
	p := fmt.Sprintf("__%s_%d__", label, m.nextN[label])
	m.idToPlaceholder[identity] = p
	m.placeholderToOriginal[p] = raw
	return p
}

// snapshot returns a copy of the (placeholder, original) pairs known to
// the memo right now, ordered longest-placeholder first so restoreBytes
// can't pick a short prefix when a longer placeholder would also match.
func (m *findingMemo) snapshot() []replacementPair {
	m.mu.Lock()
	defer m.mu.Unlock()
	if len(m.placeholderToOriginal) == 0 {
		return nil
	}
	out := make([]replacementPair, 0, len(m.placeholderToOriginal))
	for k, v := range m.placeholderToOriginal {
		out = append(out, replacementPair{find: k, replace: v})
	}
	sort.Slice(out, func(i, j int) bool { return len(out[i].find) > len(out[j].find) })
	return out
}

// labelOverrides maps common rule IDs to short, human-friendly labels
// so the placeholders read naturally to the LLM and the user. Missing
// entries fall back to upper(rule_id) with hyphens turned into
// underscores — still legible, just longer.
var labelOverrides = map[string]string{
	"email-address":           "EMAIL",
	"credit-card":             "CARD",
	"private-ipv4":            "IP",
	"private-ipv6":            "IP",
	"generic-base64-blob":     "SECRET",
	"aws-access-key-id":       "AWS_KEY",
	"aws-secret-access-key":   "AWS_KEY",
	"anthropic-api-key":       "ANTHROPIC_KEY",
	"openai-api-key":          "OPENAI_KEY",
	"gcp-api-key":             "GCP_KEY",
	"gcp-service-account-key": "GCP_KEY",
	"github-pat":              "GH_TOKEN",
	"github-fine-grained-pat": "GH_TOKEN",
	"gitlab-pat":              "GL_TOKEN",
	"slack-bot-or-user-token": "SLACK_TOKEN",
	"slack-webhook":           "SLACK_WEBHOOK",
	"jwt":                     "JWT",
	"private-key-pem":         "PRIVATE_KEY",
	"stripe-live-key":         "STRIPE_KEY",
}

// placeholderLabel returns the short LABEL token used in `__LABEL_N__`.
// Well-known rule IDs get a curated, readable label so the model sees
// something it can reason about (`__EMAIL_1__`, `__CARD_2__`). Anything
// else — gitleaks rules, presidio digit-IDs, OCR, custom keywords —
// collapses to a generic `VAR`, which keeps the placeholder format
// uniform and avoids leaking rule-name hints (`__GITLEAKS_AWS_SECRET_…__`)
// to the upstream model.
func placeholderLabel(ruleID string) string {
	if v, ok := labelOverrides[ruleID]; ok {
		return v
	}
	return "VAR"
}

// redactSpans rewrites body, substituting each match's [Offset:End] span
// with the placeholder allocated for it by memo. The shift parameter
// translates scanner offsets (which include the synthetic `url: …`
// preamble prepended by scanRequest) back into raw-body offsets.
//
// Matches that fall outside body bounds, overlap a preceding match, or
// have no Identity are skipped. The caller is expected to have already
// guaranteed every triggering match meets those conditions (see
// classifyMatches in server.go) — anything left unredactable here is a
// silent no-op for that one finding rather than a torn rewrite of the
// rest.
func redactSpans(body []byte, matches []Match, shift int, memo *findingMemo) []byte {
	type span struct {
		start, end  int
		placeholder string
	}
	spans := make([]span, 0, len(matches))
	for _, m := range matches {
		s, e := m.Offset-shift, m.End-shift
		if s < 0 || e <= s || e > len(body) {
			continue
		}
		p := memo.placeholderFor(m, string(body[s:e]))
		if p == "" {
			continue
		}
		spans = append(spans, span{s, e, p})
	}
	if len(spans) == 0 {
		return append([]byte(nil), body...)
	}
	sort.Slice(spans, func(i, j int) bool { return spans[i].start < spans[j].start })

	out := make([]byte, 0, len(body))
	cursor := 0
	for _, sp := range spans {
		if sp.start < cursor {
			continue
		}
		out = append(out, body[cursor:sp.start]...)
		out = append(out, sp.placeholder...)
		cursor = sp.end
	}
	out = append(out, body[cursor:]...)
	return out
}

// replacementPair is the unit of work for restoreBytes / streamRestorer.
type replacementPair struct {
	find, replace string
}

// restoreBytes runs every (placeholder, original) substitution in the
// pairs slice over body, in the order given. The order matters when one
// placeholder is a prefix of another (__SECRET_1__ vs __SECRET_10__) —
// memo.snapshot returns them longest-first so longer keys win.
func restoreBytes(body []byte, pairs []replacementPair) []byte {
	if len(pairs) == 0 {
		return body
	}
	out := body
	for _, p := range pairs {
		if !bytes.Contains(out, []byte(p.find)) {
			continue
		}
		out = bytes.ReplaceAll(out, []byte(p.find), []byte(p.replace))
	}
	return out
}

// streamRestorer wraps an io.Reader (typically a streamed SSE response
// body) and substitutes placeholders inline. Because a placeholder can
// straddle two reads, the wrapper holds back the trailing window of
// bytes that could still be the start of a placeholder. The window is
// sized at the length of the longest placeholder minus one so we never
// emit a byte that might still become part of a match.
type streamRestorer struct {
	src     io.Reader
	pairs   []replacementPair
	tail    []byte
	pending []byte // bytes ready to be drained to the caller
	maxLen  int
	eof     bool
	err     error
}

func newStreamRestorer(src io.Reader, pairs []replacementPair) *streamRestorer {
	maxLen := 0
	for _, p := range pairs {
		if len(p.find) > maxLen {
			maxLen = len(p.find)
		}
	}
	return &streamRestorer{src: src, pairs: pairs, maxLen: maxLen}
}

// Read fulfils io.Reader. It pulls from the underlying source, runs
// replacements over the buffered window, emits everything that can no
// longer become a partial match, and keeps the rest for the next call.
func (r *streamRestorer) Read(p []byte) (int, error) {
	for len(r.pending) == 0 && !r.eof {
		buf := make([]byte, 4096)
		n, err := r.src.Read(buf)
		if n > 0 {
			r.tail = append(r.tail, buf[:n]...)
		}
		if err == io.EOF {
			r.eof = true
		} else if err != nil {
			r.err = err
			r.eof = true
		}
		r.flush()
	}
	if len(r.pending) == 0 {
		if r.err != nil {
			return 0, r.err
		}
		return 0, io.EOF
	}
	n := copy(p, r.pending)
	r.pending = r.pending[n:]
	return n, nil
}

// flush moves bytes from r.tail (the rolling window) into r.pending
// (ready to drain) up to the cutoff that's safe from further match
// extension. On EOF it flushes everything because there can't be more
// input to grow a partial match.
func (r *streamRestorer) flush() {
	if len(r.tail) == 0 {
		return
	}
	cutoff := len(r.tail) - r.maxLen + 1
	if r.eof || cutoff > len(r.tail) {
		cutoff = len(r.tail)
	}
	if cutoff <= 0 {
		return
	}
	chunk := r.tail[:cutoff]
	r.tail = r.tail[cutoff:]
	r.pending = append(r.pending, restoreBytes(chunk, r.pairs)...)
}
