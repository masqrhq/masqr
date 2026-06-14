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
	"regexp"
)

// alnumIDSource consolidates every letter-bearing Presidio-derived rule
// (US passport / MBI / DEA; UK NINO / passport / driving licence; DE id
// card / health / social-security; IT fiscal code / driver licence /
// identity card; ES NIF / NIE / passport; IN PAN / passport / voter /
// GSTIN; SG NRIC-FIN / UEN; KR passport) into a single body scan, mirroring
// the digit-cluster classifier in sources_digit_ids.go.
//
// Without consolidation each of the 20+ rules would compile its own RE2
// pattern and run a separate full-body pass — that compounds into hundreds
// of ms on prompts that don't even contain matches. With consolidation:
//
//  1. One broad regex over the body finds every alphanumeric token of
//     length 6..18 (the smallest match is IN-passport at 8 chars; the
//     largest is IT-fiscal-code / IN-GSTIN at 15-16 chars; the window has
//     some slack to cover bordering punctuation cases).
//  2. For each candidate token (short — typically 6..16 bytes), every
//     registered check runs an anchored MatchString. RE2 evaluates these
//     effectively-instantly on inputs that small, so the per-token cost
//     is dominated by allocation, not regex.
//  3. The Validate hook, if any, runs the algorithmic checksum (NIF
//     letter, DEA Mod-10 split-sum, SG NRIC check letter, etc.).
type alnumIDSource struct {
	pattern *regexp.Regexp
	checks  []alnumCheck
}

type alnumCheck struct {
	ID, Category string
	Severity     Severity
	Match        *regexp.Regexp    // anchored: ^pattern$
	Validate     func(string) bool // optional checksum, run after Match
	// Keywords gates the rule: when non-empty, at least one keyword
	// (case-insensitive) must appear within ±keywordWindow bytes of
	// the candidate before it counts. Mirrors digitCheck.Keywords and
	// exists for the same reason — shape-only rules like
	// `it-identity-card` (`\d{7}[A-Z]{2}`) hit on `3600000ms`-shaped
	// timeout literals without an anchor.
	Keywords []string
}

func newAlnumIDSource() *alnumIDSource {
	return &alnumIDSource{
		// Alphanumeric run of 6..18 chars with optional internal dashes
		// (US MBI is the canonical dashed format: "1EG4-TE5-MK73"). After
		// extracting a candidate we strip dashes before running checks.
		// The inner group is REQUIRED so the pattern never matches a bare
		// single char — that previously caused a candidate explosion.
		pattern: regexp.MustCompile(`\b[A-Za-z0-9][A-Za-z0-9\-]{4,16}[A-Za-z0-9]\b`),
		checks:  presidioAlnumChecks(),
	}
}

func (*alnumIDSource) Name() string { return "alnum-ids" }

func (a *alnumIDSource) Scan(body []byte) []Match {
	locs := a.pattern.FindAllIndex(body, -1)
	if len(locs) == 0 {
		return nil
	}
	out := make([]Match, 0, 4)
	for _, l := range locs {
		tok := body[l[0]:l[1]]
		hasLetter, hasDigit := scanCharKinds(tok)
		// Every Presidio letter-bearing format contains BOTH at least one
		// letter and at least one digit. Filtering on those bytes is far
		// cheaper than running 20+ anchored regexes per candidate and
		// removes essentially all prose words from the hot path.
		if !hasLetter || !hasDigit {
			continue
		}
		normalized := stripDashes(tok)
		s := string(normalized)
		raw := string(tok)
		for _, c := range a.checks {
			if !c.Match.MatchString(s) {
				continue
			}
			if c.Validate != nil && !c.Validate(s) {
				continue
			}
			if !hasKeywordNear(body, l[0], l[1], c.Keywords) {
				continue
			}
			out = append(out, Match{
				RuleID:   c.ID,
				Category: c.Category,
				Severity: c.Severity,
				Offset:   l[0],
				End:      l[1],
				Snippet:  redactSnippet(raw),
				Identity: identityOf(c.ID, raw),
			})
		}
	}
	return out
}

// scanCharKinds reports whether b contains at least one ASCII letter and at
// least one ASCII digit, in a single pass.
func scanCharKinds(b []byte) (hasLetter, hasDigit bool) {
	for _, c := range b {
		switch {
		case c >= '0' && c <= '9':
			hasDigit = true
		case (c >= 'A' && c <= 'Z') || (c >= 'a' && c <= 'z'):
			hasLetter = true
		}
		if hasLetter && hasDigit {
			return
		}
	}
	return
}

// stripDashes drops every '-' from b, returning a new slice. Used so a
// dashed token like "1EG4-TE5-MK73" is matched against the undashed
// canonical form ("1EG4TE5MK73").
func stripDashes(b []byte) []byte {
	if !hasByte(b, '-') {
		return b
	}
	out := make([]byte, 0, len(b))
	for _, c := range b {
		if c != '-' {
			out = append(out, c)
		}
	}
	return out
}

func hasByte(b []byte, c byte) bool {
	for _, x := range b {
		if x == c {
			return true
		}
	}
	return false
}

// presidioAlnumChecks returns every letter-bearing Presidio-derived format
// in a single slice. Patterns are anchored (`^...$`) so each check is a
// strict shape filter on the candidate token — not a free regex over the
// full body.
func presidioAlnumChecks() []alnumCheck {
	mk := regexp.MustCompile
	return []alnumCheck{
		// US ─────────────────────────────────────────────────────────────
		{ID: "us-passport", Category: "pii-us", Severity: SevHigh,
			Match: mk(`^[A-Z]\d{8}$`)},
		{ID: "us-mbi", Category: "pii-us", Severity: SevHigh,
			Match: mk(`^[0-9][ACDEFGHJKMNPQRTUVWXY][0-9ACDEFGHJKMNPQRTUVWXY][0-9][ACDEFGHJKMNPQRTUVWXY][0-9ACDEFGHJKMNPQRTUVWXY][0-9][ACDEFGHJKMNPQRTUVWXY][ACDEFGHJKMNPQRTUVWXY][0-9]{2}$`)},
		{ID: "us-dea-number", Category: "pii-us", Severity: SevHigh,
			Match:    mk(`^[ABCDEFGHJKLMPRSTUX][A-Z]\d{7}$`),
			Validate: deaNumber},

		// UK ─────────────────────────────────────────────────────────────
		{ID: "uk-nino", Category: "pii-uk", Severity: SevHigh,
			Match: mk(`^[A-CEGHJ-PR-TW-Z][A-CEGHJ-NPR-TW-Z]\d{6}[A-D]$`)},
		{ID: "uk-passport", Category: "pii-uk", Severity: SevHigh,
			Match: mk(`^[A-Z]{2}\d{7}$`)},
		{ID: "uk-driving-licence", Category: "pii-uk", Severity: SevHigh,
			Match: mk(`^[A-Z9]{5}\d(?:0[1-9]|1[0-2]|5[1-9]|6[0-2])(?:0[1-9]|[12]\d|3[01])\d[A-Z9]{2}[A-Z0-9][A-Z]{2}$`)},

		// Germany ────────────────────────────────────────────────────────
		{ID: "de-id-card", Category: "pii-de", Severity: SevHigh,
			Match: mk(`^[CFGHJKLMNPRTVWXYZ][CFGHJKLMNPRTVWXYZ0-9]{7}\d$`)},
		{ID: "de-health-insurance", Category: "pii-de", Severity: SevHigh,
			Match: mk(`^[A-Z]\d{9}$`)},
		{ID: "de-social-security", Category: "pii-de", Severity: SevHigh,
			Match: mk(`^\d{8}[A-Z]\d{3}$`)},

		// Italy ──────────────────────────────────────────────────────────
		{ID: "it-fiscal-code", Category: "pii-it", Severity: SevHigh,
			Match: mk(`^(?i)(?:[A-Z][AEIOU][AEIOUX]|[AEIOU]X{2}|[B-DF-HJ-NP-TV-Z]{2}[A-Z]){2}(?:[\dLMNP-V]{2}(?:[A-EHLMPR-T](?:[04LQ][1-9MNP-V]|[15MR][\dLMNP-V]|[26NS][0-8LMNP-U])|[DHPS][37PT][0L]|[ACELMRT][37PT][01LM]|[AC-EHLMPR-T][26NS][9V])|(?:[02468LNQSU][048LQU]|[13579MPRTV][26NS])B[26NS][9V])(?:[A-MZ][1-9MNP-V][\dLMNP-V]{2}|[A-M][0L](?:[1-9MNP-V][\dLMNP-V]|[0L][1-9MNP-V]))[A-Z]$`)},
		{ID: "it-driver-license", Category: "pii-it", Severity: SevMedium,
			Match: mk(`^(?i)(?:[A-Z]{2}\d{7}[A-Z]|U1[BCDEFGHLJKMNPRSTUWYXZ0-9]{7}[A-Z])$`)},
		// it-identity-card's shape (`\d{7}[A-Z]{2}` or `[A-Z]{2}\d{5}[A-Z]{2}`)
		// matches plenty of non-PII like `3600000ms` timeout literals.
		// Real Italian ID cards live in Italian-language context, so
		// gate the rule on the typical noun forms.
		{ID: "it-identity-card", Category: "pii-it", Severity: SevHigh,
			Match:    mk(`^(?i)(?:\d{7}[A-Z]{2}|[A-Z]{2}\d{5}[A-Z]{2})$`),
			Keywords: []string{"carta", "identità", "identita", "documento"}},

		// Spain ──────────────────────────────────────────────────────────
		{ID: "es-nif", Category: "pii-es", Severity: SevHigh,
			Match:    mk(`^\d{7,8}[A-Z]$`),
			Validate: esNIF},
		{ID: "es-nie", Category: "pii-es", Severity: SevHigh,
			Match:    mk(`^[XYZ]\d{7}[A-Z]$`),
			Validate: esNIE},
		{ID: "es-passport", Category: "pii-es", Severity: SevHigh,
			Match: mk(`^[A-Z]{3}\d{6}$`)},

		// India ──────────────────────────────────────────────────────────
		{ID: "in-pan", Category: "pii-in", Severity: SevHigh,
			Match: mk(`^[A-Z]{3}[ABCFGHJLPT][A-Z]\d{4}[A-Z]$`)},
		{ID: "in-passport", Category: "pii-in", Severity: SevHigh,
			Match: mk(`^[A-Z][1-9]\d{5}[1-9]$`)},
		{ID: "in-voter-id", Category: "pii-in", Severity: SevMedium,
			Match: mk(`^[A-Z][ABCDGHJKMNPRSY][A-Z]\d{7}$`)},
		{ID: "in-gstin", Category: "pii-in", Severity: SevMedium,
			Match: mk(`^(?:0[1-9]|[1-3]\d|3[0-7])[A-Z]{3}[ABCFGHJLPT][A-Z]\d{4}[A-Z][0-9A-Z]Z[0-9A-Z]$`)},

		// Singapore ──────────────────────────────────────────────────────
		{ID: "sg-nric-fin", Category: "pii-sg", Severity: SevHigh,
			Match:    mk(`^(?i)[STFGM]\d{7}[A-Z]$`),
			Validate: sgNRICFIN},
		{ID: "sg-uen", Category: "pii-sg", Severity: SevMedium,
			Match: mk(`^(?:\d{8}[A-Z]|\d{9}[A-Z]|[TS]\d{2}[A-Z]{2}\d{4}[A-Z])$`)},

		// Korea ──────────────────────────────────────────────────────────
		{ID: "kr-passport", Category: "pii-kr", Severity: SevHigh,
			Match: mk(`^[MSROD](?:\d{8}|\d{3}[A-Z]\d{4})$`)},
	}
}
