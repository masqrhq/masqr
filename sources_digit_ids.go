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
	"regexp"
)

// hasKeywordNear returns true if any keyword (case-insensitive) appears
// within keywordWindow bytes either side of the [start:end] candidate
// span. Empty keywords means "no anchor required" → always true.
func hasKeywordNear(body []byte, start, end int, keywords []string) bool {
	if len(keywords) == 0 {
		return true
	}
	lo := start - keywordWindow
	if lo < 0 {
		lo = 0
	}
	hi := end + keywordWindow
	if hi > len(body) {
		hi = len(body)
	}
	// Lowercase once per candidate rather than per keyword.
	window := bytes.ToLower(body[lo:hi])
	for _, k := range keywords {
		if bytes.Contains(window, []byte(k)) {
			return true
		}
	}
	return false
}

// digitIDSource consolidates every Presidio-derived numeric-ID recognizer
// (US SSN, ITIN, NPI, ABA routing; AU TFN/ACN/ABN/Medicare; CA SIN; UK NHS;
// PL PESEL; KR RRN; TR TCKN; TH TNIN; IN Aadhaar; IT VAT; DE Tax ID) into a
// single body scan. The shared regex finds every digit-cluster candidate,
// the slice of checks then dispatches to per-format validators using only
// in-memory work — no further regex passes are needed.
//
// This collapses what would otherwise be ~15 keywordless full-body scans
// into one, which is the main reason adding the Presidio rule set doesn't
// blow up the per-prompt scan budget.
//
// Pattern shape: `\b\d[\d \-./]{7,17}\d\b` anchors a digit at both ends and
// allows separators in the middle. The smallest span (9 chars, all-digit)
// covers 9-digit IDs like SSN/SIN/TFN; the largest (19 chars) covers a
// 13-digit ID with separators. After normalisation we hold 9..18 digits,
// which spans every supported format. The classifier itself enforces exact
// length via Min/Max on each digitCheck.
type digitIDSource struct {
	pattern *regexp.Regexp
	checks  []digitCheck
}

type digitCheck struct {
	ID, Category string
	Severity     Severity
	Min, Max     int
	Validate     func(digits string) bool
	// Keywords, when non-empty, require at least one of the listed
	// substrings (case-insensitive) to appear within ±keywordWindow
	// bytes of the candidate. This is the cure for rules like
	// uk-nhs / au-medicare where a bare 10-digit Mod-11 cleanly hits
	// on dates, version strings, and other non-PII numerics in
	// auto-injected CLI context. Real PII almost always shows up next
	// to the label of its own format.
	Keywords []string
}

// keywordWindow is the half-width of the context check applied when a
// digitCheck has Keywords. 64 bytes catches a noun preceding ("NHS
// number 4520251001") or following the candidate without picking up
// distant unrelated mentions.
const keywordWindow = 64

func newDigitIDSource() *digitIDSource {
	return &digitIDSource{
		pattern: regexp.MustCompile(`\b\d[\d \-./]{7,17}\d\b`),
		checks:  presidioDigitChecks(),
	}
}

func (*digitIDSource) Name() string { return "digit-ids" }

func (d *digitIDSource) Scan(body []byte) []Match {
	locs := d.pattern.FindAllIndex(body, -1)
	if len(locs) == 0 {
		return nil
	}
	out := make([]Match, 0, 4)
	for _, l := range locs {
		raw := body[l[0]:l[1]]
		digits := digitsOf(string(raw))
		n := len(digits)
		if n < 9 || n > 18 {
			continue
		}
		snippet := redactSnippet(string(raw))
		for _, c := range d.checks {
			if n < c.Min || n > c.Max {
				continue
			}
			if !c.Validate(digits) {
				continue
			}
			if !hasKeywordNear(body, l[0], l[1], c.Keywords) {
				continue
			}
			rawStr := string(raw)
			out = append(out, Match{
				RuleID:   c.ID,
				Category: c.Category,
				Severity: c.Severity,
				Offset:   l[0],
				End:      l[1],
				Snippet:  snippet,
				Identity: identityOf(c.ID, rawStr),
			})
		}
	}
	return out
}

// presidioDigitChecks returns every digit-only identifier classifier.
// Severities reflect leak impact, not Presidio's confidence score — these
// numbers, validated, are real PII and warrant blocking by default.
func presidioDigitChecks() []digitCheck {
	return []digitCheck{
		{ID: "us-ssn", Category: "pii-us", Severity: SevCritical,
			Min: 9, Max: 9, Validate: usSSN,
			Keywords: []string{"ssn", "social security"}},
		{ID: "us-itin", Category: "pii-us", Severity: SevCritical,
			Min: 9, Max: 9, Validate: usITIN},
		{ID: "us-aba-routing", Category: "pii-us", Severity: SevHigh,
			Min: 9, Max: 9, Validate: usABARouting,
			Keywords: []string{"routing", "aba", "rtn"}},
		{ID: "us-npi", Category: "pii-us", Severity: SevMedium,
			Min: 10, Max: 10, Validate: usNPI},

		{ID: "ca-sin", Category: "pii-ca", Severity: SevCritical,
			Min: 9, Max: 9, Validate: caSIN,
			Keywords: []string{"sin", "social insurance"}},

		{ID: "au-tfn", Category: "pii-au", Severity: SevCritical,
			Min: 9, Max: 9, Validate: auTFN,
			Keywords: []string{"tfn", "tax file"}},
		{ID: "au-acn", Category: "pii-au", Severity: SevMedium,
			Min: 9, Max: 9, Validate: auACN,
			Keywords: []string{"acn", "company number"}},
		{ID: "au-abn", Category: "pii-au", Severity: SevMedium,
			Min: 11, Max: 11, Validate: auABN},
		{ID: "au-medicare", Category: "pii-au", Severity: SevHigh,
			Min: 10, Max: 10, Validate: auMedicare,
			Keywords: []string{"medicare"}},

		// uk-nhs and au-medicare are the worst FP offenders in this
		// list: bare 10-digit Mod-11 / Mod-10 hits on dates,
		// timestamps, and version numbers in auto-injected prompt
		// context. Keyword-gate to recover precision.
		{ID: "uk-nhs", Category: "pii-uk", Severity: SevHigh,
			Min: 10, Max: 10, Validate: ukNHS,
			Keywords: []string{"nhs", "national health", "patient"}},

		{ID: "pl-pesel", Category: "pii-pl", Severity: SevHigh,
			Min: 11, Max: 11, Validate: plPESEL},

		{ID: "kr-rrn", Category: "pii-kr", Severity: SevHigh,
			Min: 13, Max: 13, Validate: krRRN},

		{ID: "tr-tckn", Category: "pii-tr", Severity: SevHigh,
			Min: 11, Max: 11, Validate: trTCKN},

		{ID: "th-tnin", Category: "pii-th", Severity: SevHigh,
			Min: 13, Max: 13, Validate: thTNIN},

		{ID: "it-vat-code", Category: "pii-it", Severity: SevMedium,
			Min: 11, Max: 11, Validate: itVAT},

		{ID: "de-tax-id", Category: "pii-de", Severity: SevHigh,
			Min: 11, Max: 11, Validate: deTaxID},

		{ID: "in-aadhaar", Category: "pii-in", Severity: SevCritical,
			Min: 12, Max: 12, Validate: inAadhaar},

		{ID: "se-personnummer", Category: "pii-se", Severity: SevHigh,
			Min: 10, Max: 12, Validate: sePersonnummer},
		{ID: "se-orgnummer", Category: "pii-se", Severity: SevMedium,
			Min: 10, Max: 10, Validate: seOrgnummer,
			Keywords: []string{"orgnr", "org nummer", "orgnummer", "organisationsnummer"}},
	}
}
