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

import "regexp"

// presidioRules returns Presidio-derived rules that still benefit from the
// keyword-prefiltered rule engine. The bulk of Presidio's letter-bearing
// recognizers live in sources_alnum_ids.go (one consolidated body scan
// instead of one full-body pass per format) and the digit-only ones live
// in sources_digit_ids.go.
//
// What stays here:
//   - Rules with a strong literal anchor (BTC bech32, IBAN-generic via
//     country code, FI HETU's mandatory separator) where the prefilter
//     short-circuits on bodies that lack the anchor.
//   - Rules whose patterns are short and selective enough that the
//     incremental cost of a keywordless full-body scan is negligible.
//
// Patterns are clean-room transcriptions of the regexes published in
// microsoft/presidio's predefined_recognizers tree; checksums mirror the
// published validate_result hooks.
func presidioRules() []Rule {
	mk := regexp.MustCompile
	return []Rule{

		// ─── Generic, multi-jurisdiction ───────────────────────────────

		{
			// Bitcoin: bech32 P2WPKH (`bc1`) and testnet (`tb1`). Keyword
			// anchor matches every BTC bech32 address prefix on-chain;
			// Lightning invoices (`lnbc`) fall outside on purpose.
			ID: "bitcoin-address", Category: "pii", Severity: SevMedium,
			Keywords: []string{"bc1", "tb1"},
			Pattern:  mk(`\b(?:bc1|tb1)[a-zA-HJ-NP-Z0-9]{25,87}\b`),
		},
		{
			// Legacy Bitcoin P2PKH/P2SH addresses (base58, no clean keyword).
			// The length floor + base58 alphabet keep FPs low.
			ID: "bitcoin-legacy-address", Category: "pii", Severity: SevLow,
			Pattern: mk(`\b[13][a-km-zA-HJ-NP-Z1-9]{25,34}\b`),
		},
		{
			// IBAN — generic (any ISO 3166-1 alpha-2 country code, 2 check
			// digits, then 11–30 alphanumerics). Validated via Mod-97.
			// Severity is one tier below ch-iban so the country-specific
			// match wins during dedupe; the generic rule still fires for
			// non-CH IBANs that lack a dedicated rule.
			ID: "iban-generic", Category: "pii", Severity: SevMedium,
			Pattern:  mk(`\b[A-Z]{2}\d{2}(?:\s?[A-Z0-9]{4}){2,7}(?:\s?[A-Z0-9]{1,4})?\b`),
			Validate: ibanMod97,
		},

		// ─── Germany ───────────────────────────────────────────────────

		{
			// DE VAT ID — `DE` prefix followed by 9 digits. The keyword
			// anchor is selective enough to keep the rule effectively free.
			ID: "de-vat-id", Category: "pii-de", Severity: SevMedium,
			Keywords: []string{"DE"},
			Pattern:  mk(`\bDE\d{9}\b`),
		},

		// ─── Finland ───────────────────────────────────────────────────

		{
			// FI Henkilötunnus (HETU). DDMMYY + century separator + NNN +
			// check character (from a 31-entry lookup of date+individual).
			// Mandatory non-alnum separator at position 6 keeps this rule
			// out of the alnum-cluster classifier — kept here as its own
			// keywordless pass; the strict shape limits FPs.
			ID: "fi-personal-id", Category: "pii-fi", Severity: SevHigh,
			Pattern:  mk(`\b\d{6}[+\-ABCDEFYXWVU]\d{3}[0-9A-Z]\b`),
			Validate: fiPIC,
		},
	}
}
