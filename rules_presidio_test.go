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
	"strings"
	"testing"
)

// scannerWithoutExternal builds a scanner over the built-in rules only,
// skipping gitleaks / digit-IDs / keywords / OCR. Tests that want to assert
// "the built-in rule X fires" use this so external sources can't shadow the
// rule under test.
func scannerWithoutExternal() *Scanner {
	return NewScanner(defaultRules())
}

// scannerWithDigitIDs adds the consolidated digit-ID source to the rule
// engine so we exercise the same code path as production for purely-numeric
// identifiers like SSN/Aadhaar/NHS/PESEL/etc.
func scannerWithDigitIDs() *Scanner {
	s := NewScanner(defaultRules())
	s.sources = append(s.sources, newDigitIDSource())
	return s
}

// scannerWithAlnumIDs adds the alphanumeric-cluster classifier so we
// exercise letter-bearing IDs (passports, NRIC, fiscal codes, etc.).
func scannerWithAlnumIDs() *Scanner {
	s := NewScanner(defaultRules())
	s.sources = append(s.sources, newAlnumIDSource())
	return s
}

func mustHit(t *testing.T, s *Scanner, body, wantID string) {
	t.Helper()
	got := false
	ms := s.Scan([]byte(body))
	for _, m := range ms {
		if m.RuleID == wantID {
			got = true
			break
		}
	}
	if !got {
		t.Errorf("expected %s to fire on %q; got %v", wantID, body, ruleIDs(ms))
	}
}

func mustMiss(t *testing.T, s *Scanner, body, wantID string) {
	t.Helper()
	ms := s.Scan([]byte(body))
	for _, m := range ms {
		if m.RuleID == wantID {
			t.Errorf("did not expect %s to fire on %q; got %+v", wantID, body, m)
		}
	}
}

// ─── Letter-bearing rules (rules_presidio.go) ─────────────────────────────

func TestPresidioLetterRules(t *testing.T) {
	s := scannerWithAlnumIDs()
	cases := []struct {
		name, body, want string
	}{
		// Bitcoin
		{"btc-bech32", "wallet bc1qar0srrr7xfkvy5l643lydnw9re59gtzzwf5mdq please", "bitcoin-address"},
		{"btc-legacy", "send to 1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa quickly", "bitcoin-legacy-address"},
		// IBAN generic (non-CH)
		{"iban-de", "iban DE89370400440532013000 ok?", "iban-generic"},
		{"iban-gb", "send to GB82WEST12345698765432 today", "iban-generic"},
		// US
		{"us-passport", "passport book A12345678 issued", "us-passport"},
		{"us-mbi", "patient 1EG4-TE5-MK73 medicare", "us-mbi"},
		{"us-dea", "DEA AB1234563 on file", "us-dea-number"},
		// UK
		{"uk-nino", "NINO AB123456C registered", "uk-nino"},
		{"uk-passport", "passport AB1234567 in scope", "uk-passport"},
		// Germany
		{"de-vat", "DE123456789 is our VAT id", "de-vat-id"},
		{"de-vat-agy-wrap", `<USER_REQUEST>\nDE123456789 is our VAT id\n</USER_REQUEST>`, "de-vat-id"},
		// India
		{"in-pan", "PAN ABCPK1234E for KYC", "in-pan"},
		{"in-passport", "passport L1234567 issued in Delhi", "in-passport"},
		// Spain
		{"es-nif", "DNI 12345678Z", "es-nif"},
		{"es-nie", "NIE X1234567L for residency", "es-nie"},
		{"es-passport", "passport AAA123456 in scope", "es-passport"},
		// Singapore
		{"sg-nric", "NRIC S1234567D", "sg-nric-fin"},
		{"sg-uen", "Entity UEN 200512345A", "sg-uen"},
		// Finland
		{"fi-pic", "hetu 131052-308T", "fi-personal-id"},

		// Germany (shape-only national IDs)
		{"de-id-card", "Personalausweis C12345678 ausgestellt", "de-id-card"},
		{"de-health-insurance", "Versichertennummer A123456789 ok", "de-health-insurance"},
		{"de-social-security", "SV-Nummer 12345678A123 hinterlegt", "de-social-security"},
		// India
		{"in-voter-id", "EPIC ABC1234567 issued", "in-voter-id"},
		{"in-gstin", "GSTIN 27ABCPK1234E1Z5 registered", "in-gstin"},
		// Italy
		{"it-fiscal-code", "codice fiscale RSSMRA85T10A562S valido", "it-fiscal-code"},
		{"it-driver-license", "patente AB1234567C rilasciata", "it-driver-license"},
		// Korea
		{"kr-passport", "passport M12345678 issued in Seoul", "kr-passport"},
		// UK
		{"uk-driving-licence", "DVLA licence MORGA753112AB5CD on file", "uk-driving-licence"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			mustHit(t, s, c.body, c.want)
		})
	}
	t.Run("de-vat-fp-code", func(t *testing.T) {
		mustMiss(t, s, "SKU CODE123456789 is not a German VAT number", "de-vat-id")
	})
}

// ESpassport "AAA123456" is also 3 letters + 6 digits and conflicts with
// IT/UK passport patterns. We accept this overlap — the rule's category
// flags the country it most likely belongs to; severity is identical so
// dedupe collapses duplicates.

// ─── Digit-cluster classifier (sources_digit_ids.go) ──────────────────────

func TestDigitIDSource(t *testing.T) {
	s := scannerWithDigitIDs()
	cases := []struct {
		name, body, want string
	}{
		{"us-ssn-dashed", "SSN 219-12-3456 for tax docs", "us-ssn"},
		{"us-ssn-bare", "ssn 219123456 attached", "us-ssn"},
		{"us-itin", "ITIN 912-50-1234 ok", "us-itin"},
		{"us-aba", "routing 011000015 federal", "us-aba-routing"},
		{"us-npi", "provider NPI 1234567893 here", "us-npi"},
		{"ca-sin", "SIN 123-456-782 for CRA", "ca-sin"},
		{"au-tfn", "TFN 123 456 782 with ATO", "au-tfn"},
		{"au-acn", "ACN 004 085 616 registered", "au-acn"},
		{"au-abn", "ABN 51 824 753 556 verified", "au-abn"},
		{"au-medicare", "medicare 2239 99990 1 valid", "au-medicare"},
		{"uk-nhs", "NHS 943 476 5919 patient", "uk-nhs"},
		{"pl-pesel", "PESEL 94051012343 polish id", "pl-pesel"},
		{"kr-rrn", "RRN 950101-1234564 korean", "kr-rrn"},
		{"tr-tckn", "TCKN 12345678950 turkey", "tr-tckn"},
		{"th-tnin", "TNIN 1234567890121 thai", "th-tnin"},
		{"it-vat", "P.IVA 12345678903 italy", "it-vat-code"},
		{"de-tax-id", "Steuer-ID 12345678903 ok", "de-tax-id"},
		{"in-aadhaar", "Aadhaar 2345-6789-0124 in scope", "in-aadhaar"},
		{"se-personnummer", "PIN 940510-1230 swedish", "se-personnummer"},
		{"se-orgnummer", "OrgNr 556677-8899 company", "se-orgnummer"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			mustHit(t, s, c.body, c.want)
		})
	}
}

// TestDigitIDInvalidatesBadChecksums ensures every digit-cluster rule
// rejects an off-by-one. Without this guard, the classifier degenerates
// into "any digit cluster of the right length" and false-positives explode.
func TestDigitIDInvalidatesBadChecksums(t *testing.T) {
	s := scannerWithDigitIDs()
	cases := []struct {
		name, body, mustNotFire string
	}{
		// SSN has no published checksum; we can only invalidate by the
		// structural rules (area 000 / 666 / 9xx, group 00, serial 0000,
		// famous-fake list).
		{"us-ssn-bad-area", "ssn 000-12-3456 area zero", "us-ssn"},
		{"us-ssn-fake", "ssn 123-45-6789 in payload", "us-ssn"},
		{"ca-sin-bad", "SIN 123-456-783", "ca-sin"},
		{"au-abn-bad", "ABN 51 824 753 557", "au-abn"},
		{"uk-nhs-bad", "NHS 943 476 5920", "uk-nhs"},
		{"pl-pesel-bad", "PESEL 94051012344", "pl-pesel"},
		{"in-aadhaar-bad", "Aadhaar 2345-6789-0125", "in-aadhaar"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			mustMiss(t, s, c.body, c.mustNotFire)
		})
	}
}

// TestDigitIDClusterCoexistence ensures the digit-cluster source can co-fire
// with the credit-card rule on the same body without dropping either match.
// (Card and SSN share no digit count, so dedupe should not collapse them.)
func TestDigitIDClusterCoexistence(t *testing.T) {
	s := scannerWithDigitIDs()
	body := []byte("card 4532015112830366 with SSN 219-12-3456 in payload")
	got := map[string]bool{}
	for _, m := range s.Scan(body) {
		got[m.RuleID] = true
	}
	for _, want := range []string{"credit-card", "us-ssn"} {
		if !got[want] {
			t.Errorf("expected %s to coexist with peer matches; got %v", want, got)
		}
	}
}

// TestPrefilterNoLeakOnEmptyBody guards the no-allocation fast path: an
// empty body must produce zero matches without panicking through any of the
// new rules / sources.
func TestPrefilterNoLeakOnEmptyBody(t *testing.T) {
	s := scannerWithDigitIDs()
	if ms := s.Scan(nil); len(ms) != 0 {
		t.Errorf("scan of nil body yielded %d matches, want 0: %v", len(ms), ms)
	}
	if ms := s.Scan([]byte("")); len(ms) != 0 {
		t.Errorf("scan of empty body yielded %d matches, want 0: %v", len(ms), ms)
	}
}

// TestKeywordPrefilterStillShortCircuits guards the perf invariant that
// bodies lacking any literal anchor never reach per-rule regex evaluation
// for keyworded rules.
func TestKeywordPrefilterStillShortCircuits(t *testing.T) {
	s := scannerWithoutExternal()
	// "lorem ipsum" has no token from any defaultRules keyword set.
	body := strings.Repeat("lorem ipsum dolor sit amet consectetur ", 100)
	if ms := s.Scan([]byte(body)); len(ms) != 0 {
		t.Errorf("expected 0 matches on prose body, got %d: %v", len(ms), ms)
	}
}
