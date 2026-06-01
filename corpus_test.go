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
	"os"
	"path/filepath"
	"sort"
	"strings"
	"testing"
)

const corpusPath = "testagent/cases.jsonl"

type corpusCase struct {
	Name    string   `json:"name"`
	Prompt  string   `json:"prompt"`
	Expect  string   `json:"expect"`
	Rules   []string `json:"rules,omitempty"`
	Secrets []string `json:"secrets"`
}

// corpusSeeds drive the test corpus: realistic sentences masqr should catch (or,
// for the FORWARDED ones, must NOT). The generator scans each with the real
// scanner to discover which rule(s) fire and to extract the exact secret span —
// so cases.jsonl is always consistent with the live rules. `want` is what we
// expect: "block" (a triggering finding) or "clean" (none).
var corpusSeeds = []struct {
	name, prompt, want string
}{
	// ── secrets ────────────────────────────────────────────────────────────
	{"aws-key", "deploy this with AWS key AKIAIOSFODNN7EXAMPLE please", "block"},
	{"github-pat", "use token ghp_1234567890ABCDEFGHIJ1234567890ABCDEF for push", "block"},
	{"anthropic-key", "anthropic key sk-ant-veryverylongsecrettokenstring0123456789abcdef here", "block"},
	{"gcp-api-key", "gcp key AIzaSyAabcdefghijklmnopqrstuvwxyz123456 in app", "block"},
	{"jwt", "bearer eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c", "block"},
	{"private-key-pem", "key: -----BEGIN RSA PRIVATE KEY-----\nMIIBOgIBAAJBAKj34GkxFhD\n-----END RSA PRIVATE KEY-----", "block"},
	{"gitlab-pat", "leak: glpat-abcdefghij1234567890", "block"},
	{"gitlab-oauth", "secret: gloas-abcdefghij1234567890abcdefghij1234567890", "block"},
	{"gitlab-pipeline", "trigger: glptt-abcdefghij1234567890abcdefghij1234567890", "block"},
	{"gitlab-runner", "runner: glrt-abcdefghij1234567890", "block"},
	{"gitlab-deploy", "deploy: gldt-abcdefghij1234567890", "block"},
	{"gitlab-feed", "feed: glft-abcdefghij1234567890", "block"},
	{"gitlab-agent", "agent: glagent-abcdefghij1234567890abcdefghij1234567890abcdefghij", "block"},
	{"gitlab-scim", "scim: glsoat-abcdefghij1234567890abcdefghij1234567890", "block"},
	{"gitlab-ci-job", "job: glcbt-abcdefghij1234567890", "block"},
	{"slack-webhook", "post to https://hooks.slack.com/services/T01ABC23DEF/B04GHI56JKL/abcdefghijklmnopqrstuvwx", "block"},

	// ── PII: cards, IBAN, email ────────────────────────────────────────────
	{"credit-card", "charge the card 4111 1111 1111 1111 now", "block"},
	{"email", "please email me back at info@example.com", "block"},
	{"ch-iban", "send to iban CH9300762011623852957 today", "block"},
	{"ch-ahv", "AHV 756.1234.5678.97 on file", "block"},

	// ── PII: national IDs (digit-cluster classifier) ──────────────────────
	{"us-ssn", "SSN 219-12-3456 for tax docs", "block"},
	{"us-itin", "ITIN 912-50-1234 ok", "block"},
	{"us-aba-routing", "routing 011000015 federal", "block"},
	{"us-npi", "provider NPI 1234567893 here", "block"},
	{"ca-sin", "SIN 123-456-782 for CRA", "block"},
	{"au-tfn", "TFN 123 456 782 with ATO", "block"},
	{"au-acn", "ACN 004 085 616 registered", "block"},
	{"au-abn", "ABN 51 824 753 556 verified", "block"},
	{"au-medicare", "medicare 2239 99990 1 valid", "block"},
	{"uk-nhs", "NHS 943 476 5919 patient", "block"},
	{"pl-pesel", "PESEL 94051012343 polish id", "block"},
	{"kr-rrn", "RRN 950101-1234564 korean", "block"},
	{"tr-tckn", "TCKN 12345678950 turkey", "block"},
	{"th-tnin", "TNIN 1234567890121 thai", "block"},
	{"it-vat-code", "P.IVA 12345678903 italy", "block"},
	{"de-tax-id", "Steuer-ID 12345678903 ok", "block"},
	{"in-aadhaar", "Aadhaar 2345-6789-0124 in scope", "block"},
	{"se-personnummer", "PIN 940510-1230 swedish", "block"},
	{"se-orgnummer", "OrgNr 556677-8899 company", "block"},

	// ── PII: letter-bearing IDs (alnum classifier) ────────────────────────
	{"btc-bech32", "wallet bc1qar0srrr7xfkvy5l643lydnw9re59gtzzwf5mdq please", "block"},
	{"btc-legacy", "send to 1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa quickly", "block"},
	{"iban-de", "iban DE89370400440532013000 ok?", "block"},
	{"iban-gb", "send to GB82WEST12345698765432 today", "block"},
	{"us-passport", "passport book A12345678 issued", "block"},
	{"us-mbi", "patient 1EG4-TE5-MK73 medicare", "block"},
	{"us-dea", "DEA AB1234563 on file", "block"},
	{"uk-nino", "NINO AB123456C registered", "block"},
	{"uk-passport", "passport AB1234567 in scope", "block"},
	{"de-vat", "DE123456789 is our VAT id", "block"},
	{"in-pan", "PAN ABCPK1234E for KYC", "block"},
	{"in-passport", "passport L1234567 issued in Delhi", "block"},
	{"es-nif", "DNI 12345678Z", "block"},
	{"es-nie", "NIE X1234567L for residency", "block"},
	{"sg-nric", "NRIC S1234567D", "block"},
	{"sg-uen", "Entity UEN 200512345A", "block"},
	{"fi-pic", "hetu 131052-308T", "block"},

	// ── negatives: must NOT trip ──────────────────────────────────────────
	{"clean-math", "what is 2 + 2?", "clean"},
	{"loopback", "is 127.0.0.1 and localhost the loopback address?", "clean"},
	{"plain-numbers", "the year is 2026 and pi is about 3.14159", "clean"},
	{"aws-key-b64", "run echo QUtJQUlPU0ZPRE5ON0VYQU1QTEU= | base64 -d for deploy", "block"},
	{"de-vat-fp-code", "SKU CODE123456789 is not a German VAT number", "clean"},
	{"aws-key-path", "read ~/.config/aws/credentials — key AKIAIOSFODNN7EXAMPLE inside", "block"},

	// ── clean / benign: normal prompts with NO PII or secrets — must forward ──
	{"clean-bsearch", "explain how binary search works in simple terms", "clean"},
	{"clean-tcp-udp", "what is the difference between TCP and UDP?", "clean"},
	{"clean-haiku", "write a haiku about the ocean at sunrise", "clean"},
	{"clean-rest-api", "what are good practices for designing a REST API?", "clean"},
	{"clean-reverse-str", "how do I reverse a string in Python?", "clean"},
	{"clean-translate", "translate 'good morning, how are you' into French", "clean"},
	{"clean-git", "what does git rebase do compared to git merge?", "clean"},
	{"clean-bigo", "explain big-O notation with an everyday analogy", "clean"},
	{"clean-recipe", "suggest a simple recipe for tomato soup", "clean"},
	{"clean-units", "convert 100 fahrenheit to celsius", "clean"},
	{"clean-unit-testing", "give me three benefits of writing unit tests", "clean"},
	{"clean-version", "we shipped version 2.1.3 to staging at 3pm, summarize next steps", "clean"},
	{"clean-http-status", "the API returned status 200 then 404, what could cause that?", "clean"},
	{"clean-sql", "write a SQL query to count users grouped by signup month", "clean"},
}

func corpusScan(prompt string) []Match {
	return DefaultScanner().Scan([]byte(prompt))
}

// TestGenerateCorpus regenerates testagent/cases.jsonl from corpusSeeds, scanning
// each with the real scanner to discover rules + extract secrets. Gated behind
// WRITE_CORPUS=1 so a normal `go test` never overwrites the committed corpus.
func TestGenerateCorpus(t *testing.T) {
	if os.Getenv("WRITE_CORPUS") == "" {
		t.Skip("set WRITE_CORPUS=1 to (re)generate testagent/cases.jsonl")
	}
	pol := Policy{Threshold: SevLow}
	var lines []string
	for _, s := range corpusSeeds {
		ms := corpusScan(s.prompt)
		trig := pol.triggering(ms)
		if s.want == "block" && len(trig) == 0 {
			t.Logf("skip: seed %q expected to trip a rule but stayed clean (fix the value)", s.name)
			continue
		}
		if s.want == "clean" && len(trig) > 0 {
			t.Errorf("seed %q expected clean but tripped %v", s.name, ruleIDs(trig))
			continue
		}
		ruleSet, secSet := map[string]bool{}, map[string]bool{}
		var rules, secrets []string
		for _, m := range trig {
			if !ruleSet[m.RuleID] {
				ruleSet[m.RuleID] = true
				rules = append(rules, m.RuleID)
			}
			if m.End > m.Offset && m.End <= len(s.prompt) {
				v := s.prompt[m.Offset:m.End]
				if !secSet[v] {
					secSet[v] = true
					secrets = append(secrets, v)
				}
			}
		}
		c := corpusCase{Name: s.name, Prompt: s.prompt, Expect: "FORWARDED", Secrets: []string{}}
		if len(trig) > 0 {
			c.Expect = "BLOCKED"
			c.Rules = rules
			c.Secrets = secrets
		}
		b, _ := json.Marshal(c)
		lines = append(lines, string(b))
	}
	// testagent/ is gitignored (the harness isn't committed); create it if a dev
	// is generating the cases file for a local run.
	if err := os.MkdirAll(filepath.Dir(corpusPath), 0o755); err != nil {
		t.Fatalf("mkdir: %v", err)
	}
	if err := os.WriteFile(corpusPath, []byte(strings.Join(lines, "\n")+"\n"), 0o644); err != nil {
		t.Fatalf("write corpus: %v", err)
	}
	t.Logf("wrote %d cases to %s", len(lines), corpusPath)
}

// TestCorpusValidates checks the hardcoded corpus seeds against the live rules
// in every `go test` — no external files, so it works in any checkout (the
// testagent/ harness is intentionally not committed): every "block" seed must
// produce a triggering finding; every "clean" seed must stay clean.
func TestCorpusValidates(t *testing.T) {
	pol := Policy{Threshold: SevLow}
	for _, s := range corpusSeeds {
		ms := corpusScan(s.prompt)
		trig := pol.triggering(ms)
		switch s.want {
		case "block":
			if len(trig) == 0 {
				t.Errorf("%s: expected a triggering finding on %q, got none (matched %v)", s.name, s.prompt, ruleIDs(ms))
			}
		case "clean":
			if len(trig) > 0 {
				t.Errorf("%s: expected clean on %q, but tripped %v", s.name, s.prompt, ruleIDs(trig))
			}
		default:
			t.Errorf("%s: unknown want %q", s.name, s.want)
		}
	}
}

// TestCorpusRuleCoverage reports which built-in rules have no corpus case yet,
// so the corpus can be grown toward "every rule masqr catches". Informational
// (t.Log) — it lists gaps without failing the build.
func TestCorpusRuleCoverage(t *testing.T) {
	covered := map[string]bool{}
	for _, s := range corpusSeeds {
		for _, m := range DefaultScanner().Scan([]byte(s.prompt)) {
			covered[m.RuleID] = true
		}
	}
	var gaps []string
	for _, r := range defaultRules() {
		if !covered[r.ID] {
			gaps = append(gaps, r.ID)
		}
	}
	sort.Strings(gaps)
	t.Logf("corpus covers %d builtin rules; %d not yet covered: %v", len(covered), len(gaps), gaps)
}
