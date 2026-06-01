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

// TestFalsePositives_NoTriggersOnPromptContextNoise covers the three
// regressions the user actually hit in masqr-20260528-133920.log:
// `dangerouslyDisableSandbox` tripping generic-base64-blob,
// `4-5-20251001`-shaped date strings tripping uk-nhs, and `3600000ms`-shaped
// timeout literals tripping it-identity-card. None of these is sensitive
// and all of them appear in auto-injected CLI prompt context.
func TestFalsePositives_NoTriggersOnPromptContextNoise(t *testing.T) {
	noise := `
dangerouslyDisableSandbox is a tool flag.
claude-haiku-4-5-20251001 model knowledge cutoff date.
Default timeout: 3600000ms (one hour).
`
	got := DefaultScanner().Scan([]byte(noise))
	for _, m := range got {
		switch m.RuleID {
		case "generic-base64-blob", "uk-nhs", "it-identity-card":
			t.Errorf("false positive: rule=%q snippet=%q in noise text",
				m.RuleID, m.Snippet)
		}
	}
}

// TestKeywordAnchor_StillTriggersWithContext confirms the keyword gate
// doesn't kill recall: a real-looking NHS number alongside the "NHS"
// keyword should still trigger, and an Italian-ID-shaped token with
// "carta d'identità" context should still fire too.
func TestKeywordAnchor_StillTriggersWithContext(t *testing.T) {
	cases := []struct {
		name     string
		body     string
		wantRule string
	}{
		// 4520251001 — same digits that tripped in the live log; with
		// the NHS keyword present, it's a true positive again.
		{"nhs with anchor", "patient NHS number: 4520251001 on file", "uk-nhs"},
		// 3600000ms's shape (`\d{7}[A-Z]{2}`), but now in an Italian
		// document-ID context — should be flagged.
		{"it-id with anchor", "carta d'identità: 3600000MS", "it-identity-card"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			matches := DefaultScanner().Scan([]byte(tc.body))
			var hit bool
			for _, m := range matches {
				if m.RuleID == tc.wantRule {
					hit = true
				}
			}
			if !hit {
				t.Errorf("expected rule %q to fire on %q; got: %+v",
					tc.wantRule, tc.body, matches)
			}
		})
	}
}

// TestLooksLikeIdentifier covers the camelCase guard added to
// isHighEntropyBase64 directly, independently of the rule pipeline.
func TestLooksLikeIdentifier(t *testing.T) {
	cases := []struct {
		in   string
		want bool
	}{
		{"dangerouslyDisableSandbox", true},     // camelCase, no digits
		{"alongVariableNameInCamelCase", true},  // ≥2 transitions, no digits
		{"alphabetonlywordsplain", false},       // no transitions
		{"AKIAIOSFODNN7EXAMPLE", false},         // real AWS key has digits
		{"SGVsbG8gd29ybGQgaXMgYSB0ZXN0", false}, // real base64 has digits
	}
	for _, c := range cases {
		if got := looksLikeIdentifier(c.in); got != c.want {
			t.Errorf("looksLikeIdentifier(%q) = %v, want %v", c.in, got, c.want)
		}
	}
}

// TestEmailContextRefine covers the auto-injected user-email exclusion:
// Claude Code's `# userEmail` system-prompt block and Co-Authored-By
// `noreply@…` lines must not trip the email rule, while the same email
// appearing in actual user-typed content still does.
func TestEmailContextRefine(t *testing.T) {
	cases := []struct {
		name string
		body string
		want bool // true if email-address rule should fire
	}{
		{
			"claude code userEmail block — drop",
			"context:\n# userEmail\nThe user's email address is " +
				"viktor.shyshkovskyi@gmail.com.\n",
			false,
		},
		{
			"co-authored-by noreply — drop",
			"Co-Authored-By: Claude <noreply@anthropic.com>\n",
			false,
		},
		{
			"user-typed prompt with same email — flag",
			"please email me at viktor.shyshkovskyi@gmail.com about that",
			true,
		},
		{
			"user-typed prompt with noreply outside template — drop (local part match)",
			"shipping notifications go to noreply@my-domain.com",
			false, // noreply@ is template-shaped; we drop it everywhere
		},
		{
			"vibe agent email — drop",
			"Co-Authored-By: Mistral Vibe <vibe@mistral.ai>\n",
			false,
		},
		{
			"vibe email mixed case — drop",
			"please contact ViBe@MiStRaL.aI",
			false,
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			var fired bool
			for _, m := range DefaultScanner().Scan([]byte(tc.body)) {
				if m.RuleID == "email-address" {
					fired = true
				}
			}
			if fired != tc.want {
				t.Errorf("email-address fired=%v, want=%v on body=%q", fired, tc.want, tc.body)
			}
		})
	}
}

// TestNoiseStillCatchesEmails — guard rail: the FP fix must not blunt
// real PII detection in the same body it's pruning.
func TestNoiseStillCatchesEmails(t *testing.T) {
	body := `dangerouslyDisableSandbox tool flag.
Contact: alice@example.com about claude-haiku-4-5-20251001.`
	got := DefaultScanner().Scan([]byte(body))
	var sawEmail bool
	for _, m := range got {
		if m.RuleID == "email-address" && strings.Contains(strings.ToLower(m.Snippet), "alic") {
			sawEmail = true
		}
	}
	if !sawEmail {
		t.Errorf("email rule didn't fire on a true positive amid the noise: %+v", got)
	}
}
