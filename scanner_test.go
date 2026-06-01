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
	"strings"
	"testing"
)

// TestBuiltinRulesEndToEnd runs the full built-in rule set against a synthetic
// payload that should trip several detectors.
func TestBuiltinRulesEndToEnd(t *testing.T) {
	s := NewScanner(defaultRules())
	body := []byte(`
AWS:    AKIAIOSFODNN7EXAMPLE
GH:     ghp_1234567890ABCDEFGHIJ1234567890ABCDEF
Card:   4532015112830366
AHV:    756.1234.5678.97
IBAN:   CH9300762011623852957
Local:  10.0.0.5
JWT:    eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c
`)
	matches := s.Scan(body)

	want := []string{
		"aws-access-key-id",
		"github-pat",
		"credit-card",
		"ch-ahv",
		"ch-iban",
		"private-ipv4",
		"jwt",
	}
	got := map[string]bool{}
	for _, m := range matches {
		got[m.RuleID] = true
	}
	for _, w := range want {
		if !got[w] {
			t.Errorf("missing built-in rule match: %s (got matches: %v)", w, ruleIDs(matches))
		}
	}
}

func TestRedactSnippet(t *testing.T) {
	cases := []struct {
		in, want string
	}{
		{"", ""},
		{"abc", "•••"},
		{"abcd1234", "••••••••"}, // exactly 8 → all bullets
		{"AKIAIOSFODNN7EXAMPLE", "AKIA••••••••••••MPLE"},
		{"sk-ant-veryverylongsecrettokenstring0123456789abcdef", "sk-a••••••••••••••••cdef"}, // 16-bullet cap
	}
	for _, c := range cases {
		if got := redactSnippet(c.in); got != c.want {
			t.Errorf("redact(%q) = %q, want %q", c.in, got, c.want)
		}
	}
}

func TestDedupeMatches(t *testing.T) {
	in := []Match{
		{RuleID: "a", Snippet: "AKIA••••••MPLE", Severity: SevHigh, Offset: 10},
		{RuleID: "b", Snippet: "AKIA••••••MPLE", Severity: SevHigh, Offset: 10},     // dup (snippet+sev)
		{RuleID: "c", Snippet: "AKIA••••••MPLE", Severity: SevCritical, Offset: 10}, // diff sev, kept
		{RuleID: "d", Snippet: "OTHER", Severity: SevLow, Offset: 50},
	}
	out := dedupeMatches(in)
	if len(out) != 3 {
		t.Errorf("dedupe kept %d, want 3 (out=%v)", len(out), out)
	}
}

func TestScannerPrefilterShortCircuits(t *testing.T) {
	// Build a tiny scanner with one anchored rule. Body without the anchor
	// must short-circuit before running the expensive pattern.
	rules := []Rule{{
		ID:       "needle",
		Category: "test",
		Severity: SevHigh,
		Keywords: []string{"NEEDLE"},
		Pattern:  regexp.MustCompile(`NEEDLE-[A-Z0-9]+`),
	}}
	s := NewScanner(rules)
	if got := s.Scan([]byte("lots of hay but no anchor word")); len(got) != 0 {
		t.Errorf("expected 0 matches when anchor absent, got %d", len(got))
	}
	if got := s.Scan([]byte("found a NEEDLE-XY12 in the hay")); len(got) != 1 {
		t.Errorf("expected 1 match when anchor present, got %d", len(got))
	}
}

func TestGitLabTokenRules(t *testing.T) {
	s := NewScanner(defaultRules())
	cases := []struct {
		name, body, want string
	}{
		{"pat", "leak: glpat-abcdefghij1234567890", "gitlab-pat"},
		{"oauth", "secret: gloas-abcdefghij1234567890abcdefghij1234567890", "gitlab-oauth-app-secret"},
		{"pipeline", "trigger: glptt-abcdefghij1234567890abcdefghij1234567890", "gitlab-pipeline-trigger"},
		{"runner", "runner: glrt-abcdefghij1234567890", "gitlab-runner-token"},
		{"deploy", "deploy: gldt-abcdefghij1234567890", "gitlab-deploy-token"},
		{"feed", "feed: glft-abcdefghij1234567890", "gitlab-feed-token"},
		{"agent", "agent: glagent-abcdefghij1234567890abcdefghij1234567890abcdefghij", "gitlab-agent-token"},
		{"scim", "scim: glsoat-abcdefghij1234567890abcdefghij1234567890", "gitlab-scim-token"},
		{"ci-job", "job: glcbt-abcdefghij1234567890", "gitlab-ci-job-token"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			ms := s.Scan([]byte(c.body))
			hit := false
			for _, m := range ms {
				if m.RuleID == c.want {
					hit = true
					if m.Category != "secret" {
						t.Errorf("%s: category=%q, want secret", c.want, m.Category)
					}
					break
				}
			}
			if !hit {
				t.Errorf("expected %s to match in %q; got rules=%v", c.want, c.body, ruleIDs(ms))
			}
		})
	}
}

func TestEmailAddressRule(t *testing.T) {
	s := NewScanner(defaultRules())
	cases := []struct {
		body string
		want bool
	}{
		{"contact viktor.shyshkovskyi@gmail.com today", true},
		{"a.b+tag@sub.domain.co.uk works too", true},
		{"plain text without any emails here", false},
		{"@handle alone is not an email", false},
		{"foo@bar (no TLD) doesn't count", false},
		{"trailing dot foo@bar. invalid", false},
	}
	for _, c := range cases {
		ms := s.Scan([]byte(c.body))
		got := false
		for _, m := range ms {
			if m.RuleID == "email-address" {
				got = true
				break
			}
		}
		if got != c.want {
			t.Errorf("email rule on %q = %v, want %v (rules=%v)", c.body, got, c.want, ruleIDs(ms))
		}
	}
}

// TestEmailJSONEscapePrefix guards against the regression where a raw JSON
// body containing `\ntest@example.com` (two literal bytes `\` + `n`, not a
// newline) caused the regex to grab the leading `n` and report
// `ntest@example.com`. The Refine hook must shift past the artifact.
func TestEmailJSONEscapePrefix(t *testing.T) {
	s := NewScanner(defaultRules())
	body := []byte(`"text":"<session>\ntest@example.com\n</session>"`)
	var got *Match
	for i, m := range s.Scan(body) {
		if m.RuleID == "email-address" {
			got = &s.Scan(body)[i] // re-grab to keep pointer stable across loop
			break
		}
	}
	if got == nil {
		t.Fatalf("expected email-address match in %q", body)
	}
	if string(body[got.Offset:got.Offset+4]) != "test" {
		t.Errorf("offset %d points at %q, want 'test' (Refine should have skipped the \\n artifact)",
			got.Offset, string(body[got.Offset:got.Offset+4]))
	}
	if got.Snippet[:4] != "test" {
		t.Errorf("snippet prefix = %q, want 'test'", got.Snippet[:4])
	}
}

func TestValidatorRejection(t *testing.T) {
	// A regex-only match with a wrong checksum must be rejected by Validate.
	s := NewScanner(defaultRules())
	body := []byte("card 4532015112830367") // bad Luhn (last digit off by one)
	for _, m := range s.Scan(body) {
		if m.RuleID == "credit-card" {
			t.Errorf("Luhn-invalid card should NOT match: %+v", m)
		}
	}
}

// TestMiscBuiltinRules covers built-in rules that have no corpus seed of
// their own (the seeds with similar names exercise sibling rules or the
// gitleaks source instead): the underscore-form AWS secret, OpenAI project
// keys, Slack bot/user tokens, GCP OAuth client IDs and service-account
// key JSON, the 82-char fine-grained GitHub PAT, and the two Swiss PII
// rules (UID with Mod-11 checksum, PostFinance account).
func TestMiscBuiltinRules(t *testing.T) {
	s := NewScanner(defaultRules())
	// 82-char [A-Za-z0-9_] suffix — the fine-grained PAT's exact length.
	const ghPat = "github_pat_abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789_abcdefghijklmnopqrs"
	cases := []struct {
		name, body, want string
	}{
		{"aws-secret", "config aws_secret_access_key = wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY end", "aws-secret-access-key"},
		{"stripe", "charge with sk_live_4eC39HqLyjWDarjtT1zdp7dc now", "stripe-live-key"},
		{"openai", "key sk-proj-abcdefghijklmnopqrstuvwxyz0123456789 in env", "openai-api-key"},
		{"slack-token", "slack xoxb-123456789012-123456789012-abcdefghijklmnopqrstuvwx leaked", "slack-bot-or-user-token"},
		{"gcp-oauth", "client 123456789012-abcdefghijklmnopqrstuvwxyz012345.apps.googleusercontent.com here", "gcp-oauth-client-id"},
		{"gcp-sa-key", `creds {"type": "service_account", "project_id": "x"}`, "gcp-service-account-key"},
		{"github-fg", "tok " + ghPat + " set", "github-fine-grained-pat"},
		{"ch-uid", "company UID CHE-105.962.533 registered", "ch-uid"},
		{"ch-postfinance", "PostFinance account 80-2-2 please", "ch-postfinance-account"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			hit := false
			ms := s.Scan([]byte(c.body))
			for _, m := range ms {
				if m.RuleID == c.want {
					hit = true
					break
				}
			}
			if !hit {
				t.Errorf("expected %s to match in %q; got rules=%v", c.want, c.body, ruleIDs(ms))
			}
		})
	}
}

// TestAzureConnStringRules covers the five Azure connection-string / key
// rules in defaultRules(). The AccountKey value is the well-known Azurite
// (devstore) development key — 88 base64 chars, matching both the
// account-key {86,90} window and the conn-string {40,} window.
func TestAzureConnStringRules(t *testing.T) {
	s := NewScanner(defaultRules())
	const k = "Eby8vdM02xNOcqFlqUwJPLlmEtlCDXJ1OUzFT50uSRZ6IFsuFq2UVErCz4I6tq/K1SZFPTOtr/KBHBeksoGMGw=="
	cases := []struct {
		name, body, want string
	}{
		{"storage-conn", "conn DefaultEndpointsProtocol=https;AccountName=mystore;AccountKey=" + k + ";EndpointSuffix=core.windows.net", "azure-storage-conn-string"},
		{"account-key", "key AccountKey=" + k + " in config", "azure-storage-account-key"},
		{"service-bus", "bus Endpoint=sb://myns.servicebus.windows.net/;SharedAccessKeyName=RootManageSharedAccessKey;SharedAccessKey=abcDEF123ghiJKL456mnoPQR789stu= end", "azure-service-bus-conn"},
		{"cosmos", "cosmos AccountEndpoint=https://mycosmos.documents.azure.com:443/;AccountKey=" + k + "; trailing", "azure-cosmos-conn"},
		{"sql", "sql Server=tcp:myserver.database.windows.net,1433;Initial Catalog=mydb;User ID=admin;Password=P@ssw0rd123!; done", "azure-sql-conn"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			ms := s.Scan([]byte(c.body))
			hit := false
			for _, m := range ms {
				if m.RuleID == c.want {
					hit = true
					if m.Category != "azure" {
						t.Errorf("%s: category=%q, want azure", c.want, m.Category)
					}
					break
				}
			}
			if !hit {
				t.Errorf("expected %s to match in %q; got rules=%v", c.want, c.body, ruleIDs(ms))
			}
		})
	}
}

// TestPrivateIPv6Rule covers the private-ipv6 internal-IP rule (ULA fc00::/7
// and link-local fe80::/10).
func TestPrivateIPv6Rule(t *testing.T) {
	s := NewScanner(defaultRules())
	cases := []struct {
		name, body string
	}{
		{"ula-fd", "internal host fd00:1234:5678:9abc::1 reachable"},
		{"link-local-fe80", "iface fe80::1ff:fe23:4567:890a is link-local"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			hit := false
			for _, m := range s.Scan([]byte(c.body)) {
				if m.RuleID == "private-ipv6" {
					hit = true
					break
				}
			}
			if !hit {
				t.Errorf("expected private-ipv6 to match in %q", c.body)
			}
		})
	}
	// A public IPv6 (2001:db8::) must NOT trip the private-range rule.
	for _, m := range s.Scan([]byte("public 2001:db8::1 address")) {
		if m.RuleID == "private-ipv6" {
			t.Errorf("private-ipv6 should not match public 2001:db8::1: %+v", m)
		}
	}
}

func ruleIDs(ms []Match) []string {
	out := make([]string, 0, len(ms))
	seen := map[string]bool{}
	for _, m := range ms {
		if !seen[m.RuleID] {
			seen[m.RuleID] = true
			out = append(out, m.RuleID)
		}
	}
	return out
}

// Avoid go-vet/unused complaints on the strings import if a helper is removed.
var _ = strings.Builder{}
