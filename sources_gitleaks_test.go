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

func TestGitleaksSourceLoads(t *testing.T) {
	src, err := newGitleaksSource()
	if err != nil {
		t.Fatalf("newGitleaksSource: %v", err)
	}
	if src.Name() != "gitleaks" {
		t.Errorf("Name() = %q, want %q", src.Name(), "gitleaks")
	}
	if src.detector == nil {
		t.Fatal("detector is nil")
	}
	if len(src.detector.Config.Rules) < 50 {
		t.Errorf("default config has only %d rules, expected the full gitleaks ruleset (>=50)", len(src.detector.Config.Rules))
	}
}

// TestGitleaksKnownPatterns feeds the upstream detector well-formed example
// credentials and asserts gitleaks reports them. Rule IDs aren't pinned —
// gitleaks ships frequently and renames are possible — so we assert on
// (presence + redacted-snippet-prefix) instead.
func TestGitleaksKnownPatterns(t *testing.T) {
	src, err := newGitleaksSource()
	if err != nil {
		t.Fatalf("newGitleaksSource: %v", err)
	}

	body := []byte(strings.Join([]string{
		"GitHub PAT:  ghp_1234567890ABCDEFGHIJ1234567890ABCDEF",
		"GitHub fine: github_pat_11ABCDEFG0abcdefghijkl_AbCdEfGhIjKlMnOpQrStUvWxYz0123456789AbCdEfGhIjKl",
		"GCP key:     AIzaSyA1234567890abcdefghijklmnopqrstuvw",
		"PEM key:     -----BEGIN RSA PRIVATE KEY-----",
		"Slack hook:  https://hooks.slack.com/services/T01ABC23DEF/B04GHI56JKL/abcdefghijklmnop12345678",
	}, "\n"))

	matches := src.Scan(body)
	if len(matches) < 3 {
		t.Fatalf("expected gitleaks to fire on at least 3 patterns, got %d: %v", len(matches), ruleIDs(matches))
	}

	for _, m := range matches {
		if !strings.HasPrefix(m.RuleID, "gitleaks:") {
			t.Errorf("rule id %q missing gitleaks: prefix", m.RuleID)
		}
		if m.Category != "secret" {
			t.Errorf("category = %q, want secret", m.Category)
		}
		if m.Severity != SevCritical {
			t.Errorf("severity = %q, want critical", m.Severity)
		}
	}
}

func TestGitleaksNoMatchOnPlainText(t *testing.T) {
	src, err := newGitleaksSource()
	if err != nil {
		t.Fatalf("newGitleaksSource: %v", err)
	}
	body := []byte("hello world, this is a totally innocent prompt about cats and weather")
	if got := src.Scan(body); len(got) != 0 {
		t.Errorf("expected 0 matches, got %d: %v", len(got), ruleIDs(got))
	}
}

// TestGitleaksIgnoresUUIDsInGenericAPIKey pins the fix for the codex
// false-positive that broke `./masqr codex`: gitleaks' `generic-api-key`
// rule trips on UUIDv4/v7 session identifiers codex stamps into request
// headers on every call. Real generic API keys aren't UUID-shaped, so
// dropping these is a safe precision win.
func TestGitleaksIgnoresUUIDsInGenericAPIKey(t *testing.T) {
	src, err := newGitleaksSource()
	if err != nil {
		t.Fatalf("newGitleaksSource: %v", err)
	}
	uuids := []string{
		"019e6eea-2d92-7c72-9cb2-0c42d39e73f3", // UUIDv7 (codex session id)
		"550e8400-e29b-41d4-a716-446655440000", // canonical UUIDv4 example
	}
	for _, u := range uuids {
		body := []byte("session_id: " + u)
		for _, m := range src.Scan(body) {
			if m.RuleID == "gitleaks:generic-api-key" {
				t.Errorf("UUID %q falsely flagged as gitleaks:generic-api-key", u)
			}
		}
	}
}

func TestByteOffsetForLine(t *testing.T) {
	body := []byte("line one\nline two\nline three\n")
	cases := []struct {
		line int
		want int
	}{
		{0, 0},
		{1, 0},
		{2, 9},   // after "line one\n"
		{3, 18},  // after "line two\n"
		{99, 29}, // beyond EOF → falls through to len(body)
	}
	for _, c := range cases {
		if got := byteOffsetForLine(body, c.line); got != c.want {
			t.Errorf("byteOffsetForLine(_, %d) = %d, want %d", c.line, got, c.want)
		}
	}
}
