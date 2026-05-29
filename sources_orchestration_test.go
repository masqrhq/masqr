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
	"os"
	"path/filepath"
	"sort"
	"strings"
	"testing"
)

// TestScannerWithAllSources builds a fresh Scanner with built-in rules +
// gitleaks + keywords, scans a payload designed to trip every source, and
// asserts each source contributed at least one match.
func TestScannerWithAllSources(t *testing.T) {
	// Custom keyword file for this test.
	kwDir := t.TempDir()
	kwPath := filepath.Join(kwDir, "keywords.txt")
	if err := os.WriteFile(kwPath, []byte(strings.Join([]string{
		"Alice Johnson|NAME",
		"Project Bison|PROJECT_NAME",
		"acme-corp|COMPANY_NAME",
	}, "\n")), 0o600); err != nil {
		t.Fatalf("write keywords: %v", err)
	}
	t.Setenv("MASQR_KEYWORDS", kwPath)

	// Build a Scanner that mirrors what DefaultScanner produces, but in this
	// test instance so package-level singletons don't interfere across tests.
	s := NewScanner(defaultRules())
	s.attachExternalSources()

	if len(s.sources) < 2 {
		t.Fatalf("expected at least gitleaks+keywords sources, got %d", len(s.sources))
	}

	body := []byte(strings.Join([]string{
		"Hello Alice Johnson — pull up the Project Bison docs for acme-corp.",
		"AWS access key: AKIAIOSFODNN7EXAMPLE",
		"GitHub PAT:     ghp_1234567890ABCDEFGHIJ1234567890ABCDEF",
		"GCP API key:    AIzaSyA1234567890abcdefghijklmnopqrstuvw",
		"Credit card:    4532015112830366",
		"Swiss AHV:      756.1234.5678.97",
		"Swiss IBAN:     CH93 0076 2011 6238 5295 7",
		"Internal IP:    10.0.0.5",
		"PEM key:        -----BEGIN RSA PRIVATE KEY-----",
	}, "\n"))

	matches := s.Scan(body)
	if len(matches) == 0 {
		t.Fatal("multi-source scan returned zero matches")
	}

	prefixes := map[string]bool{}
	categories := map[string]bool{}
	for _, m := range matches {
		prefixes[ruleSourcePrefix(m.RuleID)] = true
		categories[m.Category] = true
	}

	// Each layer should have produced at least one match.
	want := []string{"built-in", "gitleaks:", "keyword:"}
	for _, p := range want {
		if !prefixes[p] {
			t.Errorf("missing layer %q in match set; got layers=%v", p, sortedKeys(prefixes))
		}
	}

	// Categories cross-section: secret + pii-card + pii-ch + pii-org + internal-ip.
	for _, c := range []string{"secret", "pii-card", "pii-ch", "pii-org", "internal-ip"} {
		if !categories[c] {
			t.Errorf("missing category %q in match set; got cats=%v", c, sortedKeys(categories))
		}
	}
}

func TestScannerBodyCap(t *testing.T) {
	// Force a body bigger than maxScanBytes (2 MiB) and verify Scan caps it.
	// We add a credit card just past the cap so the always-on cards rule
	// would fire if the cap weren't enforced.
	big := make([]byte, maxScanBytes+1024)
	for i := range big {
		big[i] = 'a'
	}
	copy(big[maxScanBytes+100:], []byte("4532015112830366"))

	s := NewScanner(defaultRules())
	matches := s.Scan(big)
	for _, m := range matches {
		if m.RuleID == "credit-card" && m.Offset >= maxScanBytes {
			t.Errorf("match found beyond body cap at offset %d (cap=%d)", m.Offset, maxScanBytes)
		}
	}
}

// TestScannerParallelSafe runs Scan from multiple goroutines concurrently to
// catch race conditions in the source orchestration layer.
func TestScannerParallelSafe(t *testing.T) {
	s := NewScanner(defaultRules())
	s.attachExternalSources()
	body := []byte("AKIAIOSFODNN7EXAMPLE and ghp_1234567890ABCDEFGHIJ1234567890ABCDEF")
	done := make(chan int, 8)
	for i := 0; i < 8; i++ {
		go func() {
			done <- len(s.Scan(body))
		}()
	}
	first := <-done
	for i := 0; i < 7; i++ {
		if got := <-done; got != first {
			t.Errorf("non-deterministic match count across goroutines: got %d and %d", first, got)
		}
	}
}

func ruleSourcePrefix(ruleID string) string {
	if idx := strings.Index(ruleID, ":"); idx > 0 {
		return ruleID[:idx+1]
	}
	return "built-in"
}

func sortedKeys(m map[string]bool) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}
