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
	"testing"
)

func writeKeywordsFile(t *testing.T, content string) string {
	t.Helper()
	dir := t.TempDir()
	p := filepath.Join(dir, "keywords.txt")
	if err := os.WriteFile(p, []byte(content), 0o600); err != nil {
		t.Fatalf("write keywords: %v", err)
	}
	return p
}

func TestKeywordsParserSkipsCommentsAndBlanks(t *testing.T) {
	path := writeKeywordsFile(t, `# header comment

Alice|NAME

  # another comment
Bob Smith|NAME
acme-corp|COMPANY_NAME
malformed line without pipe
|MISSING_KEYWORD
keyword_without_label|
`)
	src, err := newKeywordsSource(path)
	if err != nil {
		t.Fatalf("newKeywordsSource: %v", err)
	}
	if got, want := len(src.entries), 3; got != want {
		t.Fatalf("entries = %d, want %d (Alice, Bob Smith, acme-corp)", got, want)
	}
}

func TestKeywordsScanOffsetsAndBoundaries(t *testing.T) {
	path := writeKeywordsFile(t, `Alice Johnson|NAME
Alice|NAME
Project Bison|PROJECT_NAME
acme-corp|COMPANY_NAME
+41 79 555 0123|PHONE
shyshkov@gmail.com|EMAIL
`)
	src, err := newKeywordsSource(path)
	if err != nil {
		t.Fatalf("newKeywordsSource: %v", err)
	}

	body := []byte("Hello Alice Johnson, please ping shyshkov@gmail.com about Project Bison at acme-corp; phone +41 79 555 0123.")
	matches := src.Scan(body)

	got := map[string]struct {
		offset int
		text   string
	}{}
	for _, m := range matches {
		got[m.RuleID] = struct {
			offset int
			text   string
		}{m.Offset, m.Snippet}
	}

	want := []struct {
		ruleID string
		text   string
	}{
		{"keyword:NAME", "Alice Johnson"}, // longest match
		{"keyword:NAME", "Alice"},         // shorter also fires (separate entry)
		{"keyword:PROJECT_NAME", "Project Bison"},
		{"keyword:COMPANY_NAME", "acme-corp"},
		{"keyword:EMAIL", "shyshkov@gmail.com"},
		{"keyword:PHONE", "+41 79 555 0123"},
	}

	// Verify each expected entity appears at least once with the correct text.
	texts := map[string]bool{}
	for _, m := range matches {
		texts[m.RuleID+"|"+m.Snippet] = true
	}
	for _, w := range want {
		if !texts[w.ruleID+"|"+w.text] {
			t.Errorf("missing match: %s -> %q", w.ruleID, w.text)
		}
	}

	// Verify offsets land on the actual text in body (regression for the
	// Pos()-is-end-vs-start bug fixed earlier).
	for _, m := range matches {
		got := string(body[m.Offset : m.Offset+len(m.Snippet)])
		if got != m.Snippet {
			t.Errorf("offset mismatch for %s: snippet=%q body=%q", m.RuleID, m.Snippet, got)
		}
	}
}

func TestKeywordsWholeWordBoundary(t *testing.T) {
	// "Alice" should NOT match inside "AliceBlue" or "MyAlice".
	path := writeKeywordsFile(t, "Alice|NAME\n")
	src, _ := newKeywordsSource(path)
	cases := []struct {
		body string
		want int // expected match count
	}{
		{"Alice went home", 1},
		{"AliceBlue is a color", 0}, // suffix attached
		{"MyAlice is bad", 0},       // prefix attached
		{"Hello, Alice!", 1},        // punctuation neighbors ok
		{"Alice. And Alice.", 2},    // two whole-word hits
	}
	for _, c := range cases {
		got := len(src.Scan([]byte(c.body)))
		if got != c.want {
			t.Errorf("Scan(%q) returned %d matches, want %d", c.body, got, c.want)
		}
	}
}

func TestKeywordsCaseInsensitive(t *testing.T) {
	path := writeKeywordsFile(t, "Acme Corp|COMPANY_NAME\n")
	src, _ := newKeywordsSource(path)
	body := []byte("ACME CORP and acme corp and Acme Corp")
	got := len(src.Scan(body))
	if got != 3 {
		t.Errorf("expected 3 case-variant matches, got %d", got)
	}
}

func TestKeywordsSeverityMapping(t *testing.T) {
	want := map[string]Severity{
		"SECRET":       SevCritical,
		"EMAIL":        SevHigh,
		"PHONE":        SevHigh,
		"ADDRESS":      SevHigh,
		"NAME":         SevMedium,
		"COMPANY_NAME": SevLow,
		"PROJECT_NAME": SevLow,
		"UNKNOWN":      SevMedium,
	}
	for label, sev := range want {
		if got := severityFor(label); got != sev {
			t.Errorf("severityFor(%q) = %s, want %s", label, got, sev)
		}
	}
}

func TestKeywordsDeterministicOrdering(t *testing.T) {
	path := writeKeywordsFile(t, "Alice|NAME\nBob|NAME\n")
	src, _ := newKeywordsSource(path)
	body := []byte("Bob and Alice and Bob again")
	matches := src.Scan(body)
	sort.Slice(matches, func(i, j int) bool { return matches[i].Offset < matches[j].Offset })
	if len(matches) != 3 {
		t.Fatalf("got %d matches, want 3", len(matches))
	}
	if matches[0].Snippet != "Bob" || matches[1].Snippet != "Alice" || matches[2].Snippet != "Bob" {
		t.Errorf("ordering wrong: %v", []string{matches[0].Snippet, matches[1].Snippet, matches[2].Snippet})
	}
}
