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
	"bufio"
	"bytes"
	"fmt"
	"os"
	"strings"

	ahocorasick "github.com/BobuSumisu/aho-corasick"
)

type keywordEntry struct {
	original string // as written in the file (case preserved)
	lower    string // lowercased form used for matching
	label    string // e.g., NAME, EMAIL, COMPANY_NAME
}

type keywordsSource struct {
	path    string
	trie    *ahocorasick.Trie
	entries []keywordEntry
}

func newKeywordsSource(path string) (*keywordsSource, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()

	var entries []keywordEntry
	patterns := []string{}
	sc := bufio.NewScanner(f)
	sc.Buffer(make([]byte, 64*1024), 1<<20)
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		parts := strings.SplitN(line, "|", 2)
		if len(parts) != 2 {
			continue
		}
		kw := strings.TrimSpace(parts[0])
		label := strings.TrimSpace(parts[1])
		if kw == "" || label == "" {
			continue
		}
		entries = append(entries, keywordEntry{
			original: kw,
			lower:    strings.ToLower(kw),
			label:    label,
		})
		patterns = append(patterns, strings.ToLower(kw))
	}
	if err := sc.Err(); err != nil {
		return nil, err
	}
	if len(entries) == 0 {
		return nil, fmt.Errorf("no keywords loaded from %s", path)
	}

	tb := ahocorasick.NewTrieBuilder()
	tb.AddStrings(patterns)
	return &keywordsSource{
		path:    path,
		trie:    tb.Build(),
		entries: entries,
	}, nil
}

func (k *keywordsSource) Name() string { return "keywords" }

func (k *keywordsSource) Scan(body []byte) []Match {
	lower := bytes.ToLower(body)
	hits := k.trie.Match(lower)
	if len(hits) == 0 {
		return nil
	}

	out := make([]Match, 0, len(hits))
	for _, m := range hits {
		idx := int(m.Pattern())
		if idx < 0 || idx >= len(k.entries) {
			continue
		}
		e := k.entries[idx]

		// BobuSumisu reports the START byte position.
		start := int(m.Pos())
		end := start + len(e.lower)
		if start < 0 || end > len(body) {
			continue
		}

		// Whole-word check (only enforce on alphanumeric boundaries).
		if isWordByte(e.lower[0]) {
			if start > 0 && isWordByte(body[start-1]) {
				continue
			}
		}
		if isWordByte(e.lower[len(e.lower)-1]) {
			if end < len(body) && isWordByte(body[end]) {
				continue
			}
		}

		sev := severityFor(e.label)
		ruleID := "keyword:" + e.label
		raw := string(body[start:end])
		out = append(out, Match{
			RuleID:   ruleID,
			Category: "pii-org",
			Severity: sev,
			Offset:   start,
			End:      end,
			Snippet:  raw,
			Identity: identityOf(ruleID, raw),
		})
	}
	return out
}

func isWordByte(b byte) bool {
	return (b >= 'a' && b <= 'z') ||
		(b >= 'A' && b <= 'Z') ||
		(b >= '0' && b <= '9') ||
		b == '_'
}

func severityFor(label string) Severity {
	switch strings.ToUpper(label) {
	case "SECRET":
		return SevCritical
	case "EMAIL", "PHONE", "ADDRESS":
		return SevHigh
	case "NAME":
		return SevMedium
	case "COMPANY_NAME", "PROJECT_NAME":
		return SevLow
	default:
		return SevMedium
	}
}
