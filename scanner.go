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
	"crypto/sha256"
	"encoding/hex"
	"log"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"sync"

	ahocorasick "github.com/BobuSumisu/aho-corasick"
)

// ScanSource is anything that can extract Matches from a body.
type ScanSource interface {
	Name() string
	Scan(body []byte) []Match
}

type Severity string

const (
	SevCritical Severity = "critical"
	SevHigh     Severity = "high"
	SevMedium   Severity = "medium"
	SevLow      Severity = "low"
)

type Rule struct {
	ID       string
	Category string
	Severity Severity
	Keywords []string
	Pattern  *regexp.Regexp
	Validate func(string) bool                                  // optional checksum / context check
	Refine   func(body []byte, start, end int) (int, int, bool) // optional pre-validate match boundary fixup
}

type Match struct {
	RuleID   string
	Category string
	Severity Severity
	Offset   int
	End      int    // exclusive end offset in the scanned buffer; 0 means unknown
	Snippet  string // redacted preview
	// Identity is a stable per-finding fingerprint used by the redact-on-
	// repeat policy to recognise the same value across requests. Empty
	// when a source can't (or won't) commit to a stable raw form — those
	// matches always block instead of being redacted.
	Identity string
}

type Scanner struct {
	rules       []Rule
	prefixes    []string // ordered lowercase keyword list; index ↔ trie pattern id
	byPrefix    [][]int  // rules to dispatch per prefix index
	trie        *ahocorasick.Trie
	keywordless []int
	sources     []ScanSource
}

// RuleCount is the number of built-in regex rules (for DEBUG coverage reporting).
func (s *Scanner) RuleCount() int { return len(s.rules) }

// SourceNames lists the active external scan sources (gitleaks, digit-ids, …)
// for DEBUG coverage reporting.
func (s *Scanner) SourceNames() []string {
	names := make([]string, len(s.sources))
	for i, src := range s.sources {
		names[i] = src.Name()
	}
	return names
}

const maxScanBytes = 2 << 20 // 2 MiB cap

var (
	defaultScanner     *Scanner
	defaultScannerOnce sync.Once
)

func DefaultScanner() *Scanner {
	defaultScannerOnce.Do(func() {
		s := NewScanner(defaultRules())
		s.attachExternalSources()
		defaultScanner = s
	})
	return defaultScanner
}

// attachExternalSources wires up gitleaks, the consolidated digit-ID
// classifier, and (if available) the user's keywords.txt. Failures are
// logged but non-fatal — the built-in rule engine always runs even if these
// are unavailable.
func (s *Scanner) attachExternalSources() {
	if g, err := newGitleaksSource(); err != nil {
		log.Printf("scanner: gitleaks source disabled: %v", err)
	} else {
		s.sources = append(s.sources, g)
	}

	// digit-cluster classifier (US SSN, NPI, ABA; AU TFN/ACN/ABN/Medicare;
	// CA SIN; UK NHS; PL PESEL; KR RRN; TR TCKN; TH TNIN; IT VAT; DE Tax ID;
	// IN Aadhaar; SE personnummer/organisationsnummer). Runs in parallel
	// with gitleaks and is invariant to body content beyond digit clusters.
	s.sources = append(s.sources, newDigitIDSource())

	// alphanumeric-cluster classifier (US passport / MBI / DEA; UK NINO /
	// passport / driving licence; DE id card / health / social-security;
	// IT fiscal code / driver licence / identity card; ES NIF / NIE /
	// passport; IN PAN / passport / voter / GSTIN; SG NRIC-FIN / UEN;
	// KR passport). Consolidates ~22 letter-bearing regex passes into one.
	s.sources = append(s.sources, newAlnumIDSource())

	path := os.Getenv("MASQR_KEYWORDS")
	if path == "" {
		for _, candidate := range []string{
			"keywords.txt",
			"../bison-ai-concept/anonymizer-service/src/main/resources/keywords.txt",
		} {
			if _, err := os.Stat(candidate); err == nil {
				path, _ = filepath.Abs(candidate)
				break
			}
		}
	}
	if path != "" {
		if k, err := newKeywordsSource(path); err != nil {
			log.Printf("scanner: keywords source disabled (%s): %v", path, err)
		} else {
			s.sources = append(s.sources, k)
			log.Printf("scanner: loaded %d keywords from %s", len(k.entries), path)
		}
	}

	s.maybeAttachOCR()
}

func NewScanner(rules []Rule) *Scanner {
	s := &Scanner{rules: rules}
	idxByKw := map[string]int{}
	for i, r := range rules {
		if len(r.Keywords) == 0 {
			s.keywordless = append(s.keywordless, i)
			continue
		}
		for _, kw := range r.Keywords {
			k := strings.ToLower(kw)
			id, ok := idxByKw[k]
			if !ok {
				id = len(s.prefixes)
				s.prefixes = append(s.prefixes, k)
				s.byPrefix = append(s.byPrefix, nil)
				idxByKw[k] = id
			}
			s.byPrefix[id] = append(s.byPrefix[id], i)
		}
	}
	if len(s.prefixes) > 0 {
		tb := ahocorasick.NewTrieBuilder()
		tb.AddStrings(s.prefixes)
		s.trie = tb.Build()
	}
	return s
}

func (s *Scanner) Scan(body []byte) []Match {
	return s.scanRecursive(body, 0)
}

func (s *Scanner) scanRecursive(body []byte, depth int) []Match {
	if len(body) > maxScanBytes {
		body = body[:maxScanBytes]
	}

	// Built-in rules (sync). `tested` is a bit-array indexed by rule
	// position — faster and allocation-cheaper than a map for the small
	// rule counts we work with (≤ ~100 entries).
	var out []Match
	tested := make([]bool, len(s.rules))
	for _, idx := range s.keywordless {
		out = s.runRule(out, body, s.rules[idx])
		tested[idx] = true
	}
	if s.trie != nil {
		// Aho-Corasick is ~5-10× faster than RE2's case-insensitive
		// alternation prefilter for our keyword count. We pay one ASCII
		// lowercase pass over the body so the trie can stay case-sensitive.
		lower := bytes.ToLower(body)
		for _, hit := range s.trie.Match(lower) {
			id := int(hit.Pattern())
			if id < 0 || id >= len(s.byPrefix) {
				continue
			}
			for _, ridx := range s.byPrefix[id] {
				if tested[ridx] {
					continue
				}
				tested[ridx] = true
				out = s.runRule(out, body, s.rules[ridx])
			}
		}
	}

	// External sources in parallel — each is independent. Only at depth 0;
	// inside a base64-decoded payload, the built-in rules are enough (and
	// the external sources would re-scan the same blob).
	if depth == 0 && len(s.sources) > 0 {
		results := make([][]Match, len(s.sources))
		var wg sync.WaitGroup
		for i, src := range s.sources {
			wg.Add(1)
			go func(i int, src ScanSource) {
				defer wg.Done()
				results[i] = src.Scan(body)
			}(i, src)
		}
		wg.Wait()
		for _, m := range results {
			out = append(out, m...)
		}
	}

	// Decode-and-rescan high-entropy base64 blobs. Catches obfuscation like
	// `echo $AWS_KEY | base64`.
	if depth < maxScanDepth {
		for _, hit := range findBase64Candidates(body) {
			decoded, err := tryDecodeBase64(hit.text)
			if err != nil || !isMostlyPrintable(decoded) {
				continue
			}
			for _, m := range s.scanRecursive(decoded, depth+1) {
				m.RuleID += "/base64-decoded"
				// Re-anchor both ends to the outer blob: the inner
				// offsets are positions inside `decoded`, useless for
				// rewriting the original body. Treating the whole
				// blob as the redaction span is correct (and what the
				// outer generic-base64-blob match already does).
				m.Offset = hit.offset
				m.End = hit.offset + len(hit.text)
				m.Identity = ""
				out = append(out, m)
			}
		}
	}

	if depth == 0 {
		out = dropEmptyBase64Blobs(out)
		out = suppressMachineTimestamps(body, out)
	}
	return dedupeMatches(out)
}

// dropEmptyBase64Blobs filters `generic-base64-blob` matches that have no
// other finding overlapping their span. The rule fires on shape + entropy
// alone, which produces noisy positives on any opaque high-entropy token
// (session IDs, signed cookies, harmless payloads). When the recursive
// decode-rescan did surface something concrete inside the blob it shows up
// as a `<rule>/base64-decoded` match anchored to the same [Offset:End]
// span — that's the signal masqr should block on. A bare
// `generic-base64-blob` with nothing alongside it is the user's "base64
// blob with no secret" case and should pass through silently.
//
// Runs only at recursion depth 0 so inner-layer findings are already
// folded into `out` by the time the filter runs.
func dropEmptyBase64Blobs(in []Match) []Match {
	if len(in) == 0 {
		return in
	}
	hasCompanion := func(blob Match) bool {
		for _, m := range in {
			if m.RuleID == "generic-base64-blob" {
				continue
			}
			if m.Offset >= blob.Offset && m.Offset < blob.End {
				return true
			}
		}
		return false
	}
	out := in[:0]
	for _, m := range in {
		if m.RuleID == "generic-base64-blob" && !hasCompanion(m) {
			continue
		}
		out = append(out, m)
	}
	return out
}

// dedupeMatches removes overlapping matches that point at the same byte
// range, preferring the higher-severity one. Two findings collapse into one
// when they share the same (offset, end, category, severity) — that's the
// case when built-in `aws-access-key-id` and `gitleaks:<rule>` flag the same
// secret span with the same category ("secret"). The byte range is part of
// the key on purpose: the same *value* repeated at different offsets (e.g. an
// email that appears several times in one request) must stay as separate
// matches so redactSpans masks every occurrence — keying on the value alone
// collapsed them to one and leaked the rest upstream in cleartext. Different
// *categories* represent distinct interpretations (e.g., a 9-digit Luhn-valid
// number could be a US-SSN or a CA-SIN) and are intentionally kept
// side-by-side so downstream policy / users can read the context themselves.
func dedupeMatches(in []Match) []Match {
	if len(in) <= 1 {
		return in
	}
	sort.SliceStable(in, func(i, j int) bool {
		if in[i].Offset != in[j].Offset {
			return in[i].Offset < in[j].Offset
		}
		return severityRank(in[i].Severity) > severityRank(in[j].Severity)
	})
	out := make([]Match, 0, len(in))
	seen := make(map[string]bool, len(in))
	for _, m := range in {
		key := strconv.Itoa(m.Offset) + "|" + strconv.Itoa(m.End) + "|" + m.Category + "|" + string(m.Severity)
		if seen[key] {
			continue
		}
		seen[key] = true
		out = append(out, m)
	}
	return out
}

func severityRank(s Severity) int {
	switch s {
	case SevCritical:
		return 4
	case SevHigh:
		return 3
	case SevMedium:
		return 2
	case SevLow:
		return 1
	}
	return 0
}

func (s *Scanner) runRule(out []Match, body []byte, r Rule) []Match {
	for _, m := range r.Pattern.FindAllIndex(body, -1) {
		start, end := m[0], m[1]
		if r.Refine != nil {
			ns, ne, ok := r.Refine(body, start, end)
			if !ok {
				continue
			}
			start, end = ns, ne
		}
		snippet := string(body[start:end])
		if r.Validate != nil && !r.Validate(snippet) {
			continue
		}
		out = append(out, Match{
			RuleID:   r.ID,
			Category: r.Category,
			Severity: r.Severity,
			Offset:   start,
			End:      end,
			Snippet:  redactSnippet(snippet),
			Identity: identityOf(r.ID, snippet),
		})
	}
	return out
}

// identityOf returns a short stable fingerprint for a (rule, raw-match) pair.
// Truncated SHA-256 hex is plenty for collision-avoidance within a single
// masqr session and keeps the in-memory memo cheap. Empty rule or value
// returns "" so callers can detect un-redactable matches.
func identityOf(ruleID, raw string) string {
	if ruleID == "" || raw == "" {
		return ""
	}
	sum := sha256.Sum256([]byte(ruleID + "\x00" + raw))
	return hex.EncodeToString(sum[:8])
}

func redactSnippet(s string) string {
	s = strings.TrimSpace(s)
	if len(s) <= 8 {
		return strings.Repeat("•", len(s))
	}
	return s[:4] + strings.Repeat("•", min(len(s)-8, 16)) + s[len(s)-4:]
}
