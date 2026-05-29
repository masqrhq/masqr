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
	"encoding/base64"
	"math"
	"strings"
	"testing"
)

func TestShannonEntropy(t *testing.T) {
	cases := []struct {
		in  string
		min float64
		max float64
	}{
		{"aaaaaaaaaa", 0, 0.01},                    // all same → 0 bits
		{"abababab", 0.99, 1.01},                   // two symbols, 50/50 → 1 bit
		{"hello world this is a test", 3.0, 4.5},   // English prose
		{"AKIAIOSFODNN7EXAMPLE", 3.5, 5.0},         // mixed alphanum
		{"QUtJQUlPU0ZPRE5ON0VYQU1QTEU=", 3.5, 5.5}, // short b64 of structured content
	}
	for _, c := range cases {
		got := shannonEntropy([]byte(c.in))
		if got < c.min || got > c.max {
			t.Errorf("entropy(%q) = %.2f, want %.2f..%.2f", c.in, got, c.min, c.max)
		}
	}
}

func TestFindBase64Candidates(t *testing.T) {
	// A high-entropy base64 blob embedded in normal text.
	secret := base64.StdEncoding.EncodeToString([]byte("AKIAIOSFODNN7EXAMPLE-suffix-padding-to-bulk"))
	body := []byte("here is some text and " + secret + " and trailing words")

	hits := findBase64Candidates(body)
	if len(hits) != 1 {
		t.Fatalf("expected exactly 1 candidate, got %d", len(hits))
	}
	if hits[0].text != secret {
		t.Errorf("hit.text = %q, want %q", hits[0].text, secret)
	}
	expectedOffset := len("here is some text and ")
	if hits[0].offset != expectedOffset {
		t.Errorf("hit.offset = %d, want %d", hits[0].offset, expectedOffset)
	}
}

// findBase64Candidates is intentionally permissive — it returns
// everything that looks structurally like a base64 blob, so masqr can
// recursively peel wrappers whose intermediate layers don't clear the
// entropy floor. Low entropy is filtered later, by the
// `generic-base64-blob` rule's Validate. This test pins both halves of
// that split.
func TestFindBase64SurfacesLowEntropyButRuleDrops(t *testing.T) {
	body := []byte(strings.Repeat("a", 32))
	if got := findBase64Candidates(body); len(got) != 1 {
		t.Errorf("low-entropy string should still be returned as a decode candidate; got %d hits", len(got))
	}
	for _, m := range DefaultScanner().Scan(body) {
		if m.RuleID == "generic-base64-blob" {
			t.Errorf("low-entropy string should not be flagged as generic-base64-blob: %+v", m)
		}
	}
}

func TestFindBase64IgnoresShortStrings(t *testing.T) {
	body := []byte("short=ABCdef1234XYZ")
	if got := findBase64Candidates(body); len(got) != 0 {
		t.Errorf("string under length floor should not match; got %d", len(got))
	}
}

func TestTryDecodeBase64Dialects(t *testing.T) {
	plaintext := []byte("AKIAIOSFODNN7EXAMPLE")
	cases := map[string]string{
		"StdEncoding":    base64.StdEncoding.EncodeToString(plaintext),
		"RawStdEncoding": base64.RawStdEncoding.EncodeToString(plaintext),
		"URLEncoding":    base64.URLEncoding.EncodeToString(plaintext),
		"RawURLEncoding": base64.RawURLEncoding.EncodeToString(plaintext),
	}
	for name, enc := range cases {
		t.Run(name, func(t *testing.T) {
			got, err := tryDecodeBase64(enc)
			if err != nil {
				t.Fatalf("decode failed: %v", err)
			}
			if string(got) != string(plaintext) {
				t.Errorf("got %q, want %q", got, plaintext)
			}
		})
	}
}

func TestTryDecodeBase64Rejects(t *testing.T) {
	if _, err := tryDecodeBase64("!!!not a valid base64!!!"); err == nil {
		t.Error("expected error on invalid base64")
	}
}

func TestIsMostlyPrintable(t *testing.T) {
	cases := []struct {
		name string
		in   []byte
		want bool
	}{
		{"empty", []byte{}, false},
		{"ascii", []byte("hello world\n"), true},
		{"mostly-binary", []byte{0x00, 0x01, 0x02, 'h', 'i', 0xff, 0xfe}, false},
		{"png-magic", []byte{0x89, 'P', 'N', 'G', 0x0d, 0x0a, 0x1a, 0x0a}, false},
		{"mixed-mostly-printable", append([]byte(strings.Repeat("a", 90)), 0x00, 0x00), true}, // ~98% printable
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if got := isMostlyPrintable(c.in); got != c.want {
				t.Errorf("isMostlyPrintable(%q) = %v, want %v", c.in, got, c.want)
			}
		})
	}
}

func TestGenericBase64BlobRule(t *testing.T) {
	s := NewScanner(defaultRules())
	// A base64 blob that wraps an AWS access key id — recursive decode
	// surfaces the inner finding, which pins the outer blob to the
	// triggering span. Without an inner finding the bare blob is
	// suppressed (see dropEmptyBase64Blobs); harmless opaque tokens
	// should not block requests.
	payload := base64.StdEncoding.EncodeToString([]byte("AKIAIOSFODNN7EXAMPLE is the key"))
	body := []byte("prompt has data: " + payload + " end")

	matches := s.Scan(body)
	found := false
	for _, m := range matches {
		if m.RuleID == "generic-base64-blob" {
			found = true
			if m.Severity != SevLow {
				t.Errorf("severity = %s, want low", m.Severity)
			}
		}
	}
	if !found {
		t.Errorf("expected generic-base64-blob to fire alongside the decoded inner finding; got rules: %v", ruleIDs(matches))
	}
}

// TestGenericBase64BlobSuppressedWhenInnocuous pins the user-facing
// guarantee: a high-entropy base64 blob that decodes to something masqr
// has no rule for must NOT cause a block. The outer shape-only rule is
// dropped when no overlapping finding fires inside.
func TestGenericBase64BlobSuppressedWhenInnocuous(t *testing.T) {
	s := NewScanner(defaultRules())
	payload := base64.StdEncoding.EncodeToString([]byte("the quick brown fox jumps over a lazy dog 42 times"))
	body := []byte("prompt has data: " + payload + " end")

	for _, m := range s.Scan(body) {
		if m.RuleID == "generic-base64-blob" {
			t.Errorf("generic-base64-blob should be suppressed for innocuous payloads; got %+v", m)
		}
	}
}

func TestBase64DecodeRescanSurfacesHiddenAWSKey(t *testing.T) {
	s := NewScanner(defaultRules())
	// Wrap an AWS key inside base64 so the literal AKIA pattern is invisible.
	hidden := "AKIAIOSFODNN7EXAMPLE is the key and the secret is omitted"
	encoded := base64.StdEncoding.EncodeToString([]byte(hidden))
	body := []byte("benign prefix " + encoded + " benign suffix")

	matches := s.Scan(body)

	// The outer generic-base64-blob should fire.
	hasOuter := false
	hasInner := false
	for _, m := range matches {
		if m.RuleID == "generic-base64-blob" {
			hasOuter = true
		}
		if m.RuleID == "aws-access-key-id/base64-decoded" {
			hasInner = true
			// The offset must point at the OUTER base64 blob, not the
			// nonsensical inner offset which has no meaning in the body.
			if m.Offset < len("benign prefix ") || m.Offset > len(body) {
				t.Errorf("decoded match offset %d out of body bounds", m.Offset)
			}
		}
	}
	if !hasOuter {
		t.Error("outer generic-base64-blob did not fire")
	}
	if !hasInner {
		t.Errorf("decode-rescan did not surface the hidden AWS key; got rules: %v", ruleIDs(matches))
	}
}

func TestBase64RecursionDepthCapped(t *testing.T) {
	// Wrap the plaintext maxScanDepth+1 times. After exactly
	// maxScanDepth recursive decodes the scanner should refuse to go
	// deeper, leaving an undecoded final layer and no AWS-rule hit.
	plain := "AKIAIOSFODNN7EXAMPLE"
	payload := plain
	for i := 0; i <= maxScanDepth; i++ {
		payload = base64.StdEncoding.EncodeToString([]byte(payload))
	}
	body := []byte("data: " + payload)

	s := NewScanner(defaultRules())
	matches := s.Scan(body)

	for _, m := range matches {
		if strings.HasPrefix(m.RuleID, "aws-access-key-id") {
			t.Errorf("recursion exceeded maxScanDepth=%d: rule %s found despite wrapping %d times",
				maxScanDepth, m.RuleID, maxScanDepth+1)
		}
	}
	// Informational: entropy of the outer wrap.
	_ = math.Abs(shannonEntropy([]byte(payload)))
}
