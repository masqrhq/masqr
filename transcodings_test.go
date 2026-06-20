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
	"compress/gzip"
	"encoding/base32"
	"encoding/base64"
	"encoding/hex"
	"strings"
	"testing"
)

// Public, documentation-only samples — the same ones the red-team gap corpus
// uses. Neither is a live credential.
const (
	sampleAWSKey    = "AKIAIOSFODNN7EXAMPLE"
	sampleGitHubPAT = "ghp_1234567890abcdefABCDEF1234567890abcd"
)

func gzipB64(t *testing.T, s string) string {
	t.Helper()
	var buf bytes.Buffer
	zw := gzip.NewWriter(&buf)
	if _, err := zw.Write([]byte(s)); err != nil {
		t.Fatalf("gzip write: %v", err)
	}
	if err := zw.Close(); err != nil {
		t.Fatalf("gzip close: %v", err)
	}
	return base64.StdEncoding.EncodeToString(buf.Bytes())
}

func percentEncode(s string) string {
	var b strings.Builder
	for i := 0; i < len(s); i++ {
		b.WriteString("%")
		b.WriteString(strings.ToUpper(hex.EncodeToString([]byte{s[i]})))
	}
	return b.String()
}

func htmlEntityEncode(s string) string {
	var b strings.Builder
	for i := 0; i < len(s); i++ {
		b.WriteString("&#")
		b.WriteString(itoa(int(s[i])))
		b.WriteString(";")
	}
	return b.String()
}

func itoa(n int) string {
	if n == 0 {
		return "0"
	}
	var digits []byte
	for n > 0 {
		digits = append([]byte{byte('0' + n%10)}, digits...)
		n /= 10
	}
	return string(digits)
}

func scannerFlagged(body, wantRulePrefix string) bool {
	for _, m := range DefaultScanner().Scan([]byte(body)) {
		if strings.HasPrefix(m.RuleID, wantRulePrefix) {
			return true
		}
	}
	return false
}

// TestObfuscatedSecretsAreDecoded covers every technique the red-team corpus
// flagged as a known gap: base32, hex, URL percent-encoding, HTML numeric
// entities, and gzip-then-base64. Each fixture embeds a public sample secret
// behind one encoding layer; the scanner must normalize it back and fire the
// underlying rule.
func TestObfuscatedSecretsAreDecoded(t *testing.T) {
	cases := []struct {
		technique  string
		encoded    string
		wantRuleID string
	}{
		// AWS access key id.
		{"base32", base32.StdEncoding.WithPadding(base32.NoPadding).EncodeToString([]byte(sampleAWSKey)), "aws-access-key-id"},
		{"hex", hex.EncodeToString([]byte(sampleAWSKey)), "aws-access-key-id"},
		{"url_percent", percentEncode(sampleAWSKey), "aws-access-key-id"},
		{"html_entities", htmlEntityEncode(sampleAWSKey), "aws-access-key-id"},
		{"gzip_b64", gzipB64(t, sampleAWSKey), "aws-access-key-id"},

		// GitHub personal access token.
		{"base32", base32.StdEncoding.WithPadding(base32.NoPadding).EncodeToString([]byte(sampleGitHubPAT)), "github-pat"},
		{"hex", hex.EncodeToString([]byte(sampleGitHubPAT)), "github-pat"},
		{"url_percent", percentEncode(sampleGitHubPAT), "github-pat"},
		{"html_entities", htmlEntityEncode(sampleGitHubPAT), "github-pat"},
		{"gzip_b64", gzipB64(t, sampleGitHubPAT), "github-pat"},
	}

	for _, tc := range cases {
		t.Run(tc.wantRuleID+"/"+tc.technique, func(t *testing.T) {
			body := "Deploy note — production " + tc.wantRuleID +
				" for the worker pool: " + tc.encoded
			if !scannerFlagged(body, tc.wantRuleID) {
				t.Fatalf("technique %q: scanner missed %s in %q",
					tc.technique, tc.wantRuleID, body)
			}
		})
	}
}

// TestObfuscatedSecrets_ExactCorpusFixtures pins the precise byte strings the
// red-team corpus reported as missed, so a regression in the decoders is caught
// against the literal inputs rather than only locally re-encoded ones.
func TestObfuscatedSecrets_ExactCorpusFixtures(t *testing.T) {
	cases := []struct {
		id         string
		content    string
		wantRuleID string
	}{
		{"aws:base32", "IFFUSQKJJ5JUMT2EJZHDORKYIFGVATCF", "aws-access-key-id"},
		{"aws:hex", "414b4941494f53464f444e4e374558414d504c45", "aws-access-key-id"},
		{"aws:url_percent", "%41%4B%49%41%49%4F%53%46%4F%44%4E%4E%37%45%58%41%4D%50%4C%45", "aws-access-key-id"},
		{"aws:html_entities", "&#65;&#75;&#73;&#65;&#73;&#79;&#83;&#70;&#79;&#68;&#78;&#78;&#55;&#69;&#88;&#65;&#77;&#80;&#76;&#69;", "aws-access-key-id"},
		{"aws:gzip_b64", "H4sIAI4CN2oC/3P09nT09A9283fx8zN3jXD0DfBxBQDiHCf6FAAAAA==", "aws-access-key-id"},
		{"ghp:base32", "M5UHAXZRGIZTINJWG44DSMDBMJRWIZLGIFBEGRCFIYYTEMZUGU3DOOBZGBQWEY3E", "github-pat"},
		{"ghp:hex", "6768705f313233343536373839306162636465664142434445463132333435363738393061626364", "github-pat"},
		{"ghp:gzip_b64", "H4sIAI4CN2oC/0vPKIg3NDI2MTUzt7A0SExKTklNc3RydnF1QxUFAKQSDtYoAAAA", "github-pat"},
	}
	for _, tc := range cases {
		t.Run(tc.id, func(t *testing.T) {
			body := "Deploy note — production for the worker pool: " + tc.content
			if !scannerFlagged(body, tc.wantRuleID) {
				t.Fatalf("missed %s for fixture %s: %q", tc.wantRuleID, tc.id, body)
			}
		})
	}
}

// TestTranscodingDecoders exercises the individual decoders directly so a
// failure points at the codec rather than the whole pipeline.
func TestTranscodingDecoders(t *testing.T) {
	want := sampleAWSKey

	if d, ok := decodeHex(hex.EncodeToString([]byte(want))); !ok || string(d) != want {
		t.Errorf("decodeHex = %q, %v; want %q", d, ok, want)
	}
	b32 := base32.StdEncoding.WithPadding(base32.NoPadding).EncodeToString([]byte(want))
	if d, ok := decodeBase32(b32); !ok || string(d) != want {
		t.Errorf("decodeBase32 = %q, %v; want %q", d, ok, want)
	}
	if d, ok := decodePercent(percentEncode(want)); !ok || string(d) != want {
		t.Errorf("decodePercent = %q, %v; want %q", d, ok, want)
	}
	if d, ok := decodeHTMLEntities(htmlEntityEncode(want)); !ok || string(d) != want {
		t.Errorf("decodeHTMLEntities = %q, %v; want %q", d, ok, want)
	}

	var buf bytes.Buffer
	zw := gzip.NewWriter(&buf)
	zw.Write([]byte(want))
	zw.Close()
	if d, ok := maybeDecompress(buf.Bytes()); !ok || string(d) != want {
		t.Errorf("maybeDecompress = %q, %v; want %q", d, ok, want)
	}
	if _, ok := maybeDecompress([]byte("not gzip data at all")); ok {
		t.Errorf("maybeDecompress accepted non-gzip input")
	}
}

// TestTranscodingDoesNotFlagBenignText guards against the new decoders turning
// ordinary high-entropy-looking text into false positives. None of these decode
// to anything matching a secret rule.
func TestTranscodingDoesNotFlagBenignText(t *testing.T) {
	benign := []string{
		"git commit deadbeefdeadbeefcafebabe0123456789abcdef0123",         // hex of binary → garbage
		"CONSTANTVALUEFORTHECONFIGURATIONOFSOMETHINGLARGE",                // all-caps, base32 alphabet
		"path is %2Fhome%2Fuser%2Fproject%2Fsrc%2Fmain and more",          // url-encoded path
		"entities &#104;&#101;&#108;&#108;&#111; mean hello not a secret", // html → "hello"
	}
	for _, b := range benign {
		for _, m := range DefaultScanner().Scan([]byte(b)) {
			if m.Category == "secret" {
				t.Errorf("benign text flagged as secret: rule=%q body=%q", m.RuleID, b)
			}
		}
	}
}
