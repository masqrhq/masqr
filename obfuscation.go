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
	"encoding/hex"
	"io"
	"regexp"
	"strconv"
	"strings"
)

// This file adds decode-and-rescan layers for reversible obfuscations that
// hide an otherwise-detectable secret from the rule engine: raw hex, base32,
// URL percent-encoding, HTML numeric character references, and gzip-then-
// base64. Each layer mirrors the existing base64 / \uXXXX handling in
// scanner.go: a finder returns candidate spans (reusing base64Hit for the
// {text, offset} pair) and a decoder peels exactly one layer. scanRecursive
// then rescans the decoded bytes and re-anchors any inner finding to the
// outer span so redaction masks the whole encoded run.
//
// The decoders are deliberately conservative — they only fire on runs that
// are structurally pure (a long contiguous hex/base32 run, a chain of %XX
// triplets, a chain of &#…; entities, or a gzip blob inside base64). The
// shared safeguards (decoded-printability check plus the requirement that the
// inner rescan surface a real finding) keep false positives and adversarial
// input bounded, exactly as they do for the base64 path.

type decodeLayer struct {
	suffix string
	find   func([]byte) []base64Hit
	decode func(string) ([]byte, bool)
}

// decodeLayers is the ordered set of obfuscation peelers applied at every
// recursion depth below maxScanDepth. base64 and \uXXXX keep their bespoke
// loops in scanner.go; everything reversible-but-textual lives here.
var decodeLayers = []decodeLayer{
	{"/hex-decoded", findHexCandidates, decodeHex},
	{"/base32-decoded", findBase32Candidates, decodeBase32},
	{"/url-decoded", findURLPercentCandidates, decodeURLPercent},
	{"/html-decoded", findHTMLEntityCandidates, decodeHTMLEntities},
	{"/gzip-decoded", findBase64Candidates, decodeGzipBase64},
	// Additional on-the-wire normalisations (see normalize.go): a value
	// double percent-encoded, fullwidth-Unicode, quoted-printable, split by
	// interleaved whitespace, or folded with a backslash line-continuation.
	{"/percent-decoded", findDoublePercentCandidates, decodeDoublePercent},
	{"/fullwidth-decoded", findFullwidthCandidates, decodeFullwidth},
	{"/qp-decoded", findQuotedPrintableCandidates, decodeQuotedPrintable},
	{"/whitespace-decoded", findWhitespaceCandidates, decodeWhitespaceInterleaved},
	{"/continuation-decoded", findLineContinuationCandidates, decodeLineContinuation},
}

// scanDecodedLayer decodes each candidate, rescans the plaintext one level
// deeper, and re-anchors every inner finding to the outer encoded span. It is
// the shared body behind the base64 / unicode loops generalised over a decode
// function, used by every entry in decodeLayers.
func (s *Scanner) scanDecodedLayer(out []Match, hits []base64Hit, depth int, suffix string, decode func(string) ([]byte, bool)) []Match {
	for _, hit := range hits {
		decoded, ok := decode(hit.text)
		if !ok || !isMostlyPrintable(decoded) {
			continue
		}
		for _, m := range s.scanRecursive(decoded, depth+1) {
			m.RuleID += suffix
			m.Offset = hit.offset
			m.End = hit.offset + len(hit.text)
			m.Identity = ""
			out = append(out, m)
		}
	}
	return out
}

// ─── hex ────────────────────────────────────────────────────────────────────

// hexRunPattern matches a contiguous run of ≥16 hex digits (≥8 decoded bytes).
// Shorter runs are too small to hold a useful secret and too common in prose.
var hexRunPattern = regexp.MustCompile(`[0-9A-Fa-f]{16,}`)

func findHexCandidates(body []byte) []base64Hit { return runHits(hexRunPattern, body) }

func decodeHex(s string) ([]byte, bool) {
	if len(s)%2 != 0 {
		return nil, false
	}
	d, err := hex.DecodeString(s)
	if err != nil {
		return nil, false
	}
	return d, true
}

// ─── base32 ──────────────────────────────────────────────────────────────────

// base32RunPattern matches a run of the standard RFC 4648 base32 alphabet
// (A–Z, 2–7) with optional `=` padding, long enough to hold a real secret.
var base32RunPattern = regexp.MustCompile(`[A-Z2-7]{16,}={0,6}`)

func findBase32Candidates(body []byte) []base64Hit { return runHits(base32RunPattern, body) }

func decodeBase32(s string) ([]byte, bool) {
	s = strings.TrimRight(s, "=")
	if pad := len(s) % 8; pad != 0 {
		s += strings.Repeat("=", 8-pad)
	}
	d, err := base32.StdEncoding.DecodeString(s)
	if err != nil {
		return nil, false
	}
	return d, true
}

// ─── URL percent-encoding ────────────────────────────────────────────────────

// urlPercentRunPattern matches a chain of ≥8 `%XX` triplets — the shape of a
// fully percent-encoded value rather than the odd encoded space in prose.
var urlPercentRunPattern = regexp.MustCompile(`(?:%[0-9A-Fa-f]{2}){8,}`)

func findURLPercentCandidates(body []byte) []base64Hit { return runHits(urlPercentRunPattern, body) }

func decodeURLPercent(s string) ([]byte, bool) {
	var b bytes.Buffer
	for i := 0; i+3 <= len(s); i += 3 {
		if s[i] != '%' {
			return nil, false
		}
		v, err := strconv.ParseUint(s[i+1:i+3], 16, 8)
		if err != nil {
			return nil, false
		}
		b.WriteByte(byte(v))
	}
	if b.Len() == 0 {
		return nil, false
	}
	return b.Bytes(), true
}

// ─── HTML numeric character references ───────────────────────────────────────

// htmlEntityRunPattern matches a chain of ≥8 decimal (`&#65;`) or hex
// (`&#x41;`) numeric character references.
var htmlEntityRunPattern = regexp.MustCompile(`(?:&#(?:x[0-9A-Fa-f]+|[0-9]+);){8,}`)

// htmlEntityPattern captures the numeric body of a single reference; the
// leading `x` (if present) marks a hex reference.
var htmlEntityPattern = regexp.MustCompile(`&#(x[0-9A-Fa-f]+|[0-9]+);`)

func findHTMLEntityCandidates(body []byte) []base64Hit { return runHits(htmlEntityRunPattern, body) }

func decodeHTMLEntities(s string) ([]byte, bool) {
	var b bytes.Buffer
	for _, m := range htmlEntityPattern.FindAllStringSubmatch(s, -1) {
		digits := m[1]
		var (
			v   uint64
			err error
		)
		if len(digits) > 0 && (digits[0] == 'x' || digits[0] == 'X') {
			v, err = strconv.ParseUint(digits[1:], 16, 32)
		} else {
			v, err = strconv.ParseUint(digits, 10, 32)
		}
		if err != nil {
			return nil, false
		}
		b.WriteRune(rune(v))
	}
	if b.Len() == 0 {
		return nil, false
	}
	return b.Bytes(), true
}

// ─── gzip + base64 ───────────────────────────────────────────────────────────

// decodeGzipBase64 peels a base64 layer then gunzips the result. It reuses the
// existing base64 candidate finder; non-gzip base64 simply fails the gzip
// header check and is left to the dedicated base64 loop in scanner.go.
func decodeGzipBase64(s string) ([]byte, bool) {
	raw, err := tryDecodeBase64(s)
	if err != nil {
		return nil, false
	}
	zr, err := gzip.NewReader(bytes.NewReader(raw))
	if err != nil {
		return nil, false
	}
	defer zr.Close()
	// Bound decompression so a small base64 blob can't expand without limit.
	out, err := io.ReadAll(io.LimitReader(zr, maxScanBytes))
	if err != nil {
		return nil, false
	}
	return out, true
}

// runHits returns every match of pat in body as a base64Hit {text, offset}.
func runHits(pat *regexp.Regexp, body []byte) []base64Hit {
	locs := pat.FindAllIndex(body, -1)
	if len(locs) == 0 {
		return nil
	}
	out := make([]base64Hit, 0, len(locs))
	for _, l := range locs {
		out = append(out, base64Hit{text: string(body[l[0]:l[1]]), offset: l[0]})
	}
	return out
}
