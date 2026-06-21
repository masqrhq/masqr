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
	"regexp"
	"strconv"
	"strings"
)

// This file adds five more decode-and-rescan layers in the same shape as the
// reversible obfuscations in obfuscation.go. They normalise representations
// that masqr receives *on the wire* — i.e. the raw request bytes, after the
// transport's JSON encoder has run but before any JSON layer un-escapes them —
// so a secret hidden by one of them is folded back to its plain form and seen
// by the rule engine:
//
//   - double percent-encoding (`%2567…`): one lenient %XX pass leaves a normal
//     `%67…` run that the existing url-decode layer peels on the next recursion.
//   - fullwidth Unicode (`Ａ`/`Ａ`): NFKC-style fold of the halfwidth-and-
//     fullwidth block back to ASCII, covering both the raw-UTF-8 form and the
//     JSON-escaped `\uffXX` form.
//   - quoted-printable (`=67=68…`): MIME `=XX` octets.
//   - whitespace interleaving (`AKIA IOSF …`): strip the spacing inside a run
//     of short alphanumeric groups.
//   - backslash line-continuation (`…abcdef\<newline>ABCDEF…`): join the YAML/
//     shell style continuation the encoder leaves as `\\\n` (or `\` + newline).
//
// Each layer shares obfuscation.go's safeguards: the decode must stay mostly
// printable and the inner rescan must surface a real finding, so benign input
// that happens to match a finder shape produces nothing.

// The decoders below are registered in obfuscation.go's decodeLayers table.

// ─── double percent-encoding ─────────────────────────────────────────────────

// doublePercentRunPattern matches a chain of ≥8 `%25XX` quintuplets — the shape
// of a value whose every byte was percent-encoded twice (`%` → `%25`). A single
// lenient decode pass turns it into an ordinary `%XX` run.
var doublePercentRunPattern = regexp.MustCompile(`(?:%25[0-9A-Fa-f]{2}){8,}`)

func findDoublePercentCandidates(body []byte) []base64Hit {
	return runHits(doublePercentRunPattern, body)
}

// decodeDoublePercent peels exactly one percent layer leniently: each `%XX` is
// decoded, every other byte is copied through. `%2567` → `%67`, so the result
// is a clean single-encoded run the url-decode layer handles on recursion.
func decodeDoublePercent(s string) ([]byte, bool) {
	var b bytes.Buffer
	for i := 0; i < len(s); {
		if s[i] == '%' && i+3 <= len(s) {
			if v, err := strconv.ParseUint(s[i+1:i+3], 16, 8); err == nil {
				b.WriteByte(byte(v))
				i += 3
				continue
			}
		}
		b.WriteByte(s[i])
		i++
	}
	if b.Len() == 0 {
		return nil, false
	}
	return b.Bytes(), true
}

// ─── fullwidth Unicode ───────────────────────────────────────────────────────

// fullwidthRunPattern matches a run of ≥8 fullwidth ASCII variants, either as
// raw runes (U+FF01–FF5E) or as JSON `\uffXX` escapes — masqr sees the former
// when the transport emits raw UTF-8 and the latter when it escapes non-ASCII.
var fullwidthRunPattern = regexp.MustCompile(`(?:\\u[fF][fF][0-9A-Fa-f]{2}|[\x{ff01}-\x{ff5e}\x{3000}]){8,}`)

func findFullwidthCandidates(body []byte) []base64Hit {
	return runHits(fullwidthRunPattern, body)
}

// decodeFullwidth resolves any `\uffXX` escapes to their runes, then folds the
// fullwidth block back to ASCII (NFKC compatibility mapping for U+FF01–FF5E).
func decodeFullwidth(s string) ([]byte, bool) {
	if strings.Contains(s, `\u`) || strings.Contains(s, `\U`) {
		if dec, ok := decodeUnicodeEscapes(s); ok {
			s = dec
		}
	}
	var b strings.Builder
	for _, r := range s {
		b.WriteRune(foldFullwidth(r))
	}
	out := b.String()
	if out == "" {
		return nil, false
	}
	return []byte(out), true
}

// foldFullwidth maps a single fullwidth ASCII variant (or the ideographic
// space) to its halfwidth ASCII equivalent, leaving every other rune untouched.
func foldFullwidth(r rune) rune {
	switch {
	case r >= 0xFF01 && r <= 0xFF5E:
		return r - 0xFEE0
	case r == 0x3000:
		return ' '
	}
	return r
}

// ─── quoted-printable ────────────────────────────────────────────────────────

// quotedPrintableRunPattern matches a chain of ≥8 MIME `=XX` octets.
var quotedPrintableRunPattern = regexp.MustCompile(`(?:=[0-9A-Fa-f]{2}){8,}`)

func findQuotedPrintableCandidates(body []byte) []base64Hit {
	return runHits(quotedPrintableRunPattern, body)
}

func decodeQuotedPrintable(s string) ([]byte, bool) {
	var b bytes.Buffer
	for i := 0; i+3 <= len(s); i += 3 {
		if s[i] != '=' {
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

// ─── whitespace interleaving ─────────────────────────────────────────────────

// whitespaceRunPattern matches a run of ≥4 short alphanumeric groups separated
// by a single space/tab — the shape of a secret split into fixed-width chunks
// (`AKIA IOSF ODNN 7EXA MPLE`). Stripping the spacing rejoins the value.
var whitespaceRunPattern = regexp.MustCompile(`(?:[0-9A-Za-z]{2,8}[ \t]){3,}[0-9A-Za-z]{2,8}`)

// findWhitespaceCandidates keeps only runs whose groups are all the same width:
// a secret chunked for transport looks like `AKIA IOSF ODNN …`, whereas natural
// prose ("the year is 2026 and pi is about") has uneven word lengths. The
// uniform-width gate keeps the layer from rejoining ordinary sentences (which
// would otherwise feed the entropy-only generic-base64-blob rule).
func findWhitespaceCandidates(body []byte) []base64Hit {
	var out []base64Hit
	for _, hit := range runHits(whitespaceRunPattern, body) {
		if uniformChunkWidth(hit.text) {
			out = append(out, hit)
		}
	}
	return out
}

// uniformChunkWidth reports whether every whitespace-separated group in s has
// the same length.
func uniformChunkWidth(s string) bool {
	groups := strings.FieldsFunc(s, func(r rune) bool { return r == ' ' || r == '\t' })
	if len(groups) < 4 {
		return false
	}
	w := len(groups[0])
	for _, g := range groups[1:] {
		if len(g) != w {
			return false
		}
	}
	return true
}

func decodeWhitespaceInterleaved(s string) ([]byte, bool) {
	out := make([]byte, 0, len(s))
	for i := 0; i < len(s); i++ {
		if s[i] == ' ' || s[i] == '\t' {
			continue
		}
		out = append(out, s[i])
	}
	if len(out) == 0 || len(out) == len(s) {
		return nil, false
	}
	return out, true
}

// ─── backslash line-continuation ─────────────────────────────────────────────

// lineContinuationJunk matches a backslash run that escapes a line break,
// whether the break survives as a literal newline or was itself escaped to the
// two-character `\n` by the transport's JSON encoder.
var lineContinuationJunk = regexp.MustCompile(`\\+(?:\r?\n|n)`)

// lineContinuationRunPattern matches two or more identifier-ish fragments joined
// by such continuations — the shape of a secret folded across lines.
var lineContinuationRunPattern = regexp.MustCompile(`[0-9A-Za-z_]+(?:\\+(?:\r?\n|n)[0-9A-Za-z_]+)+`)

func findLineContinuationCandidates(body []byte) []base64Hit {
	return runHits(lineContinuationRunPattern, body)
}

func decodeLineContinuation(s string) ([]byte, bool) {
	out := lineContinuationJunk.ReplaceAllString(s, "")
	if out == s || out == "" {
		return nil, false
	}
	return []byte(out), true
}
