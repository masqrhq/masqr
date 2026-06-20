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
	"html"
	"io"
	"net/url"
	"regexp"
)

// This file extends masqr's decode-and-rescan pipeline (see scanner.go) with
// the common "encode the secret so the literal rules miss it" tricks beyond
// base64 and \uXXXX escapes: lowercase/uppercase hex, base32, URL
// percent-encoding, HTML numeric entities, and gzip-then-base64. Each one is
// expressed as a `transcoding`: a span finder plus a decoder. The scanner
// runs the real rule engine over the decoded bytes, so the gates here stay
// deliberately loose — a candidate that decodes to non-printable bytes or to
// text that matches no rule simply produces nothing.
const (
	// 16 hex chars = 8 decoded bytes. Shorter runs can't hold a real
	// credential, and longer hashes (git SHAs, md5/sha256) decode to binary
	// and are dropped by the printable check.
	minHexLength = 16
	// base32 of a 20-byte AWS key is 32 chars; of structured tokens, longer.
	// 24 keeps short all-caps words (which share the A-Z2-7 alphabet) out of
	// the candidate set.
	minBase32Length = 24
	// Contiguous %XX / &#NN; runs: a real secret obfuscated this way is one
	// long uninterrupted run. 8 units = 8 decoded bytes minimum.
	minEscapeRun = 8
)

// transcoding pairs a candidate-span finder with a decoder and the RuleID
// suffix to stamp on findings recovered through it.
type transcoding struct {
	find   func(body []byte) []base64Hit
	decode func(s string) ([]byte, bool)
	suffix string
}

var (
	hexCandidatePattern        = regexp.MustCompile(`[0-9A-Fa-f]{16,}`)
	base32CandidatePattern     = regexp.MustCompile(`[A-Z2-7]{24,}={0,8}`)
	percentCandidatePattern    = regexp.MustCompile(`(?:%[0-9A-Fa-f]{2}){8,}`)
	htmlEntityCandidatePattern = regexp.MustCompile(`(?:&#[0-9]+;|&#[xX][0-9A-Fa-f]+;){8,}`)
)

// transcodings is the ordered set of secondary decoders applied to every scan
// body. base64 and \uXXXX escapes are handled inline in scanner.go because the
// former also feeds the gzip-then-base64 path.
var transcodings = []transcoding{
	{find: regexpHits(hexCandidatePattern), decode: decodeHex, suffix: "/hex-decoded"},
	{find: regexpHits(base32CandidatePattern), decode: decodeBase32, suffix: "/base32-decoded"},
	{find: regexpHits(percentCandidatePattern), decode: decodePercent, suffix: "/url-decoded"},
	{find: regexpHits(htmlEntityCandidatePattern), decode: decodeHTMLEntities, suffix: "/html-decoded"},
}

// regexpHits adapts a candidate pattern into the base64Hit-returning finder
// shape shared by the decode-and-rescan loop.
func regexpHits(re *regexp.Regexp) func(body []byte) []base64Hit {
	return func(body []byte) []base64Hit {
		locs := re.FindAllIndex(body, -1)
		if len(locs) == 0 {
			return nil
		}
		out := make([]base64Hit, 0, len(locs))
		for _, l := range locs {
			out = append(out, base64Hit{text: string(body[l[0]:l[1]]), offset: l[0]})
		}
		return out
	}
}

// decodeHex decodes an even-length run of hex digits. Odd-length runs are
// trimmed by one char rather than rejected outright, so a hex blob that abuts
// other text still decodes its leading bytes.
func decodeHex(s string) ([]byte, bool) {
	if len(s)%2 != 0 {
		s = s[:len(s)-1]
	}
	if len(s) < minHexLength {
		return nil, false
	}
	d, err := hex.DecodeString(s)
	if err != nil {
		return nil, false
	}
	return d, true
}

// decodeBase32 decodes standard (RFC 4648) base32, trimming the run to a whole
// number of 8-char blocks so unpadded runs still decode.
func decodeBase32(s string) ([]byte, bool) {
	s = trimPadding(s)
	if n := len(s) % 8; n != 0 {
		s = s[:len(s)-n]
	}
	if len(s) < 8 {
		return nil, false
	}
	d, err := base32.StdEncoding.WithPadding(base32.NoPadding).DecodeString(s)
	if err != nil {
		return nil, false
	}
	return d, true
}

// decodePercent decodes a contiguous run of %XX escapes.
func decodePercent(s string) ([]byte, bool) {
	d, err := url.PathUnescape(s)
	if err != nil {
		return nil, false
	}
	return []byte(d), true
}

// decodeHTMLEntities expands HTML entities (numeric and named) in a run.
func decodeHTMLEntities(s string) ([]byte, bool) {
	d := html.UnescapeString(s)
	if d == s {
		return nil, false
	}
	return []byte(d), true
}

// maybeDecompress inflates a gzip stream. It's used as a fallback when a
// base64 blob decodes to non-printable bytes: `gzip(secret) | base64` is a
// common way to smuggle a credential past literal scanners.
func maybeDecompress(data []byte) ([]byte, bool) {
	if len(data) < 2 || data[0] != 0x1f || data[1] != 0x8b {
		return nil, false
	}
	zr, err := gzip.NewReader(bytes.NewReader(data))
	if err != nil {
		return nil, false
	}
	defer zr.Close()
	out, err := io.ReadAll(io.LimitReader(zr, maxScanBytes))
	if err != nil || len(out) == 0 {
		return nil, false
	}
	return out, true
}

func trimPadding(s string) string {
	for len(s) > 0 && s[len(s)-1] == '=' {
		s = s[:len(s)-1]
	}
	return s
}
