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
	"errors"
	"math"
	"regexp"
)

const (
	// 24 chars catches even a single AWS access key ID encoded alone
	// (`echo $AWS_KEY_ID | base64` → 28 chars). Trade-off: more long-UUID /
	// hash false positives, mitigated by the entropy floor below.
	minBase64Length = 24
	// Tiered entropy floor: short base64 of structured content (like a 20-byte
	// AWS key encoded alone) naturally peaks around 3.8-4.0 bits/byte because
	// the alphabet usage is limited at that length. Long random base64 ≥ 5.0.
	minEntropyShort = 3.7 // for 24..31 chars
	minEntropyLong  = 4.5 // for ≥ 32 chars
	// Recursion budget: 0 disables decode-rescan; N decodes up to N
	// times. Real obfuscation tends to be shallow (a secret base64'd
	// inside JSON inside another base64), but we lift the cap from 1
	// to 5 so masqr can peel multiple layers of wrapping without
	// gluing every adversarial input into one giant scan.
	//
	// The total work stays bounded because (a) every recursion call
	// reapplies the maxScanBytes ceiling, (b) the high-entropy /
	// printability / identifier filters reject the vast majority of
	// candidates before we descend, and (c) the depth cap is finite.
	maxScanDepth = 5
)

// isHighEntropyBase64 applies the tiered entropy floor, then rejects runs
// that look like Unix paths or programmer-style identifiers. `/` is a
// valid base64 char so slash-heavy runs need a path-shape filter; long
// camelCase / kebab-case identifiers (think `dangerouslyDisableSandbox`)
// can clear the lower entropy floor when they really shouldn't. Real
// base64 of binary data nearly always contains digits or `+`.
func isHighEntropyBase64(s string) bool {
	e := shannonEntropy([]byte(s))
	if len(s) >= 32 {
		if e < minEntropyLong {
			return false
		}
	} else if e < minEntropyShort {
		return false
	}
	if looksLikePath(s) {
		return false
	}
	return !looksLikeIdentifier(s)
}

// looksLikePath rejects slash-separated runs that contain only letters and
// slashes. Random base64 of 24+ bytes has ≥1 digit with probability ~0.99
// (10/64 per char), so the absence of digits AND `+` together with ≥2
// slashes is a strong path signal.
func looksLikePath(s string) bool {
	var slashes, digitsOrPlus int
	for i := 0; i < len(s); i++ {
		c := s[i]
		switch {
		case c == '/':
			slashes++
		case (c >= '0' && c <= '9') || c == '+':
			digitsOrPlus++
		}
	}
	return slashes >= 2 && digitsOrPlus == 0
}

// looksLikeIdentifier rejects programmer-style identifiers — camelCase
// (`dangerouslyDisableSandbox`), snake_case, and kebab-case names — that
// happen to sit in the base64 alphabet and clear the entropy floor.
// Heuristic: only letters and `_`/`-` (no digits, no `+`, no `/`) plus
// at least two case transitions or word breaks. Real base64 has ≥1
// digit with very high probability at these lengths; identifiers
// almost never do.
func looksLikeIdentifier(s string) bool {
	var letters, digits, plus, slash, underscores int
	var caseTransitions int
	prevWasLower := false
	prevWasLetter := false
	for i := 0; i < len(s); i++ {
		c := s[i]
		switch {
		case c >= 'a' && c <= 'z':
			if prevWasLetter && !prevWasLower {
				caseTransitions++
			}
			prevWasLower = true
			prevWasLetter = true
			letters++
		case c >= 'A' && c <= 'Z':
			if prevWasLetter && prevWasLower {
				caseTransitions++
			}
			prevWasLower = false
			prevWasLetter = true
			letters++
		case c >= '0' && c <= '9':
			digits++
			prevWasLetter = false
		case c == '+':
			plus++
			prevWasLetter = false
		case c == '/':
			slash++
			prevWasLetter = false
		case c == '_' || c == '-':
			underscores++
			prevWasLetter = false
		}
	}
	if digits > 0 || plus > 0 || slash > 0 {
		return false // real base64 features → not an identifier
	}
	// camelCase: ≥2 case transitions in a letter-only run.
	if caseTransitions >= 2 && letters >= 10 {
		return true
	}
	// snake_case / kebab-case: ≥2 separators in a letter-only run.
	if underscores >= 2 && letters >= 10 {
		return true
	}
	return false
}

// base64CandidatePattern catches runs of standard base64 alphabet ≥ minBase64Length
// chars, with optional `=` padding. URL-safe variants (`-_`) decode via the
// fallback encodings in tryDecodeBase64 — the pattern above conservatively only
// finds standard-alphabet candidates, which already covers Anthropic, Azure,
// AWS, GCP, and most other cloud token formats.
var base64CandidatePattern = regexp.MustCompile(`[A-Za-z0-9+/]{24,}={0,2}`)

type base64Hit struct {
	text   string
	offset int
}

// findBase64Candidates returns every span that looks structurally like a
// base64 blob. We deliberately do NOT entropy-filter here: the entropy
// floor is the right gate for *flagging* a blob as a likely secret (the
// `generic-base64-blob` rule applies it), but it's the wrong gate for
// *recursive decoding*. Intermediate layers in `b64(b64(secret))` chains
// often dip below the floor because they're encodings of structured
// ASCII rather than random bytes, and skipping them here would stop us
// from ever peeling the wrapper. The remaining safeguards — pattern
// shape, successful `tryDecodeBase64`, decoded-printable check, and
// maxScanDepth — keep adversarial input bounded.
func findBase64Candidates(body []byte) []base64Hit {
	locs := base64CandidatePattern.FindAllIndex(body, -1)
	if len(locs) == 0 {
		return nil
	}
	out := make([]base64Hit, 0, len(locs))
	for _, l := range locs {
		blob := body[l[0]:l[1]]
		out = append(out, base64Hit{text: string(blob), offset: l[0]})
	}
	return out
}

// shannonEntropy returns the byte-level Shannon entropy in bits/byte.
// Truly random base64 ≈ 6.0; structured base64 of JSON ≈ 4.5-5.0;
// English prose ≈ 3.0-4.0; repetitive text ≈ 1.0-2.0.
func shannonEntropy(data []byte) float64 {
	if len(data) == 0 {
		return 0
	}
	var freq [256]int
	for _, b := range data {
		freq[b]++
	}
	n := float64(len(data))
	var h float64
	for _, c := range freq {
		if c == 0 {
			continue
		}
		p := float64(c) / n
		h -= p * math.Log2(p)
	}
	return h
}

// tryDecodeBase64 attempts every base64 dialect Go's stdlib supports —
// standard/URL-safe × padded/unpadded.
func tryDecodeBase64(s string) ([]byte, error) {
	for _, enc := range []*base64.Encoding{
		base64.StdEncoding,
		base64.RawStdEncoding,
		base64.URLEncoding,
		base64.RawURLEncoding,
	} {
		if d, err := enc.DecodeString(s); err == nil {
			return d, nil
		}
	}
	return nil, errors.New("not valid base64")
}

// isMostlyPrintable rejects decoded blobs that look like binary/garbage — those
// are usually image bytes, compressed data, or a false-positive base64 match.
// A leaked credential decoded out of base64 is almost always ASCII.
func isMostlyPrintable(data []byte) bool {
	if len(data) == 0 {
		return false
	}
	printable := 0
	for _, b := range data {
		if (b >= 0x20 && b <= 0x7e) || b == '\n' || b == '\r' || b == '\t' {
			printable++
		}
	}
	return float64(printable)/float64(len(data)) >= 0.85
}
