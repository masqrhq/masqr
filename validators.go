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
	"math/big"
)

// luhn validates a Luhn-protected number (e.g., payment card PAN).
// Accepts the original textual match — strips non-digits internally.
func luhn(s string) bool {
	digits := make([]int, 0, len(s))
	for _, r := range s {
		if r >= '0' && r <= '9' {
			digits = append(digits, int(r-'0'))
		}
	}
	if len(digits) < 13 || len(digits) > 19 {
		return false
	}
	parity := len(digits) % 2
	sum := 0
	for i, d := range digits {
		if i%2 == parity {
			d *= 2
			if d > 9 {
				d -= 9
			}
		}
		sum += d
	}
	return sum%10 == 0
}

// cardPAN guards the credit-card rule. A bare Luhn check has a 10% false
// positive rate on random 14-digit runs, and log filenames like
// `masqr-20260527-212415.log` happen to satisfy it. Reject 14-digit runs
// that parse as a sane YYYYMMDDHHMMSS timestamp first — no real card
// number with a 19xx/20xx prefix is also a valid datetime, so this loses
// no true positives in practice.
func cardPAN(s string) bool {
	digits := make([]byte, 0, len(s))
	for _, r := range s {
		if r >= '0' && r <= '9' {
			digits = append(digits, byte(r))
		}
	}
	if len(digits) == 14 && looksLikeYYYYMMDDHHMMSS(digits) {
		return false
	}
	return luhn(s)
}

// looksLikeYYYYMMDDHHMMSS reports whether a 14-digit run decodes as a
// plausible local timestamp. The year window is intentionally wide
// (1900–2099) to cover both retrospective log files and dates emitted by
// scripts using the local clock.
func looksLikeYYYYMMDDHHMMSS(d []byte) bool {
	if len(d) != 14 {
		return false
	}
	n := func(i, j int) int {
		v := 0
		for k := i; k < j; k++ {
			v = v*10 + int(d[k]-'0')
		}
		return v
	}
	year := n(0, 4)
	month := n(4, 6)
	day := n(6, 8)
	hour := n(8, 10)
	minute := n(10, 12)
	second := n(12, 14)
	return year >= 1900 && year <= 2099 &&
		month >= 1 && month <= 12 &&
		day >= 1 && day <= 31 &&
		hour <= 23 && minute <= 59 && second <= 59
}

// ibanMod97 validates an IBAN via the ISO-13616 Mod-97-10 algorithm.
func ibanMod97(iban string) bool {
	s := stripSpaces(iban)
	if len(s) < 5 || len(s) > 34 {
		return false
	}
	// Move first 4 chars to end.
	rearranged := s[4:] + s[:4]
	// Replace letters: A=10, B=11, … Z=35; then mod 97.
	n := new(big.Int)
	chunk := new(big.Int)
	ninetySeven := big.NewInt(97)
	for _, r := range rearranged {
		switch {
		case r >= '0' && r <= '9':
			n.Mul(n, big.NewInt(10))
			n.Add(n, chunk.SetInt64(int64(r-'0')))
		case r >= 'A' && r <= 'Z':
			n.Mul(n, big.NewInt(100))
			n.Add(n, chunk.SetInt64(int64(r-'A'+10)))
		default:
			return false
		}
		n.Mod(n, ninetySeven)
	}
	return n.Int64() == 1
}

// ahvCheck validates a Swiss AHV/AVS number (756.XXXX.XXXX.XX, 13 digits)
// using the EAN-13 Mod-10 algorithm.
func ahvCheck(s string) bool {
	digits := make([]int, 0, 13)
	for _, r := range s {
		if r >= '0' && r <= '9' {
			digits = append(digits, int(r-'0'))
		}
	}
	if len(digits) != 13 || digits[0] != 7 || digits[1] != 5 || digits[2] != 6 {
		return false
	}
	sum := 0
	for i := 0; i < 12; i++ {
		w := 1
		if i%2 == 1 {
			w = 3
		}
		sum += digits[i] * w
	}
	check := (10 - sum%10) % 10
	return check == digits[12]
}

// uidCheck validates a Swiss UID (CHE-XXX.XXX.XXX) check digit using the
// official weighted-Mod-11 algorithm.
func uidCheck(s string) bool {
	digits := make([]int, 0, 9)
	for _, r := range s {
		if r >= '0' && r <= '9' {
			digits = append(digits, int(r-'0'))
		}
	}
	if len(digits) != 9 {
		return false
	}
	weights := []int{5, 4, 3, 2, 7, 6, 5, 4}
	sum := 0
	for i := 0; i < 8; i++ {
		sum += digits[i] * weights[i]
	}
	check := 11 - (sum % 11)
	switch check {
	case 10:
		return false
	case 11:
		check = 0
	}
	return check == digits[8]
}

// trimJSONEscapePrefix is a Refine hook for rules whose pattern uses `\b` to
// anchor the local-part start. If the matched span is immediately preceded by
// a backslash AND its first byte is one of the common JSON escape letters
// (n, r, t, b, f, v), the leading byte is an artifact of an escape sequence
// like `\n` appearing in raw, unparsed JSON bodies. Shift past it.
func trimJSONEscapePrefix(body []byte, start, end int) (int, int, bool) {
	if start > 0 && start+1 < end && body[start-1] == '\\' && isJSONEscapeLetter(body[start]) {
		start++
	}
	// Sanity-check that we still have at least one local-part char before `@`.
	at := -1
	for i := start; i < end; i++ {
		if body[i] == '@' {
			at = i
			break
		}
	}
	if at <= start {
		return 0, 0, false
	}
	return start, end, true
}

func isJSONEscapeLetter(b byte) bool {
	switch b {
	case 'n', 'r', 't', 'b', 'f', 'v':
		return true
	}
	return false
}

// emailContextRefine extends trimJSONEscapePrefix with two CLI-metadata
// exclusions. LLM CLIs (Claude Code et al.) auto-inject the signed-in
// user's email into the system prompt under a "# userEmail" / "The
// user's email address is …" block, and they embed `noreply@…`
// addresses in Co-Authored-By scaffolding. Both show up on every turn
// and are not user-typed prompt content — flagging them blocks the
// conversation for no security gain. A real "please email me at …" the
// user typed lacks both signals and still trips the rule.
func emailContextRefine(body []byte, start, end int) (int, int, bool) {
	start, end, ok := trimJSONEscapePrefix(body, start, end)
	if !ok {
		return 0, 0, false
	}
	if hasNoReplyLocalPart(body[start:end]) {
		return 0, 0, false
	}
	if isVibeEmail(body[start:end]) {
		return 0, 0, false
	}
	if hasUserEmailContextMarker(body, start) {
		return 0, 0, false
	}
	return start, end, true
}

// hasNoReplyLocalPart returns true if the matched email's local part is
// "noreply" (case-insensitive). Template addresses, never user-typed.
func hasNoReplyLocalPart(span []byte) bool {
	const prefix = "noreply@"
	if len(span) < len(prefix) {
		return false
	}
	return bytes.EqualFold(span[:len(prefix)], []byte(prefix))
}

// isVibeEmail returns true if the matched email is "vibe@mistral.ai" (case-insensitive).
// CLI-metadata/agent address, never user-typed.
func isVibeEmail(span []byte) bool {
	return bytes.EqualFold(span, []byte("vibe@mistral.ai"))
}

// userEmailContextWindow is how far back from the match we look for a
// CLI-metadata marker. 128 bytes is enough to span the "# userEmail\n
// The user's email address is …" Claude Code block while ignoring
// unrelated content further upstream.
const userEmailContextWindow = 128

// userEmailContextMarkers are case-insensitive substrings that signal
// the email is part of the CLI's metadata-about-the-user, not a leak.
// Keep them tightly scoped so a user typing the same phrase in their
// own prompt as part of a real request still gets flagged.
var userEmailContextMarkers = [][]byte{
	[]byte("useremail"),       // Claude Code: "# userEmail\n"
	[]byte("user's email"),    // Claude Code prose form
	[]byte("user email addr"), // Conservative trailing-noun form
}

func hasUserEmailContextMarker(body []byte, start int) bool {
	lo := start - userEmailContextWindow
	if lo < 0 {
		lo = 0
	}
	pre := bytes.ToLower(body[lo:start])
	for _, m := range userEmailContextMarkers {
		if bytes.Contains(pre, m) {
			return true
		}
	}
	return false
}

func stripSpaces(s string) string {
	out := make([]byte, 0, len(s))
	for i := 0; i < len(s); i++ {
		if s[i] != ' ' && s[i] != '\t' {
			out = append(out, s[i])
		}
	}
	return string(out)
}
