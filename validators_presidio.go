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

// Checksum / format validators for Presidio-derived rules.
// Patterns derive from Microsoft Presidio's predefined_recognizers; the
// algorithms here are clean-room transcriptions of the published checksums
// (no Presidio code is imported).
//
// Each validator accepts the raw matched snippet (digits + separators) and
// returns true if the snippet is a structurally valid identifier of the
// expected type. Validators short-circuit on length / charset mismatch so
// they are cheap to call from the digit-cluster classifier.

import (
	"strconv"
	"strings"
)

// digitsOf returns the ASCII digit characters of s. Whitespace, punctuation,
// and letters are stripped. The result is suitable as input to the integer
// checksum routines below.
func digitsOf(s string) string {
	b := make([]byte, 0, len(s))
	for i := 0; i < len(s); i++ {
		c := s[i]
		if c >= '0' && c <= '9' {
			b = append(b, c)
		}
	}
	return string(b)
}

// allSame reports whether every byte of s is identical to s[0]. Used to
// reject degenerate identifiers like 000000000 / 111111111 which pass many
// checksums by coincidence.
func allSame(s string) bool {
	if len(s) < 2 {
		return false
	}
	for i := 1; i < len(s); i++ {
		if s[i] != s[0] {
			return false
		}
	}
	return true
}

// isPalindrome reports whether s reads the same forwards and backwards.
// Presidio rejects palindromic Aadhaar numbers as obvious synthetic samples.
func isPalindrome(s string) bool {
	for i, j := 0, len(s)-1; i < j; i, j = i+1, j-1 {
		if s[i] != s[j] {
			return false
		}
	}
	return true
}

// ─── Mod-10 / Luhn family ────────────────────────────────────────────────

// luhnDigits applies the Luhn check to a digit-only string (assumes len ≥ 2).
// Identical algorithm to luhn() in validators.go but takes a pre-stripped
// input so the digit-cluster classifier can avoid re-stripping.
func luhnDigits(s string) bool {
	if len(s) < 2 {
		return false
	}
	parity := len(s) % 2
	sum := 0
	for i := 0; i < len(s); i++ {
		d := int(s[i] - '0')
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

// usABARouting validates a US ABA routing number (9 digits, weighted Mod-10).
// Algorithm: 3·d0 + 7·d1 + 1·d2 + 3·d3 + 7·d4 + 1·d5 + 3·d6 + 7·d7 + 1·d8 ≡ 0 (mod 10).
// Leading digit must be one of {0,1,2,3,6,7,8} per Federal Reserve allocation.
func usABARouting(s string) bool {
	if len(s) != 9 {
		return false
	}
	switch s[0] {
	case '0', '1', '2', '3', '6', '7', '8':
	default:
		return false
	}
	if allSame(s) {
		return false
	}
	weights := [9]int{3, 7, 1, 3, 7, 1, 3, 7, 1}
	sum := 0
	for i := 0; i < 9; i++ {
		sum += int(s[i]-'0') * weights[i]
	}
	return sum%10 == 0
}

// usSSN validates a US Social Security Number (9 digits) by structural
// rules. The SSA does not publish a checksum, so we apply the disallowed
// ranges and famous-fake list from Presidio's invalidate_result.
func usSSN(s string) bool {
	if len(s) != 9 {
		return false
	}
	if allSame(s) {
		return false
	}
	area, group, serial := s[0:3], s[3:5], s[5:9]
	if area == "000" || area == "666" || area[0] == '9' {
		return false
	}
	if group == "00" || serial == "0000" {
		return false
	}
	for _, fake := range []string{"123456789", "987654320", "078051120", "219099999"} {
		if s == fake {
			return false
		}
	}
	return true
}

// usITIN validates a US Individual Taxpayer ID (9 digits, area 9XX, group
// 50-65 / 70-88 / 90-92 / 94-99 per IRS Pub 1915).
func usITIN(s string) bool {
	if len(s) != 9 || s[0] != '9' {
		return false
	}
	group, err := strconv.Atoi(s[3:5])
	if err != nil {
		return false
	}
	switch {
	case group >= 50 && group <= 65:
	case group >= 70 && group <= 88:
	case group >= 90 && group <= 92:
	case group >= 94 && group <= 99:
	default:
		return false
	}
	if s[5:] == "0000" {
		return false
	}
	return true
}

// usNPI validates a 10-digit US National Provider Identifier using the
// CMS "80840" Luhn prefix check.
func usNPI(s string) bool {
	if len(s) != 10 {
		return false
	}
	if allSame(s[:9]) { // degenerate
		return false
	}
	return luhnDigits("80840" + s)
}

// caSIN validates a Canadian Social Insurance Number (9 digits, Luhn,
// leading digit 1-7 or 9 per ESDC allocation).
func caSIN(s string) bool {
	if len(s) != 9 {
		return false
	}
	if s[0] == '0' || s[0] == '8' {
		return false
	}
	if allSame(s) {
		return false
	}
	return luhnDigits(s)
}

// auTFN validates an Australian Tax File Number (9 digits, weighted Mod-11
// per ATO).
func auTFN(s string) bool {
	if len(s) != 9 {
		return false
	}
	weights := [9]int{1, 4, 3, 7, 5, 8, 6, 9, 10}
	sum := 0
	for i := 0; i < 9; i++ {
		sum += int(s[i]-'0') * weights[i]
	}
	return sum%11 == 0
}

// auACN validates an Australian Company Number (9 digits, weighted Mod-10
// per ASIC).
func auACN(s string) bool {
	if len(s) != 9 {
		return false
	}
	weights := [8]int{8, 7, 6, 5, 4, 3, 2, 1}
	sum := 0
	for i := 0; i < 8; i++ {
		sum += int(s[i]-'0') * weights[i]
	}
	complement := (10 - sum%10) % 10
	return complement == int(s[8]-'0')
}

// auABN validates an Australian Business Number (11 digits, weighted Mod-89
// per ATO, with the first-digit-minus-1 transform).
func auABN(s string) bool {
	if len(s) != 11 {
		return false
	}
	weights := [11]int{10, 1, 3, 5, 7, 9, 11, 13, 15, 17, 19}
	first := int(s[0] - '0')
	if first == 0 {
		first = 9
	} else {
		first--
	}
	sum := first * weights[0]
	for i := 1; i < 11; i++ {
		sum += int(s[i]-'0') * weights[i]
	}
	return sum%89 == 0
}

// auMedicare validates an Australian Medicare card number (10 digits; first
// digit 2-6; positions 1-8 weighted Mod-10; digit 9 = check; digit 10 =
// issue number, not checksummed).
func auMedicare(s string) bool {
	if len(s) != 10 {
		return false
	}
	if s[0] < '2' || s[0] > '6' {
		return false
	}
	weights := [8]int{1, 3, 7, 9, 1, 3, 7, 9}
	sum := 0
	for i := 0; i < 8; i++ {
		sum += int(s[i]-'0') * weights[i]
	}
	return sum%10 == int(s[8]-'0')
}

// ukNHS validates a 10-digit UK NHS number using the published Mod-11 check
// with weights [10,9,8,7,6,5,4,3,2] and check digit at position 9.
func ukNHS(s string) bool {
	if len(s) != 10 {
		return false
	}
	if allSame(s) {
		return false
	}
	sum := 0
	for i := 0; i < 9; i++ {
		sum += int(s[i]-'0') * (10 - i)
	}
	check := 11 - sum%11
	switch check {
	case 11:
		check = 0
	case 10:
		return false
	}
	return check == int(s[9]-'0')
}

// plPESEL validates a Polish PESEL (11 digits) by embedded-date sanity +
// weighted Mod-10 check.
func plPESEL(s string) bool {
	if len(s) != 11 {
		return false
	}
	// Embedded-date sanity. The month encodes century:
	//   01-12 → 1900s; 21-32 → 2000s; 81-92 → 1800s; 41-52 → 2100s; 61-72 → 2200s.
	month, err := strconv.Atoi(s[2:4])
	if err != nil {
		return false
	}
	mm := 0
	switch {
	case month >= 1 && month <= 12, month >= 21 && month <= 32,
		month >= 41 && month <= 52, month >= 61 && month <= 72,
		month >= 81 && month <= 92:
		mm = ((month - 1) % 20) + 1
	default:
		return false
	}
	day, err := strconv.Atoi(s[4:6])
	if err != nil || day < 1 || day > 31 {
		return false
	}
	if (mm == 4 || mm == 6 || mm == 9 || mm == 11) && day > 30 {
		return false
	}
	if mm == 2 && day > 29 {
		return false
	}
	weights := [10]int{1, 3, 7, 9, 1, 3, 7, 9, 1, 3}
	sum := 0
	for i := 0; i < 10; i++ {
		sum += int(s[i]-'0') * weights[i]
	}
	check := (10 - sum%10) % 10
	return check == int(s[10]-'0')
}

// krRRN validates a Korean Resident Registration Number issued before
// October 2020 (13 digits: YYMMDD-NXXXXXX) using the published Mod-11 check.
// Numbers issued after the 2020 reform have no checksum and will return false.
func krRRN(s string) bool {
	if len(s) != 13 {
		return false
	}
	month, _ := strconv.Atoi(s[2:4])
	if month < 1 || month > 12 {
		return false
	}
	day, _ := strconv.Atoi(s[4:6])
	if day < 1 || day > 31 {
		return false
	}
	if s[6] < '1' || s[6] > '4' {
		return false
	}
	weights := [12]int{2, 3, 4, 5, 6, 7, 8, 9, 2, 3, 4, 5}
	sum := 0
	for i := 0; i < 12; i++ {
		sum += int(s[i]-'0') * weights[i]
	}
	check := (11 - sum%11) % 10
	return check == int(s[12]-'0')
}

// trTCKN validates a Turkish national ID (11 digits) using the NVI two-digit
// checksum: d10 = (7·odd − even) mod 10; d11 = sum(d1..d10) mod 10.
func trTCKN(s string) bool {
	if len(s) != 11 || s[0] == '0' {
		return false
	}
	d := [11]int{}
	for i := 0; i < 11; i++ {
		d[i] = int(s[i] - '0')
	}
	odd := d[0] + d[2] + d[4] + d[6] + d[8]
	even := d[1] + d[3] + d[5] + d[7]
	if (odd*7-even)%10 != ((d[9]%10)+10)%10 {
		return false
	}
	sumFirst10 := 0
	for i := 0; i < 10; i++ {
		sumFirst10 += d[i]
	}
	return sumFirst10%10 == d[10]
}

// thTNIN validates a Thai national ID (13 digits) using the Department of
// Provincial Administration Mod-11 check.
func thTNIN(s string) bool {
	if len(s) != 13 || s[0] == '0' {
		return false
	}
	sum := 0
	for i := 0; i < 12; i++ {
		sum += int(s[i]-'0') * (13 - i)
	}
	x := sum % 11
	want := 0
	if x <= 1 {
		want = 1 - x
	} else {
		want = 11 - x
	}
	return want == int(s[12]-'0')
}

// itVAT validates an Italian Partita IVA (11 digits) using the
// odd/even alternating doubling rule (Luhn variant).
func itVAT(s string) bool {
	if len(s) != 11 || s == "00000000000" {
		return false
	}
	x, y := 0, 0
	for i := 0; i < 5; i++ {
		x += int(s[2*i] - '0')
		ty := int(s[2*i+1]-'0') * 2
		if ty > 9 {
			ty -= 9
		}
		y += ty
	}
	check := (10 - (x+y)%10) % 10
	return check == int(s[10]-'0')
}

// deTaxID validates the German Steueridentifikationsnummer (11 digits)
// using ISO 7064 Mod 11,10 with the post-2016 "no digit appears more than
// 3 times in positions 0..9" rule.
func deTaxID(s string) bool {
	if len(s) != 11 || s[0] == '0' {
		return false
	}
	var freq [10]int
	for i := 0; i < 10; i++ {
		freq[s[i]-'0']++
		if freq[s[i]-'0'] > 3 {
			return false
		}
	}
	product := 10
	for i := 0; i < 10; i++ {
		total := (int(s[i]-'0') + product) % 10
		if total == 0 {
			total = 10
		}
		product = (total * 2) % 11
	}
	check := 11 - product
	if check == 10 {
		check = 0
	}
	return check == int(s[10]-'0')
}

// inAadhaar validates a 12-digit Indian Aadhaar number using the Verhoeff
// scheme with Presidio's extra guards: leading digit ≥ 2, not a palindrome.
func inAadhaar(s string) bool {
	if len(s) != 12 || s[0] < '2' {
		return false
	}
	if isPalindrome(s) {
		return false
	}
	return verhoeff(s)
}

// verhoeffD is the Verhoeff multiplication table.
var verhoeffD = [10][10]int{
	{0, 1, 2, 3, 4, 5, 6, 7, 8, 9},
	{1, 2, 3, 4, 0, 6, 7, 8, 9, 5},
	{2, 3, 4, 0, 1, 7, 8, 9, 5, 6},
	{3, 4, 0, 1, 2, 8, 9, 5, 6, 7},
	{4, 0, 1, 2, 3, 9, 5, 6, 7, 8},
	{5, 9, 8, 7, 6, 0, 4, 3, 2, 1},
	{6, 5, 9, 8, 7, 1, 0, 4, 3, 2},
	{7, 6, 5, 9, 8, 2, 1, 0, 4, 3},
	{8, 7, 6, 5, 9, 3, 2, 1, 0, 4},
	{9, 8, 7, 6, 5, 4, 3, 2, 1, 0},
}

// verhoeffP is the Verhoeff permutation table.
var verhoeffP = [8][10]int{
	{0, 1, 2, 3, 4, 5, 6, 7, 8, 9},
	{1, 5, 7, 6, 2, 8, 3, 0, 9, 4},
	{5, 8, 0, 3, 7, 9, 6, 1, 4, 2},
	{8, 9, 1, 6, 0, 4, 3, 5, 2, 7},
	{9, 4, 5, 3, 1, 2, 6, 8, 7, 0},
	{4, 2, 8, 6, 5, 7, 3, 9, 0, 1},
	{2, 7, 9, 3, 8, 0, 6, 4, 1, 5},
	{7, 0, 4, 6, 9, 1, 3, 2, 5, 8},
}

// verhoeff runs the Verhoeff checksum over a digit-only string.
func verhoeff(s string) bool {
	c := 0
	for i := len(s) - 1; i >= 0; i-- {
		c = verhoeffD[c][verhoeffP[(len(s)-1-i)%8][int(s[i]-'0')]]
	}
	return c == 0
}

// sePersonnummer validates a Swedish Personnummer in 10-digit (YYMMDD-XXXX)
// or 12-digit (YYYYMMDDXXXX) form by birthdate sanity + Luhn on the
// trailing 10 digits.
func sePersonnummer(s string) bool {
	switch len(s) {
	case 10:
	case 12:
		s = s[2:]
	default:
		return false
	}
	month, _ := strconv.Atoi(s[2:4])
	day, _ := strconv.Atoi(s[4:6])
	// Samordningsnummer encodes day+60 for coordinated identification.
	if day > 60 && day-60 >= 1 && day-60 <= 31 {
		day -= 60
	}
	if month < 1 || month > 12 || day < 1 || day > 31 {
		return false
	}
	return luhnDigits(s)
}

// seOrgnummer validates a 10-digit Swedish Organisationsnummer by Luhn,
// rejecting personnummer-shaped values (third pair < 20).
func seOrgnummer(s string) bool {
	if len(s) != 10 {
		return false
	}
	if s[2] < '2' { // Organisationsnummer third-pair ≥ 20
		return false
	}
	return luhnDigits(s)
}

// ─── ASCII helpers for letter-prefix IDs ──────────────────────────────────

// esNIFLetter returns the expected DNI/NIF check letter for the given 8-digit
// numeric portion. The mapping is fixed by Real Decreto 338/1990.
func esNIFLetter(eight string) byte {
	table := "TRWAGMYFPDXBNJZSQVHLCKE"
	n, err := strconv.Atoi(eight)
	if err != nil {
		return 0
	}
	return table[n%23]
}

// esNIF validates a Spanish DNI/NIF (8 digits + letter). Accepts an
// optional leading zero (Presidio's pattern allows 7-or-8 digit numeric
// portion). The check letter is derived by mod-23 lookup.
func esNIF(s string) bool {
	s = strings.ToUpper(strings.ReplaceAll(s, "-", ""))
	if len(s) < 8 || len(s) > 9 {
		return false
	}
	letter := s[len(s)-1]
	if letter < 'A' || letter > 'Z' {
		return false
	}
	num := s[:len(s)-1]
	if len(num) == 7 {
		num = "0" + num
	}
	for i := 0; i < len(num); i++ {
		if num[i] < '0' || num[i] > '9' {
			return false
		}
	}
	return esNIFLetter(num) == letter
}

// esNIE validates a Spanish NIE (X|Y|Z + 7 digits + letter) by mapping the
// leading letter to a digit and reusing the NIF check.
func esNIE(s string) bool {
	s = strings.ToUpper(strings.ReplaceAll(s, "-", ""))
	if len(s) != 9 {
		return false
	}
	var prefix byte
	switch s[0] {
	case 'X':
		prefix = '0'
	case 'Y':
		prefix = '1'
	case 'Z':
		prefix = '2'
	default:
		return false
	}
	num := string(prefix) + s[1:8]
	letter := s[8]
	for i := 0; i < len(num); i++ {
		if num[i] < '0' || num[i] > '9' {
			return false
		}
	}
	return esNIFLetter(num) == letter
}

// sgNRICFIN validates a Singapore NRIC (S/T = citizen, F/G = foreigner,
// M = post-2022 foreigner) using the IRAS check-letter algorithm.
func sgNRICFIN(s string) bool {
	s = strings.ToUpper(s)
	if len(s) != 9 {
		return false
	}
	prefix := s[0]
	switch prefix {
	case 'S', 'T', 'F', 'G', 'M':
	default:
		return false
	}
	for i := 1; i < 8; i++ {
		if s[i] < '0' || s[i] > '9' {
			return false
		}
	}
	weights := [7]int{2, 7, 6, 5, 4, 3, 2}
	sum := 0
	for i := 0; i < 7; i++ {
		sum += int(s[i+1]-'0') * weights[i]
	}
	if prefix == 'T' || prefix == 'G' {
		sum += 4
	}
	if prefix == 'M' {
		sum += 3
	}
	rem := sum % 11
	var table string
	switch prefix {
	case 'S', 'T':
		table = "JZIHGFEDCBA"
	case 'F', 'G':
		table = "XWUTRQPNMLK"
	case 'M':
		table = "KLJNPQRTUWX"
	}
	return s[8] == table[rem]
}

// fiPIC validates a Finnish Henkilötunnus (DDMMYY+separator+NNN+check).
// The separator encodes century; the check character comes from a 31-entry
// lookup of (date + individual) mod 31.
func fiPIC(s string) bool {
	if len(s) != 11 {
		return false
	}
	sep := s[6]
	switch sep {
	case '+', '-', 'A', 'B', 'C', 'D', 'E', 'F', 'Y', 'X', 'W', 'V', 'U':
	default:
		return false
	}
	for i := 0; i < 6; i++ {
		if s[i] < '0' || s[i] > '9' {
			return false
		}
	}
	for i := 7; i < 10; i++ {
		if s[i] < '0' || s[i] > '9' {
			return false
		}
	}
	day, _ := strconv.Atoi(s[0:2])
	month, _ := strconv.Atoi(s[2:4])
	if month < 1 || month > 12 || day < 1 || day > 31 {
		return false
	}
	n, _ := strconv.Atoi(s[0:6] + s[7:10])
	table := "0123456789ABCDEFHJKLMNPRSTUVWXY"
	return table[n%31] == s[10]
}

// deaNumber validates a US DEA Certificate Number (2 letters + 7 digits).
// Check digit at position 8 = (d1+d3+d5) + 2·(d2+d4+d6), low-order digit.
func deaNumber(s string) bool {
	if len(s) != 9 {
		return false
	}
	u := strings.ToUpper(s)
	if u[0] < 'A' || u[0] > 'Z' || u[1] < 'A' || u[1] > 'Z' {
		return false
	}
	for i := 2; i < 9; i++ {
		if u[i] < '0' || u[i] > '9' {
			return false
		}
	}
	odd := int(u[2]-'0') + int(u[4]-'0') + int(u[6]-'0')
	even := int(u[3]-'0') + int(u[5]-'0') + int(u[7]-'0')
	return (odd+2*even)%10 == int(u[8]-'0')
}
