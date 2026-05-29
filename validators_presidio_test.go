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

import "testing"

// Each table below pairs a known-valid identifier with at least one
// structurally-similar invalid one. Valid vectors are either (a) the
// agency's own published example or (b) computed by following the
// Presidio reference algorithm. Invalid vectors flip the check digit
// by one or violate a structural rule (zero area, wrong prefix, etc.).

func TestUSSSN(t *testing.T) {
	cases := []struct {
		in   string
		want bool
	}{
		{"001010001", true},  // valid form (NH area)
		{"219123456", true},  // valid form
		{"123456789", false}, // famous fake
		{"000123456", false}, // area 000 forbidden
		{"666123456", false}, // area 666 forbidden
		{"912345678", false}, // 9xx area is ITIN territory
		{"111001234", false}, // group 00 forbidden
		{"123450000", false}, // serial 0000 forbidden
		{"078051120", false}, // famous fake
		{"111111111", false}, // degenerate
	}
	for _, c := range cases {
		if got := usSSN(c.in); got != c.want {
			t.Errorf("usSSN(%q) = %v, want %v", c.in, got, c.want)
		}
	}
}

func TestUSITIN(t *testing.T) {
	cases := []struct {
		in   string
		want bool
	}{
		{"912501234", true},  // group 50 ∈ valid range
		{"912881234", true},  // group 88
		{"912991234", true},  // group 99
		{"912491234", false}, // group 49 not in ITIN range
		{"812501234", false}, // leading 9 required
		{"912500000", false}, // serial 0000
	}
	for _, c := range cases {
		if got := usITIN(c.in); got != c.want {
			t.Errorf("usITIN(%q) = %v, want %v", c.in, got, c.want)
		}
	}
}

func TestUSNPI(t *testing.T) {
	cases := []struct {
		in   string
		want bool
	}{
		{"1234567893", true},  // computed from 80840 + 123456789 Luhn
		{"1234567894", false}, // off-by-one check
		{"1111111111", false}, // degenerate body
	}
	for _, c := range cases {
		if got := usNPI(c.in); got != c.want {
			t.Errorf("usNPI(%q) = %v, want %v", c.in, got, c.want)
		}
	}
}

func TestUSABARouting(t *testing.T) {
	cases := []struct {
		in   string
		want bool
	}{
		{"100000007", true},  // computed Mod-10
		{"011000015", true},  // Federal Reserve Boston (public)
		{"100000008", false}, // off-by-one
		{"400000007", false}, // leading 4 not in allocation
		{"000000000", false}, // degenerate
	}
	for _, c := range cases {
		if got := usABARouting(c.in); got != c.want {
			t.Errorf("usABARouting(%q) = %v, want %v", c.in, got, c.want)
		}
	}
}

func TestCASIN(t *testing.T) {
	cases := []struct {
		in   string
		want bool
	}{
		{"123456782", true},  // computed Luhn
		{"123456789", false}, // off-by-one
		{"800000007", false}, // leading 8 not allocated
		{"000000000", false}, // degenerate
	}
	for _, c := range cases {
		if got := caSIN(c.in); got != c.want {
			t.Errorf("caSIN(%q) = %v, want %v", c.in, got, c.want)
		}
	}
}

func TestAUTFN(t *testing.T) {
	cases := []struct {
		in   string
		want bool
	}{
		{"123456782", true},  // ATO test vector
		{"100000001", true},  // computed Mod-11
		{"123456783", false}, // off-by-one
	}
	for _, c := range cases {
		if got := auTFN(c.in); got != c.want {
			t.Errorf("auTFN(%q) = %v, want %v", c.in, got, c.want)
		}
	}
}

func TestAUACN(t *testing.T) {
	cases := []struct {
		in   string
		want bool
	}{
		{"004085616", true},  // ASIC public test vector
		{"100000002", true},  // computed
		{"004085617", false}, // off-by-one
	}
	for _, c := range cases {
		if got := auACN(c.in); got != c.want {
			t.Errorf("auACN(%q) = %v, want %v", c.in, got, c.want)
		}
	}
}

func TestAUABN(t *testing.T) {
	cases := []struct {
		in   string
		want bool
	}{
		{"51824753556", true},  // ATO's own ABN (public)
		{"51824753557", false}, // off-by-one
		{"00000000000", false}, // all-zero
	}
	for _, c := range cases {
		if got := auABN(c.in); got != c.want {
			t.Errorf("auABN(%q) = %v, want %v", c.in, got, c.want)
		}
	}
}

func TestAUMedicare(t *testing.T) {
	cases := []struct {
		in   string
		want bool
	}{
		{"2239999901", true},  // computed
		{"2239999911", false}, // bad check
		{"1234567891", false}, // first digit < 2
	}
	for _, c := range cases {
		if got := auMedicare(c.in); got != c.want {
			t.Errorf("auMedicare(%q) = %v, want %v", c.in, got, c.want)
		}
	}
}

func TestUKNHS(t *testing.T) {
	cases := []struct {
		in   string
		want bool
	}{
		{"9876544322", true},  // computed Mod-11
		{"9434765919", true},  // NHS Digital published example
		{"9876544323", false}, // off-by-one
		{"0000000000", false}, // degenerate
	}
	for _, c := range cases {
		if got := ukNHS(c.in); got != c.want {
			t.Errorf("ukNHS(%q) = %v, want %v", c.in, got, c.want)
		}
	}
}

func TestPLPESEL(t *testing.T) {
	cases := []struct {
		in   string
		want bool
	}{
		{"94051012343", true},  // 1994-05-10, computed Mod-10
		{"94051012344", false}, // off-by-one
		{"94131012343", false}, // month 13 invalid
		{"94050012343", false}, // day 00 invalid
	}
	for _, c := range cases {
		if got := plPESEL(c.in); got != c.want {
			t.Errorf("plPESEL(%q) = %v, want %v", c.in, got, c.want)
		}
	}
}

func TestKRRRN(t *testing.T) {
	cases := []struct {
		in   string
		want bool
	}{
		{"9501011234564", true},  // computed
		{"9501011234565", false}, // off-by-one
		{"9513011234564", false}, // month 13 invalid
		{"9501010234564", false}, // sex digit 0 invalid
	}
	for _, c := range cases {
		if got := krRRN(c.in); got != c.want {
			t.Errorf("krRRN(%q) = %v, want %v", c.in, got, c.want)
		}
	}
}

func TestTRTCKN(t *testing.T) {
	cases := []struct {
		in   string
		want bool
	}{
		{"12345678950", true},  // computed
		{"12345678951", false}, // off-by-one
		{"02345678950", false}, // leading zero
	}
	for _, c := range cases {
		if got := trTCKN(c.in); got != c.want {
			t.Errorf("trTCKN(%q) = %v, want %v", c.in, got, c.want)
		}
	}
}

func TestTHTNIN(t *testing.T) {
	cases := []struct {
		in   string
		want bool
	}{
		{"1234567890121", true},  // computed
		{"1234567890122", false}, // off-by-one
		{"0234567890121", false}, // leading zero
	}
	for _, c := range cases {
		if got := thTNIN(c.in); got != c.want {
			t.Errorf("thTNIN(%q) = %v, want %v", c.in, got, c.want)
		}
	}
}

func TestITVAT(t *testing.T) {
	cases := []struct {
		in   string
		want bool
	}{
		{"12345678903", true},  // computed Luhn-like
		{"12345678904", false}, // off-by-one
		{"00000000000", false}, // explicitly excluded
	}
	for _, c := range cases {
		if got := itVAT(c.in); got != c.want {
			t.Errorf("itVAT(%q) = %v, want %v", c.in, got, c.want)
		}
	}
}

func TestDETaxID(t *testing.T) {
	cases := []struct {
		in   string
		want bool
	}{
		{"12345678903", true},  // computed ISO 7064 Mod 11,10
		{"12345678904", false}, // off-by-one
		{"02345678903", false}, // leading zero
		{"11111111111", false}, // > 3 same digits
	}
	for _, c := range cases {
		if got := deTaxID(c.in); got != c.want {
			t.Errorf("deTaxID(%q) = %v, want %v", c.in, got, c.want)
		}
	}
}

func TestINAadhaar(t *testing.T) {
	cases := []struct {
		in   string
		want bool
	}{
		{"234567890124", true},  // computed Verhoeff
		{"234567890125", false}, // off-by-one
		{"123456789012", false}, // leading 1 forbidden
		{"234565654322", false}, // off-by-many random
	}
	for _, c := range cases {
		if got := inAadhaar(c.in); got != c.want {
			t.Errorf("inAadhaar(%q) = %v, want %v", c.in, got, c.want)
		}
	}
}

func TestSEPersonnummer(t *testing.T) {
	cases := []struct {
		in   string
		want bool
	}{
		{"9405101230", true},   // computed Luhn, valid date
		{"199405101230", true}, // 12-digit form
		{"9405101231", false},  // off-by-one
		{"9413101230", false},  // invalid month
	}
	for _, c := range cases {
		if got := sePersonnummer(c.in); got != c.want {
			t.Errorf("sePersonnummer(%q) = %v, want %v", c.in, got, c.want)
		}
	}
}

func TestSEOrgnummer(t *testing.T) {
	cases := []struct {
		in   string
		want bool
	}{
		{"5566778899", true},  // computed Luhn, third-pair ≥ 20
		{"5566778890", false}, // off-by-one
		{"1116778899", false}, // third-pair 16 < 20 → personnummer-shaped
	}
	for _, c := range cases {
		if got := seOrgnummer(c.in); got != c.want {
			t.Errorf("seOrgnummer(%q) = %v, want %v", c.in, got, c.want)
		}
	}
}

func TestESNIF(t *testing.T) {
	cases := []struct {
		in   string
		want bool
	}{
		{"12345678Z", true},  // computed
		{"12345678-Z", true}, // dash separator
		{"12345678A", false}, // wrong letter
		{"01234567L", true},  // 8-digit form with leading zero
	}
	for _, c := range cases {
		if got := esNIF(c.in); got != c.want {
			t.Errorf("esNIF(%q) = %v, want %v", c.in, got, c.want)
		}
	}
}

func TestESNIE(t *testing.T) {
	cases := []struct {
		in   string
		want bool
	}{
		{"X1234567L", true},  // X→0 then NIF check
		{"Y1234567X", true},  // Y→1 (computed below)
		{"X1234567A", false}, // wrong letter
		{"A1234567L", false}, // prefix not X/Y/Z
	}
	for _, c := range cases {
		if got := esNIE(c.in); got != c.want {
			t.Errorf("esNIE(%q) = %v, want %v", c.in, got, c.want)
		}
	}
}

func TestSGNRICFIN(t *testing.T) {
	cases := []struct {
		in   string
		want bool
	}{
		{"S1234567D", true}, // computed
		{"T1234567J", true},
		{"F1234567N", true},
		{"G1234567X", true},
		{"M1234567X", true},
		{"S1234567A", false}, // wrong letter
		{"Z1234567D", false}, // unsupported prefix
	}
	for _, c := range cases {
		if got := sgNRICFIN(c.in); got != c.want {
			t.Errorf("sgNRICFIN(%q) = %v, want %v", c.in, got, c.want)
		}
	}
}

func TestFIPIC(t *testing.T) {
	cases := []struct {
		in   string
		want bool
	}{
		{"131052-308T", true},  // 1952-10-13, computed
		{"131052X308T", true},  // X separator (post-2023 supplementary)
		{"131052-308A", false}, // wrong check char
		{"311352-308T", false}, // month 13 invalid
		{"131052/308T", false}, // '/' not in valid separator set
	}
	for _, c := range cases {
		if got := fiPIC(c.in); got != c.want {
			t.Errorf("fiPIC(%q) = %v, want %v", c.in, got, c.want)
		}
	}
}

func TestDEANumber(t *testing.T) {
	cases := []struct {
		in   string
		want bool
	}{
		{"AB1234563", true},  // computed split-sum
		{"AB1234564", false}, // off-by-one
		{"1B1234563", false}, // leading non-letter
	}
	for _, c := range cases {
		if got := deaNumber(c.in); got != c.want {
			t.Errorf("deaNumber(%q) = %v, want %v", c.in, got, c.want)
		}
	}
}
