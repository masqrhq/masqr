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

func TestLuhn(t *testing.T) {
	cases := []struct {
		in   string
		want bool
	}{
		{"4532015112830366", true},      // valid Visa
		{"4111111111111111", true},      // valid Visa (test card)
		{"5555555555554444", true},      // valid Mastercard (test card)
		{"378282246310005", true},       // valid Amex (test card)
		{"4532-0151-1283-0366", true},   // dashes ok
		{"4532 0151 1283 0366", true},   // spaces ok
		{"4532015112830367", false},     // bad check digit
		{"1234567890123456", false},     // random
		{"1234", false},                 // too short
		{"12345678901234567890", false}, // too long
		{"abcdefghijklmnop", false},     // no digits
	}
	for _, c := range cases {
		if got := luhn(c.in); got != c.want {
			t.Errorf("luhn(%q) = %v, want %v", c.in, got, c.want)
		}
	}
}

func TestIBANMod97(t *testing.T) {
	cases := []struct {
		in   string
		want bool
	}{
		{"CH9300762011623852957", true},      // valid CH IBAN
		{"CH93 0076 2011 6238 5295 7", true}, // with spaces
		{"GB82WEST12345698765432", true},     // valid UK
		{"DE89370400440532013000", true},     // valid DE
		{"CH9300762011623852958", false},     // wrong check digit
		{"CH00000000000000000000", false},    // not a real IBAN
		{"NOTANIBAN", false},                 // garbage
		{"", false},                          // empty
	}
	for _, c := range cases {
		if got := ibanMod97(c.in); got != c.want {
			t.Errorf("ibanMod97(%q) = %v, want %v", c.in, got, c.want)
		}
	}
}

func TestAHVCheck(t *testing.T) {
	cases := []struct {
		in   string
		want bool
	}{
		{"756.9217.0769.85", true},  // valid AHV (canonical example)
		{"756.1234.5678.97", true},  // valid AHV (Mod-10 verified)
		{"756.1234.5678.99", false}, // wrong check digit
		{"755.1234.5678.97", false}, // wrong country prefix
		{"123.4567.8901.23", false}, // wrong prefix
		{"756.1234.5678", false},    // too short
		{"", false},
	}
	for _, c := range cases {
		if got := ahvCheck(c.in); got != c.want {
			t.Errorf("ahvCheck(%q) = %v, want %v", c.in, got, c.want)
		}
	}
}

func TestUIDCheck(t *testing.T) {
	cases := []struct {
		in   string
		want bool
	}{
		{"CHE-105.962.533", true},  // valid UID (Mod-11 verified)
		{"CHE-105.962.535", false}, // wrong check digit (real-world miscopy)
		{"CHE-105.962.534", false}, // off-by-one
		{"CHE-105.962", false},     // too short
		{"", false},
	}
	for _, c := range cases {
		if got := uidCheck(c.in); got != c.want {
			t.Errorf("uidCheck(%q) = %v, want %v", c.in, got, c.want)
		}
	}
}
