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
	"strings"
	"testing"
)

// BenchmarkScanProse measures cold scanning of a prose body that contains
// no anchor keyword. The prefilter must short-circuit and the per-rule
// regex loop should not run.
func BenchmarkScanProse(b *testing.B) {
	s := NewScanner(defaultRules())
	body := []byte(strings.Repeat("the quick brown fox jumped over the lazy dog. ", 2048))
	b.SetBytes(int64(len(body)))
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = s.Scan(body)
	}
}

// BenchmarkScanWithHits exercises a body containing one finding from each
// major rule family — pii, secret, attachment, internal-ip.
func BenchmarkScanWithHits(b *testing.B) {
	s := NewScanner(defaultRules())
	body := []byte(strings.Repeat("filler text ", 500) + `
AWS=AKIAIOSFODNN7EXAMPLE
SSN=219-12-3456
Card=4532015112830366
NHS=9434765919
IBAN=DE89370400440532013000
Email=test@example.com
Aadhaar=2345-6789-0124
`)
	b.SetBytes(int64(len(body)))
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = s.Scan(body)
	}
}

// BenchmarkDigitIDSourceAlone isolates the consolidated digit-cluster
// classifier so we can spot regressions in that one hot path.
func BenchmarkDigitIDSourceAlone(b *testing.B) {
	d := newDigitIDSource()
	body := []byte(strings.Repeat("order 12345 from yesterday at 14:30 with ID 99887766 ", 500) +
		"SSN 219-12-3456 NHS 943 476 5919 Aadhaar 2345-6789-0124")
	b.SetBytes(int64(len(body)))
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = d.Scan(body)
	}
}
