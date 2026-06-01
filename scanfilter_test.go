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
	"strings"
	"testing"
)

// TestNeutralizeOpaqueFields checks that a thoughtSignature value is blanked in
// place (length preserved, surrounding JSON intact) so its base64/base58
// substrings can't be scanned.
func TestNeutralizeOpaqueFields(t *testing.T) {
	buf := []byte(`{"parts":[{"text":"hi","thoughtSignature":"EpMDsecretBLOBig=="}],"x":"keep"}`)
	out := neutralizeOpaqueFields(buf)
	if len(out) != len(buf) {
		t.Fatalf("length changed: %d vs %d (offsets would shift)", len(out), len(buf))
	}
	if bytes.Contains(out, []byte("EpMDsecretBLOBig==")) {
		t.Errorf("thoughtSignature value not blanked:\n%s", out)
	}
	if !bytes.Contains(out, []byte(`"text":"hi"`)) || !bytes.Contains(out, []byte(`"keep"`)) {
		t.Errorf("blanked outside the value span:\n%s", out)
	}
	if !bytes.Contains(out, []byte(`"thoughtSignature":"`)) {
		t.Errorf("key and quotes should stay intact:\n%s", out)
	}
}

// TestThoughtSignatureNotScanned is the end-to-end guard: a real secret outside
// a thoughtSignature is still flagged (with a correct, redactable offset), while
// nothing inside the thoughtSignature blob trips a rule.
func TestThoughtSignatureNotScanned(t *testing.T) {
	// A long, varied base64 blob that would otherwise trip generic-base64-blob.
	blob := "EpMDCpADAQ" + strings.Repeat("aB3xZ9kQwR7vT2mN", 16) + "ig=="
	body := []byte(`{"contents":[` +
		`{"role":"model","parts":[{"text":"ok","thoughtSignature":"` + blob + `"}]},` +
		`{"role":"user","parts":[{"text":"deploy with AKIAIOSFODNN7EXAMPLE now"}]}]}`)

	var sawAWS bool
	for _, m := range scanRequest(nil, body) {
		switch m.RuleID {
		case "aws-access-key-id":
			sawAWS = true
			if m.End > 0 && m.End <= len(body) {
				if got := string(body[m.Offset:m.End]); !strings.HasPrefix(got, "AKIA") {
					t.Errorf("aws match offset points at %q, not the key", got)
				}
			}
		case "generic-base64-blob", "bitcoin-legacy-address":
			t.Errorf("thoughtSignature produced a false finding: %s %q", m.RuleID, m.Snippet)
		}
	}
	if !sawAWS {
		t.Error("a real AWS key outside the thoughtSignature must still be flagged")
	}
}
