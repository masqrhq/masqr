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

// TestThinkingBlockNotScanned guards the Anthropic extended-thinking case: the
// `signature` and `thinking` text of a thinking block, and the `data` of a
// redacted_thinking block, must not be scanned (masking any of them mutates the
// signed bytes and the upstream rejects the turn with 400 "Invalid `signature`
// in `thinking` block"), while a real secret in the user's text still trips.
func TestThinkingBlockNotScanned(t *testing.T) {
	// Long, varied base64 blobs standing in for the signed thinking bytes —
	// the kind that trip generic-base64-blob / bitcoin-legacy-address.
	sig := "ErUECmMIDhgCKkA" + strings.Repeat("aB3xZ9kQwR7vT2mN", 16) + "ig=="
	// A secret the model echoed into its own reasoning: masqr must not touch
	// it, because the signature covers the thinking text too.
	think := "let me use AKIAIOSFODNN7THINKKEY from the env"
	data := "WaEoCpEDAQ" + strings.Repeat("Zq8xV2nB5kM7wR3t", 16) + "ag=="
	body := []byte(`{"messages":[` +
		`{"role":"assistant","content":[` +
		`{"type":"thinking","thinking":"` + think + `","signature":"` + sig + `"},` +
		`{"type":"redacted_thinking","data":"` + data + `"}]},` +
		`{"role":"user","content":[{"type":"text","text":"deploy with AKIAIOSFODNN7EXAMPLE now"}]}]}`)

	var sawUserAWS bool
	for _, m := range scanRequest(nil, body) {
		if m.End <= 0 || m.End > len(body) {
			continue
		}
		got := string(body[m.Offset:m.End])
		switch m.RuleID {
		case "aws-access-key-id":
			if got == "AKIAIOSFODNN7EXAMPLE" {
				sawUserAWS = true
			} else {
				t.Errorf("a thinking-block secret was flagged: %q", got)
			}
		case "generic-base64-blob", "bitcoin-legacy-address":
			t.Errorf("a thinking-block blob produced a false finding: %s %q", m.RuleID, got)
		}
	}
	if !sawUserAWS {
		t.Error("a real AWS key in the user's text must still be flagged")
	}
}

// TestGenericSignatureFieldStillScanned proves the scoping is tight: a JSON
// field merely named `signature` that is NOT a thinking-block sibling is still
// scanned, so blanking thinking signatures doesn't open a blanket blind spot.
func TestGenericSignatureFieldStillScanned(t *testing.T) {
	body := []byte(`{"webhook":{"signature":"AKIAIOSFODNN7EXAMPLE"}}`)
	var saw bool
	for _, m := range scanRequest(nil, body) {
		if m.RuleID == "aws-access-key-id" {
			saw = true
		}
	}
	if !saw {
		t.Error("a secret in a non-thinking `signature` field must still be flagged")
	}
}
