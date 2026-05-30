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

// findOffset locates sub in body and returns [off,end). Helper for span tests.
func findOffset(t *testing.T, body, sub string) (int, int) {
	t.Helper()
	i := strings.Index(body, sub)
	if i < 0 {
		t.Fatalf("substring %q not found in body", sub)
	}
	return i, i + len(sub)
}

func TestSpanIsWithinTimestamp(t *testing.T) {
	// The nanosecond fractional+Z tail a UEN rule grabs out of an ISO stamp.
	body := `{"now":"2026-05-30T00:22:27.321937990Z"}`
	off, end := findOffset(t, body, "321937990Z")
	if !spanIsWithinTimestamp([]byte(body), off, end) {
		t.Errorf("fractional+Z tail of an RFC3339 stamp should be recognised as a timestamp span")
	}
	// A standalone alnum token that is NOT inside a timestamp must not match.
	body2 := `Entity UEN 200512345A registered`
	off2, end2 := findOffset(t, body2, "200512345A")
	if spanIsWithinTimestamp([]byte(body2), off2, end2) {
		t.Errorf("a bare UEN in prose must not be treated as a timestamp")
	}
}

func TestSpanIsEpochMillis(t *testing.T) {
	// 13-digit ms epoch as a request-ID path segment → suppressed.
	body := `"requestId":"agent/e3e8a2a0/1780100526979/b803fda9/2"`
	off, end := findOffset(t, body, "1780100526979")
	if !spanIsEpochMillis([]byte(body), off, end) {
		t.Errorf("slash-delimited 13-digit epoch in a requestId should be recognised as an epoch")
	}

	// Same 13 digits as a JSON timestamp value → suppressed.
	body2 := `{"createdAt":1780100526979}`
	off2, end2 := findOffset(t, body2, "1780100526979")
	if !spanIsEpochMillis([]byte(body2), off2, end2) {
		t.Errorf("epoch under a time-ish key should be recognised")
	}

	// SAME digits, but in natural-language prose with no machine context →
	// NOT an epoch (so a real 13-digit national ID still fires).
	body3 := `my national id number is 1780100526979 ok`
	off3, end3 := findOffset(t, body3, "1780100526979")
	if spanIsEpochMillis([]byte(body3), off3, end3) {
		t.Errorf("a 13-digit ID in prose must NOT be suppressed as an epoch")
	}

	// Out-of-range 13-digit number is never an epoch.
	body4 := `id/9999999999999/x`
	off4, end4 := findOffset(t, body4, "9999999999999")
	if spanIsEpochMillis([]byte(body4), off4, end4) {
		t.Errorf("13 digits outside the plausible ms-epoch window must not match")
	}

	// Part of a longer digit run is not a standalone epoch.
	body5 := `/11780100526979/`
	off5 := strings.Index(body5, "1780100526979")
	if spanIsEpochMillis([]byte(body5), off5, off5+13) {
		t.Errorf("a 13-digit slice of a longer number must not match")
	}
}

// TestScannerSuppressesAgyMetadata is the regression for the reported bug: a
// benign prompt whose envelope carries agy's request ID (13-digit epoch) and a
// nanosecond ISO timestamp must produce NO th-tnin / sg-uen findings.
func TestScannerSuppressesAgyMetadata(t *testing.T) {
	envelope := `{"requestId":"agent/e3e8a2a0-3fda-4a57-a6b3-be3016e2a1c5/1780100526979/b803fda9-dd72-46cf-8f27-fe09ffbd57e1/2",` +
		`"metadata":"The current local time is: 2026-05-30T00:22:27.321937990Z",` +
		`"contents":[{"role":"user","parts":[{"text":"2 + 2 = ?"}]}]}`

	for _, m := range DefaultScanner().Scan([]byte(envelope)) {
		if m.RuleID == "th-tnin" || m.RuleID == "sg-uen" {
			t.Errorf("benign agy envelope still tripped %s @%d..%d (%s) — timestamp/epoch not suppressed",
				m.RuleID, m.Offset, m.End, m.Snippet)
		}
	}
}

// TestSuppressMachineTimestampsKeepsRealFindings makes sure the filter only
// removes verified timestamp/epoch spans and leaves an unrelated finding.
func TestSuppressMachineTimestampsKeepsRealFindings(t *testing.T) {
	body := []byte(`ts /1780100526979/ and key AKIAIOSFODNN7EXAMPLE here`)
	in := []Match{
		{RuleID: "th-tnin", Offset: 4, End: 17}, // the epoch
		{RuleID: "aws-access-key-id", Offset: strings.Index(string(body), "AKIA"), End: strings.Index(string(body), "AKIA") + 20},
	}
	out := suppressMachineTimestamps(body, in)
	var ids []string
	for _, m := range out {
		ids = append(ids, m.RuleID)
	}
	if len(out) != 1 || ids[0] != "aws-access-key-id" {
		t.Errorf("want only aws-access-key-id retained, got %v", ids)
	}
}
