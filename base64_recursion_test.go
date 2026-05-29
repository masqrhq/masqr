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
	"strings"
	"testing"
)

// TestBase64RecursiveDecodeFindsNestedSecret confirms masqr peels
// multiple base64 wrappers (`base64(base64(base64(secret)))`) and
// flags the leaked AWS key buried in the bottom layer. Pre-fix the
// recursion cap was 1, so the same input slipped through after the
// second wrap.
func TestBase64RecursiveDecodeFindsNestedSecret(t *testing.T) {
	const awsKey = "AKIAIOSFODNN7EXAMPLE"

	payload := awsKey
	// Three rounds of base64 wrapping — well within the new maxScanDepth.
	for i := 0; i < 3; i++ {
		payload = base64.StdEncoding.EncodeToString([]byte(payload))
	}
	body := []byte("prompt context: " + payload + " (encoded data)")

	got := DefaultScanner().Scan(body)
	var hit bool
	for _, m := range got {
		// The scanner appends `/base64-decoded` once per recursion
		// hop. We don't care how deep — just that the AWS rule fired
		// somewhere down the chain.
		if strings.HasPrefix(m.RuleID, "aws-access-key-id") {
			hit = true
		}
	}
	if !hit {
		t.Fatalf("expected nested AWS key to be flagged through recursion; got: %+v", got)
	}
}
