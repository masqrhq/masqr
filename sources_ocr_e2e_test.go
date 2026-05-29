//go:build linux && amd64

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
	"fmt"
	"os"
	"testing"
)

// TestOCRRecognizeRealImage verifies the embedded PP-OCRv5 pipeline (det →
// cls → rec) actually recognizes text from a real image. Skipped unless the
// test image at MASQR_OCR_TEST_IMAGE exists — the test image is too large to
// commit so this is gated.
func TestOCRRecognizeRealImage(t *testing.T) {
	path := os.Getenv("MASQR_OCR_TEST_IMAGE")
	if path == "" {
		t.Skip("set MASQR_OCR_TEST_IMAGE to a path-to-image to run this test")
	}
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read test image: %v", err)
	}

	parent := NewScanner(nil)
	o, err := newOCRSource(parent)
	if err != nil {
		t.Fatalf("newOCRSource: %v", err)
	}
	defer o.Close()

	text, err := o.recognize(raw)
	if err != nil {
		t.Fatalf("recognize: %v", err)
	}
	if text == "" {
		t.Fatal("recognize returned empty text")
	}
	t.Logf("recognized %d chars:\n%s", len(text), text)

	// Also exercise the Scan() entrypoint with the image embedded in an
	// Anthropic content block, to confirm the regex + base64 + handoff path.
	b64 := base64.StdEncoding.EncodeToString(raw)
	body := []byte(fmt.Sprintf(
		`{"messages":[{"role":"user","content":[{"type":"image","source":{"type":"base64","media_type":"image/jpeg","data":"%s"}}]}]}`, b64))
	matches := o.Scan(body)
	t.Logf("Scan() returned %d secret matches", len(matches))
}
