//go:build (linux && (amd64 || arm64)) || (darwin && arm64) || (windows && (amd64 || arm64))

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
	"os"
	"testing"
)

// clearOCREnv removes MASQR_OCR for the duration of the test, restoring any
// prior value on cleanup, so we can exercise the unset/default path.
func clearOCREnv(t *testing.T) {
	t.Helper()
	prev, had := os.LookupEnv("MASQR_OCR")
	if err := os.Unsetenv("MASQR_OCR"); err != nil {
		t.Fatalf("unset MASQR_OCR: %v", err)
	}
	t.Cleanup(func() {
		if had {
			os.Setenv("MASQR_OCR", prev)
		} else {
			os.Unsetenv("MASQR_OCR")
		}
	})
}

// TestOCREnabledByEnv documents the opt-out semantics: OCR is on by default and
// only a recognised falsey MASQR_OCR value turns it off.
func TestOCREnabledByEnv(t *testing.T) {
	cases := []struct {
		val  string
		set  bool
		want bool
	}{
		{set: false, want: true}, // unset → enabled by default
		{val: "", set: true, want: true},
		{val: "1", set: true, want: true},
		{val: "true", set: true, want: true},
		{val: "yes", set: true, want: true},
		{val: "on", set: true, want: true},
		{val: "anything", set: true, want: true},
		{val: "0", set: true, want: false},
		{val: " 0 ", set: true, want: false},
		{val: "false", set: true, want: false},
		{val: "FALSE", set: true, want: false},
		{val: "no", set: true, want: false},
		{val: "off", set: true, want: false},
	}
	for _, c := range cases {
		if c.set {
			t.Setenv("MASQR_OCR", c.val)
		} else {
			clearOCREnv(t)
		}
		if got := ocrEnabledByEnv(); got != c.want {
			t.Errorf("ocrEnabledByEnv() with MASQR_OCR=%q (set=%v) = %v, want %v", c.val, c.set, got, c.want)
		}
	}
}

// TestMaybeAttachOCRDefault verifies that with default env (MASQR_OCR unset) the
// OCR source is attached, and that the opt-out (MASQR_OCR=0) skips it. The
// embedded models ship with the binary on supported platforms, so the source
// must load successfully here.
func TestMaybeAttachOCRDefault(t *testing.T) {
	// Default env: OCR should be attached.
	clearOCREnv(t)
	s := NewScanner(defaultRules())
	s.maybeAttachOCR()
	if !hasSource(s, "ocr") {
		t.Fatal("expected OCR source attached by default (MASQR_OCR unset)")
	}

	// Opt-out: OCR should be skipped.
	t.Setenv("MASQR_OCR", "0")
	s2 := NewScanner(defaultRules())
	s2.maybeAttachOCR()
	if hasSource(s2, "ocr") {
		t.Fatal("expected OCR source skipped when MASQR_OCR=0")
	}
}

func hasSource(s *Scanner, name string) bool {
	for _, src := range s.sources {
		if src.Name() == name {
			return true
		}
	}
	return false
}
