//go:build !((linux && (amd64 || arm64)) || (darwin && arm64) || (windows && (amd64 || arm64)))

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
	"log"
	"os"
	"runtime"
)

// maybeAttachOCR is a no-op on platforms outside the supported matrix
// (currently linux/{amd64,arm64}, darwin/arm64, windows/{amd64,arm64}). If a
// user explicitly opts in via MASQR_OCR=1 we log a loud warning so the silent
// disable isn't mistaken for "OCR is running but finding nothing."
func (s *Scanner) maybeAttachOCR() {
	if os.Getenv("MASQR_OCR") == "1" {
		log.Printf("scanner: MASQR_OCR=1 ignored — OCR is not bundled for %s/%s "+
			"(supported: linux/{amd64,arm64}, darwin/arm64, windows/{amd64,arm64}); "+
			"see README §Platform support",
			runtime.GOOS, runtime.GOARCH)
	}
}
