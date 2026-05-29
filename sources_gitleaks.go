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
	"fmt"
	"regexp"

	"github.com/zricethezav/gitleaks/v8/detect"
)

type gitleaksSource struct {
	detector *detect.Detector
}

func newGitleaksSource() (*gitleaksSource, error) {
	d, err := detect.NewDetectorDefaultConfig()
	if err != nil {
		return nil, fmt.Errorf("gitleaks default config: %w", err)
	}
	// Silence gitleaks' internal verbose output / colored banners.
	d.Verbose = false
	d.NoColor = true
	d.MaxTargetMegaBytes = 8 // body cap
	return &gitleaksSource{detector: d}, nil
}

func (g *gitleaksSource) Name() string { return "gitleaks" }

// uuidShape matches RFC 4122 UUIDs in their canonical hyphenated form.
// Gitleaks' `generic-api-key` rule flags every long hex-ish run with
// hyphens — including session/turn IDs codex stamps into request
// headers on every call — so we strip these here before they reach the
// policy layer. Specific gitleaks rules (`aws-secret-access-key`,
// `slack-bot-or-user-token`, etc.) carry their own anchors and don't
// need this guard.
var uuidShape = regexp.MustCompile(`^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$`)

func (g *gitleaksSource) Scan(body []byte) []Match {
	findings := g.detector.DetectBytes(body)
	out := make([]Match, 0, len(findings))
	for _, f := range findings {
		if f.RuleID == "generic-api-key" && uuidShape.MatchString(f.Secret) {
			continue
		}
		// Gitleaks reports line/column; we anchor at the line start
		// and then locate the actual secret bytes from there. Without
		// this, JSON bodies (single line, no newlines) all land at
		// offset 0 and the redactor would rewrite the wrong span.
		lineStart := byteOffsetForLine(body, f.StartLine)
		offset, end := -1, -1
		if f.Secret != "" {
			if i := bytes.Index(body[lineStart:], []byte(f.Secret)); i >= 0 {
				offset = lineStart + i
				end = offset + len(f.Secret)
			}
		}
		if offset < 0 {
			// Couldn't anchor — fall back to line-start so the log
			// line stays informative even though redact can't fire.
			offset = lineStart
		}
		out = append(out, Match{
			RuleID:   "gitleaks:" + f.RuleID,
			Category: "secret",
			Severity: SevCritical,
			Offset:   offset,
			End:      end,
			Snippet:  redactSnippet(f.Secret),
		})
	}
	return out
}

func byteOffsetForLine(body []byte, line int) int {
	if line <= 1 {
		return 0
	}
	cur := 1
	for i, b := range body {
		if b == '\n' {
			cur++
			if cur == line {
				return i + 1
			}
		}
	}
	return bytes.LastIndexByte(body, '\n') + 1
}
