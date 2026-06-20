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

// TestObfuscatedSecretsAreDecodedAndCaught covers the red-team gap fixtures:
// each documentation-only sample secret (AKIAIOSFODNN7EXAMPLE / a ghp_ PAT) is
// hidden behind a reversible obfuscation the rule engine cannot match on its
// own. masqr must peel the encoding and flag the inner secret. The encoded
// strings below are the exact fixture payloads from redteam-gaps.jsonl.
func TestObfuscatedSecretsAreDecodedAndCaught(t *testing.T) {
	cases := []struct {
		id        string
		technique string
		wantRule  string // rule-ID prefix the fired match must carry
		content   string
	}{
		// ─── aws-access-key-id (AKIAIOSFODNN7EXAMPLE) ──────────────────
		{
			id: "aws-access-key-id:base32", technique: "base32", wantRule: "aws-access-key-id",
			content: "Deploy note — production aws-access-key-id for the worker pool: IFFUSQKJJ5JUMT2EJZHDORKYIFGVATCF",
		},
		{
			id: "aws-access-key-id:hex", technique: "hex", wantRule: "aws-access-key-id",
			content: "Deploy note — production aws-access-key-id for the worker pool: 414b4941494f53464f444e4e374558414d504c45",
		},
		{
			id: "aws-access-key-id:url_percent", technique: "url_percent", wantRule: "aws-access-key-id",
			content: "Deploy note — production aws-access-key-id for the worker pool: %41%4B%49%41%49%4F%53%46%4F%44%4E%4E%37%45%58%41%4D%50%4C%45",
		},
		{
			id: "aws-access-key-id:html_entities", technique: "html_entities", wantRule: "aws-access-key-id",
			content: "Deploy note — production aws-access-key-id for the worker pool: &#65;&#75;&#73;&#65;&#73;&#79;&#83;&#70;&#79;&#68;&#78;&#78;&#55;&#69;&#88;&#65;&#77;&#80;&#76;&#69;",
		},
		{
			id: "aws-access-key-id:gzip_b64", technique: "gzip_b64", wantRule: "aws-access-key-id",
			content: "Deploy note — production aws-access-key-id for the worker pool: H4sIAI4CN2oC/3P09nT09A9283fx8zN3jXD0DfBxBQDiHCf6FAAAAA==",
		},
		// ─── github-pat (ghp_1234567890abcdefABCDEF1234567890abcd) ──────
		{
			id: "github-pat:base32", technique: "base32", wantRule: "github-pat",
			content: "Deploy note — production github-pat for the worker pool: M5UHAXZRGIZTINJWG44DSMDBMJRWIZLGIFBEGRCFIYYTEMZUGU3DOOBZGBQWEY3E",
		},
		{
			id: "github-pat:hex", technique: "hex", wantRule: "github-pat",
			content: "Deploy note — production github-pat for the worker pool: 6768705f313233343536373839306162636465664142434445463132333435363738393061626364",
		},
		{
			id: "github-pat:url_percent", technique: "url_percent", wantRule: "github-pat",
			content: "Deploy note — production github-pat for the worker pool: %67%68%70%5F%31%32%33%34%35%36%37%38%39%30%61%62%63%64%65%66%41%42%43%44%45%46%31%32%33%34%35%36%37%38%39%30%61%62%63%64",
		},
		{
			id: "github-pat:html_entities", technique: "html_entities", wantRule: "github-pat",
			content: "Deploy note — production github-pat for the worker pool: &#103;&#104;&#112;&#95;&#49;&#50;&#51;&#52;&#53;&#54;&#55;&#56;&#57;&#48;&#97;&#98;&#99;&#100;&#101;&#102;&#65;&#66;&#67;&#68;&#69;&#70;&#49;&#50;&#51;&#52;&#53;&#54;&#55;&#56;&#57;&#48;&#97;&#98;&#99;&#100;",
		},
		{
			id: "github-pat:gzip_b64", technique: "gzip_b64", wantRule: "github-pat",
			content: "Deploy note — production github-pat for the worker pool: H4sIAI4CN2oC/0vPKIg3NDI2MTUzt7A0SExKTklNc3RydnF1QxUFAKQSDtYoAAAA",
		},
	}

	for _, tc := range cases {
		t.Run(tc.id, func(t *testing.T) {
			got := DefaultScanner().Scan([]byte(tc.content))
			var found bool
			for _, m := range got {
				if strings.HasPrefix(m.RuleID, tc.wantRule) {
					found = true
					break
				}
			}
			if !found {
				t.Fatalf("technique %q: expected a %q finding in %q; got %+v",
					tc.technique, tc.wantRule, tc.content, got)
			}
		})
	}
}

// TestObfuscationDecodersUnit exercises each decoder in isolation so a
// regression in one peeler is attributed precisely, independent of the rule
// engine.
func TestObfuscationDecodersUnit(t *testing.T) {
	const aws = "AKIAIOSFODNN7EXAMPLE"

	t.Run("hex", func(t *testing.T) {
		got, ok := decodeHex("414b4941494f53464f444e4e374558414d504c45")
		if !ok || string(got) != aws {
			t.Fatalf("decodeHex = %q, %v", got, ok)
		}
		if _, ok := decodeHex("abc"); ok { // odd length
			t.Fatal("decodeHex accepted odd-length input")
		}
	})

	t.Run("base32", func(t *testing.T) {
		got, ok := decodeBase32("IFFUSQKJJ5JUMT2EJZHDORKYIFGVATCF")
		if !ok || string(got) != aws {
			t.Fatalf("decodeBase32 = %q, %v", got, ok)
		}
	})

	t.Run("url_percent", func(t *testing.T) {
		got, ok := decodeURLPercent("%41%4B%49%41")
		if !ok || string(got) != "AKIA" {
			t.Fatalf("decodeURLPercent = %q, %v", got, ok)
		}
	})

	t.Run("html_entities", func(t *testing.T) {
		dec, ok := decodeHTMLEntities("&#65;&#75;&#73;&#65;")
		if !ok || string(dec) != "AKIA" {
			t.Fatalf("decodeHTMLEntities decimal = %q, %v", dec, ok)
		}
		hexDec, ok := decodeHTMLEntities("&#x41;&#x4B;&#x49;&#x41;")
		if !ok || string(hexDec) != "AKIA" {
			t.Fatalf("decodeHTMLEntities hex = %q, %v", hexDec, ok)
		}
	})

	t.Run("gzip_b64", func(t *testing.T) {
		got, ok := decodeGzipBase64("H4sIAI4CN2oC/3P09nT09A9283fx8zN3jXD0DfBxBQDiHCf6FAAAAA==")
		if !ok || string(got) != aws {
			t.Fatalf("decodeGzipBase64 = %q, %v", got, ok)
		}
		if _, ok := decodeGzipBase64("bm90LWd6aXAtanVzdC1iNjQ="); ok {
			t.Fatal("decodeGzipBase64 accepted non-gzip base64")
		}
	})
}
