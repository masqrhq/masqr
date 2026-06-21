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
	"encoding/json"
	"io"
	"log"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
)

// redteamFixture is one red-team gap: the *parsed* `.content` of a line in
// redteam-gaps.jsonl (i.e. the plain Go string a JSON decoder yields), plus the
// secret-rule prefix masqr must surface once it un-obfuscates it.
type redteamFixture struct {
	id        string
	technique string
	wantRule  string
	content   string
}

// redteamFixtures mirrors redteam-gaps.jsonl exactly. Each `content` is the
// decoded `.content` field; the proxy test below re-encodes it into a JSON
// request body, which is the precise transformation the acceptance gate applies
// when it POSTs the fixture to /v1/messages.
var redteamFixtures = []redteamFixture{
	{
		id: "aws-access-key-id:json-unicode-escape", technique: "json-unicode-escape",
		wantRule: "aws-access-key-id",
		// Literal `\uXXXX` text (single backslash) that the transport's JSON
		// encoder doubles to `\\uXXXX` on the wire.
		content: "aws_access_key_id = \"\\u0041\\u004b\\u0049\\u0041\\u0049\\u004f\\u0053\\u0046\\u004f\\u0044\\u004e\\u004e\\u0037\\u0045\\u0058\\u0041\\u004d\\u0050\\u004c\\u0045\"",
	},
	{
		id: "github-pat:double-percent-encoding", technique: "double-percent-encoding",
		wantRule: "github-pat",
		content:  "redirect_uri=https://cb.example/oauth?t=%2567%2568%2570%255F%2531%2532%2533%2534%2535%2536%2537%2538%2539%2530%2561%2562%2563%2564%2565%2566%2541%2542%2543%2544%2545%2546%2531%2532%2533%2534%2535%2536%2537%2538%2539%2530%2561%2562%2563%2564",
	},
	{
		id: "aws-access-key-id:fullwidth", technique: "fullwidth-unicode",
		wantRule: "aws-access-key-id",
		// Fullwidth ASCII variants (U+FF21 …) spelling AKIAIOSFODNN7EXAMPLE.
		content: "locale-exported access key id: ＡＫＩＡＩＯＳＦＯＤＮＮ７ＥＸＡＭＰＬＥ",
	},
	{
		id: "github-pat:quoted-printable", technique: "quoted-printable",
		wantRule: "github-pat",
		content:  "Content-Transfer-Encoding: quoted-printable | X-Auth: =67=68=70=5F=31=32=33=34=35=36=37=38=39=30=61=62=63=64=65=66=41=42=43=44=45=46=31=32=33=34=35=36=37=38=39=30=61=62=63=64",
	},
	{
		id: "aws-access-key-id:whitespace-interleaving", technique: "whitespace-interleaving",
		wantRule: "aws-access-key-id",
		content:  "aws_key = \"AKIA IOSF ODNN 7EXA MPLE\"  # whitespace stripped on load",
	},
	{
		id: "github-pat:yaml-line-continuation", technique: "yaml-line-continuation",
		wantRule: "github-pat",
		// A YAML double-quoted scalar folded with a `\`+newline continuation.
		content: "gh_token: \"ghp_1234567890abcdef\\\nABCDEF1234567890abcd\"",
	},
}

// marshalMessagesBody re-encodes content into an Anthropic /v1/messages request
// body the way the acceptance gate does — content becomes a JSON string value,
// so JSON-level escaping is applied exactly as it is on the wire.
func marshalMessagesBody(t *testing.T, content string) []byte {
	t.Helper()
	body, err := json.Marshal(map[string]any{
		"model":      "claude-3-5-sonnet-20241022",
		"max_tokens": 16,
		"messages":   []map[string]string{{"role": "user", "content": content}},
	})
	if err != nil {
		t.Fatalf("marshal body: %v", err)
	}
	return body
}

// TestRedteamFixturesBlockedThroughProxy is the acceptance test: it drives every
// fixture through the real reverse-proxy handler (not Scan() in-process) the way
// the gate does — JSON-wrapped POST to /v1/messages — and requires masqr to
// block (451) on the un-obfuscated secret. The upstream must never be reached.
func TestRedteamFixturesBlockedThroughProxy(t *testing.T) {
	for _, f := range redteamFixtures {
		t.Run(f.id, func(t *testing.T) {
			var upstreamHit bool
			upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				upstreamHit = true
				w.WriteHeader(http.StatusOK)
			}))
			defer upstream.Close()
			u, _ := url.Parse(upstream.URL)
			h := newProxy(u, log.New(io.Discard, "", 0), Policy{Threshold: SevLow}, nil)

			body := marshalMessagesBody(t, f.content)
			req := httptest.NewRequest(http.MethodPost, "/v1/messages", strings.NewReader(string(body)))
			req.Header.Set("Content-Type", "application/json")
			w := httptest.NewRecorder()
			h.ServeHTTP(w, req)

			if upstreamHit {
				t.Fatalf("technique %q: upstream was reached — the obfuscated secret was not caught\nwire body: %s",
					f.technique, body)
			}
			if w.Code != http.StatusUnavailableForLegalReasons {
				t.Fatalf("technique %q: status = %d, want 451 (blocked)\nwire body: %s",
					f.technique, w.Code, body)
			}
			var be blockedError
			if err := json.Unmarshal(w.Body.Bytes(), &be); err != nil {
				t.Fatalf("decode block body: %v\nraw: %s", err, w.Body.String())
			}
			if !strings.Contains(be.Error.Message, f.wantRule) {
				t.Errorf("technique %q: block message %q does not name rule %q",
					f.technique, be.Error.Message, f.wantRule)
			}
		})
	}
}

// TestRedteamFixturesScannedOnWireBytes asserts the same fixtures at the scanner
// boundary: it scans the exact JSON request bytes (what scanRequest feeds the
// engine) and checks a finding carrying the expected rule prefix is produced.
func TestRedteamFixturesScannedOnWireBytes(t *testing.T) {
	for _, f := range redteamFixtures {
		t.Run(f.id, func(t *testing.T) {
			wire := marshalMessagesBody(t, f.content)
			got := DefaultScanner().Scan(wire)
			var found bool
			for _, m := range got {
				if strings.HasPrefix(m.RuleID, f.wantRule) {
					found = true
					break
				}
			}
			if !found {
				ids := make([]string, 0, len(got))
				for _, m := range got {
					ids = append(ids, m.RuleID)
				}
				t.Fatalf("technique %q: no %q finding in wire bytes %s; got %v",
					f.technique, f.wantRule, wire, ids)
			}
		})
	}
}

// TestFullwidthEscapedForm covers the variant where the transport escapes the
// fullwidth runes as JSON `\uffXX` (e.g. a Python json.dumps with the default
// ensure_ascii) rather than emitting raw UTF-8. masqr must fold either form.
func TestFullwidthEscapedForm(t *testing.T) {
	// Literal `\uffXX` escape text (backtick string → real backslashes), the
	// form a Python json.dumps(ensure_ascii=True) transport leaves on the wire.
	const escaped = `access key id: \uff21\uff2b\uff29\uff21\uff29\uff2f\uff33\uff26\uff2f\uff24\uff2e\uff2e\uff17\uff25\uff38\uff21\uff2d\uff30\uff2c\uff25`
	got := DefaultScanner().Scan([]byte(escaped))
	var found bool
	for _, m := range got {
		if strings.HasPrefix(m.RuleID, "aws-access-key-id") {
			found = true
			break
		}
	}
	if !found {
		t.Fatalf("expected aws-access-key-id from escaped fullwidth, got %+v", got)
	}
}

// TestNormalizeDecodersUnit exercises each new peeler in isolation so a
// regression is attributed precisely, independent of the rule engine.
func TestNormalizeDecodersUnit(t *testing.T) {
	const aws = "AKIAIOSFODNN7EXAMPLE"
	const ghp = "ghp_1234567890abcdefABCDEF1234567890abcd"

	t.Run("double_percent", func(t *testing.T) {
		// One lenient pass turns %2567 into %67 (a single-encoded run).
		got, ok := decodeDoublePercent("%2567%2568%2570")
		if !ok || string(got) != "%67%68%70" {
			t.Fatalf("decodeDoublePercent = %q, %v", got, ok)
		}
	})

	t.Run("fullwidth_raw", func(t *testing.T) {
		got, ok := decodeFullwidth("ＡＫＩＡ")
		if !ok || string(got) != "AKIA" {
			t.Fatalf("decodeFullwidth raw = %q, %v", got, ok)
		}
	})

	t.Run("fullwidth_escaped", func(t *testing.T) {
		got, ok := decodeFullwidth(`\uff21\uff2b\uff29\uff21`)
		if !ok || string(got) != "AKIA" {
			t.Fatalf("decodeFullwidth escaped = %q, %v", got, ok)
		}
	})

	t.Run("quoted_printable", func(t *testing.T) {
		got, ok := decodeQuotedPrintable("=41=4B=49=41")
		if !ok || string(got) != "AKIA" {
			t.Fatalf("decodeQuotedPrintable = %q, %v", got, ok)
		}
		if _, ok := decodeQuotedPrintable("=4G=4H"); ok {
			t.Fatal("decodeQuotedPrintable accepted non-hex octets")
		}
	})

	t.Run("whitespace", func(t *testing.T) {
		got, ok := decodeWhitespaceInterleaved("AKIA IOSF ODNN 7EXA MPLE")
		if !ok || string(got) != aws {
			t.Fatalf("decodeWhitespaceInterleaved = %q, %v", got, ok)
		}
		if _, ok := decodeWhitespaceInterleaved("nowhitespace"); ok {
			t.Fatal("decodeWhitespaceInterleaved fired with nothing to strip")
		}
	})

	t.Run("line_continuation", func(t *testing.T) {
		// JSON-escaped form: literal backslashes followed by `n`.
		got, ok := decodeLineContinuation(`ghp_1234567890abcdef\\\nABCDEF1234567890abcd`)
		if !ok || string(got) != ghp {
			t.Fatalf("decodeLineContinuation escaped = %q, %v", got, ok)
		}
		// Literal-newline form (backslash + real newline).
		got2, ok := decodeLineContinuation("ghp_1234567890abcdef\\\nABCDEF1234567890abcd")
		if !ok || string(got2) != ghp {
			t.Fatalf("decodeLineContinuation newline = %q, %v", got2, ok)
		}
		if _, ok := decodeLineContinuation("plain text with no continuation"); ok {
			t.Fatal("decodeLineContinuation fired with no continuation present")
		}
	})

	t.Run("double_backslash_unicode", func(t *testing.T) {
		got, ok := decodeUnicodeEscapes(`\\u0041\\u004b\\u0049\\u0041`)
		if !ok || got != "AKIA" {
			t.Fatalf("decodeUnicodeEscapes double-backslash = %q, %v", got, ok)
		}
		// Single-backslash form still decodes (no regression).
		got2, ok := decodeUnicodeEscapes(`\u0041\u004b\u0049\u0041`)
		if !ok || got2 != "AKIA" {
			t.Fatalf("decodeUnicodeEscapes single-backslash = %q, %v", got2, ok)
		}
	})
}
