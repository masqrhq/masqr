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
	"io"
	"log"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
)

// TestExternalSourcesPopulateIdentity ensures gitleaks and presidio digit-id
// matches carry stable Identity fingerprints so interactive mask-and-continue
// can offer `mask` (see maskableIdentities in consent.go).
func TestExternalSourcesPopulateIdentity(t *testing.T) {
	t.Run("gitleaks-slack", func(t *testing.T) {
		src, err := newGitleaksSource()
		if err != nil {
			t.Fatalf("newGitleaksSource: %v", err)
		}
		body := []byte(`token = "xoxb-86271706642-89779378365-IBsZm5gV"`)
		var slack []Match
		for _, m := range src.Scan(body) {
			if strings.Contains(m.RuleID, "slack") {
				slack = append(slack, m)
			}
		}
		if len(slack) == 0 {
			t.Fatal("expected gitleaks to flag slack token")
		}
		if ids := maskableIdentities(slack); len(ids) == 0 {
			t.Fatalf("slack matches not maskable: %+v", slack)
		}
	})

	t.Run("digit-id-de-tax", func(t *testing.T) {
		src := newDigitIDSource()
		body := []byte("Steuer-ID 12345678903 ok")
		var de []Match
		for _, m := range src.Scan(body) {
			if m.RuleID == "de-tax-id" {
				de = append(de, m)
			}
		}
		if len(de) == 0 {
			t.Fatal("expected de-tax-id match")
		}
		if ids := maskableIdentities(de); len(ids) == 0 {
			t.Fatalf("de-tax-id match not maskable: %+v", de)
		}
	})
}

// TestAgyMaskConsentFlowGitleaks is the round-5 regression: a gitleaks slack
// finding must offer `mask`, consent must stick, and the value must not reach
// upstream in the clear.
func TestAgyMaskConsentFlowGitleaks(t *testing.T) {
	const token = "xoxb-86271706642-89779378365-IBsZm5gV"
	agy, _ := LookupProvider("agy")
	var forwarded int
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		forwarded++
		b, _ := io.ReadAll(r.Body)
		if strings.Contains(string(b), token) {
			t.Errorf("upstream received the raw slack token: %s", b)
		}
		w.Header().Set("Content-Type", "text/event-stream")
		_, _ = w.Write([]byte("data: {\"response\":{\"candidates\":[{\"content\":{\"parts\":[{\"text\":\"ok\"}]}}]}}\n\n"))
	}))
	defer upstream.Close()
	agy.Routes = []Route{{PathPrefix: "/v1internal", Target: upstream.URL}}
	agy.Target = upstream.URL
	u, _ := url.Parse(upstream.URL)
	h := newProxy(u, log.New(io.Discard, "", 0), Policy{Threshold: SevLow, Provider: agy}, nil)

	post := func(text string) *httptest.ResponseRecorder {
		body := `{"contents":[{"role":"user","parts":[{"text":"<USER_REQUEST>\n` + text + `\n</USER_REQUEST>"}]}]}`
		req := httptest.NewRequest(http.MethodPost, "/v1internal:streamGenerateContent?alt=sse", strings.NewReader(body))
		req.Header.Set("Content-Type", "application/json")
		w := httptest.NewRecorder()
		h.ServeHTTP(w, req)
		return w
	}

	if w := post(`token = "` + token + `"`); w.Code != 200 || !strings.Contains(w.Body.String(), "`mask`") {
		t.Fatalf("first turn: want block offering mask; got %d\n%s", w.Code, w.Body.String())
	}
	if forwarded != 0 {
		t.Fatalf("nothing should have been forwarded yet (got %d)", forwarded)
	}
	if w := post("mask"); !strings.Contains(w.Body.String(), "Masking enabled") {
		t.Fatalf("consent turn: want ack; got:\n%s", w.Body.String())
	}
	w := post(`token = "` + token + `"`)
	if w.Code != 200 || strings.Contains(w.Body.String(), "masqr blocked") {
		t.Fatalf("post-consent turn should forward, not block; got %d\n%s", w.Code, w.Body.String())
	}
	if forwarded != 1 {
		t.Fatalf("post-consent turn should forward exactly once; forwarded=%d", forwarded)
	}
}
