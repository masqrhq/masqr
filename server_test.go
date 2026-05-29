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

// TestWebSocketUpgradeReturns501 pins the short-circuit that keeps
// codex (and any other CLI that probes `ws://` before HTTPS) from
// stalling on the WebSocket handshake. masqr can't proxy WS frames, so
// the right thing is a hard 501 — codex's HTTPS fallback then kicks in
// immediately instead of waiting ~45s per retry.
func TestWebSocketUpgradeReturns501(t *testing.T) {
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		t.Errorf("upstream must not be hit on a WS upgrade")
	}))
	defer upstream.Close()
	u, _ := url.Parse(upstream.URL)
	h := newProxy(u, log.New(io.Discard, "", 0), Policy{Threshold: SevCritical})

	req := httptest.NewRequest(http.MethodGet, "/responses", nil)
	req.Header.Set("Connection", "Upgrade")
	req.Header.Set("Upgrade", "websocket")
	req.Header.Set("Sec-WebSocket-Version", "13")
	req.Header.Set("Sec-WebSocket-Key", "IkLRIYd4zzS8uE5PIik0Zg==")

	w := httptest.NewRecorder()
	h.ServeHTTP(w, req)

	// 404 is intentional — it's the only status that triggers codex's
	// native "Falling back from WebSockets to HTTPS transport" path
	// without retries (5xx retries, other 4xx is treated as fatal).
	if w.Code != http.StatusNotFound {
		t.Fatalf("status = %d, want 404 on WS upgrade; body=%q", w.Code, w.Body.String())
	}
}

// TestRequestHeadersAreNotScanned pins the invariant that masqr never
// feeds HTTP request headers into the rule engine. Headers carry CLI
// bookkeeping (session/turn IDs, auth tokens, originator strings) that
// CLIs stamp on every call and which masqr has no business flagging.
// Only URL + (decoded) body should reach the scanner.
func TestRequestHeadersAreNotScanned(t *testing.T) {
	// Put a value that would obviously trip a built-in rule into a
	// custom header. The body is benign.
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	defer upstream.Close()
	u, _ := url.Parse(upstream.URL)
	h := newProxy(u, log.New(io.Discard, "", 0), Policy{Threshold: SevLow})

	body := strings.NewReader(`{"prompt":"hello"}`)
	req := httptest.NewRequest(http.MethodPost, "/v1/messages", body)
	req.Header.Set("Content-Type", "application/json")
	// These would all trip the rule engine if headers were scanned.
	req.Header.Set("Authorization", "Bearer AKIAIOSFODNN7EXAMPLE")
	req.Header.Set("X-Custom-Email", "leak@example.com")
	req.Header.Set("X-Codex-Turn-Metadata",
		`{"session_id":"019e6eea-2d92-7c72-9cb2-0c42d39e73f3"}`)

	w := httptest.NewRecorder()
	h.ServeHTTP(w, req)

	if w.Code == http.StatusUnavailableForLegalReasons {
		t.Fatalf("request blocked — masqr must not scan HTTP headers; body=%q",
			w.Body.String())
	}
}

// TestPolicyBlockReturns451 verifies that a critical finding intercepts the
// request and never forwards it upstream.
func TestPolicyBlockReturns451(t *testing.T) {
	var upstreamHit bool
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		upstreamHit = true
		w.WriteHeader(http.StatusOK)
	}))
	defer upstream.Close()
	u, _ := url.Parse(upstream.URL)

	policy := Policy{Threshold: SevCritical}
	h := newProxy(u, log.New(io.Discard, "", 0), policy)

	// AWS access key ID is `critical`/`secret` in defaultRules — should trip.
	body := strings.NewReader(`{"prompt": "key=AKIAIOSFODNN7EXAMPLE"}`)
	req := httptest.NewRequest(http.MethodPost, "/v1/messages", body)
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()

	h.ServeHTTP(w, req)

	if upstreamHit {
		t.Fatalf("upstream was hit even though policy should have intercepted")
	}
	if w.Code != http.StatusUnavailableForLegalReasons {
		t.Fatalf("status = %d, want 451", w.Code)
	}
	if got := w.Header().Get("X-Masqr-Blocked"); got != "1" {
		t.Errorf("X-Masqr-Blocked = %q, want %q", got, "1")
	}

	var be blockedError
	if err := json.Unmarshal(w.Body.Bytes(), &be); err != nil {
		t.Fatalf("decode body: %v\nraw: %s", err, w.Body.String())
	}
	if be.Type != "error" || be.Error.Type != "masqr_blocked" {
		t.Errorf("envelope type=%q error.type=%q, want error/masqr_blocked", be.Type, be.Error.Type)
	}
	if len(be.Error.Findings) == 0 {
		t.Error("expected at least one finding in error body")
	}
	if !strings.Contains(be.Error.Message, "aws-access-key-id") {
		t.Errorf("message should name the tripping rule, got: %q", be.Error.Message)
	}
}

// TestPolicyThresholdFiltersBelowFloor ensures only matches at or above the
// configured threshold trigger a block — a medium-only alert should NOT block
// when --block-on=critical.
func TestPolicyThresholdFiltersBelowFloor(t *testing.T) {
	var upstreamHit bool
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		upstreamHit = true
	}))
	defer upstream.Close()
	u, _ := url.Parse(upstream.URL)

	policy := Policy{Threshold: SevCritical}
	h := newProxy(u, log.New(io.Discard, "", 0), policy)

	// email-address rule is medium/pii — below the critical floor.
	body := strings.NewReader(`{"prompt": "contact me at someone@example.com please"}`)
	req := httptest.NewRequest(http.MethodPost, "/v1/messages", body)
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()

	h.ServeHTTP(w, req)

	if !upstreamHit {
		t.Fatal("upstream should have been hit — medium severity is below critical threshold")
	}
}

func TestParseSeverity(t *testing.T) {
	cases := []struct {
		in   string
		want Severity
		ok   bool
	}{
		{"critical", SevCritical, true},
		{"HIGH", SevHigh, true},
		{"  medium  ", SevMedium, true},
		{"low", SevLow, true},
		{"none", "", false},
		{"", "", false},
	}
	for _, c := range cases {
		got, err := ParseSeverity(c.in)
		if c.ok && (err != nil || got != c.want) {
			t.Errorf("ParseSeverity(%q) = (%q,%v), want (%q,nil)", c.in, got, err, c.want)
		}
		if !c.ok && err == nil {
			t.Errorf("ParseSeverity(%q) should have errored", c.in)
		}
	}
}
