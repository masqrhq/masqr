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

// TestLookupProviderMatchesBasenames covers the path-stripping behaviour:
// users installing the Gemini CLI via npm get something like
// `~/.npm-global/bin/gemini`, while system-package installs are at
// `/usr/local/bin/gemini`. Both must resolve.
func TestLookupProviderMatchesBasenames(t *testing.T) {
	cases := []struct {
		cmd      string
		wantName string
		wantHit  bool
	}{
		{"claude", "anthropic", true},
		{"/usr/local/bin/claude", "anthropic", true},
		{"claude-code", "anthropic", true},

		{"gemini", "google-gemini", true},
		{"/home/me/.npm-global/bin/gemini", "google-gemini", true},
		{"GEMINI", "google-gemini", true}, // case-insensitive
		{"C:\\tools\\gemini.exe", "google-gemini", true},
		{"gemini-cli", "google-gemini", true},

		{"codex", "openai", true},
		{"openai", "openai", true},

		{"vim", "generic", false}, // unknown → generic fallback
		{"/usr/local/bin/some-llm", "generic", false},
	}
	for _, c := range cases {
		p, ok := LookupProvider(c.cmd)
		if ok != c.wantHit {
			t.Errorf("LookupProvider(%q) ok = %v, want %v", c.cmd, ok, c.wantHit)
		}
		if p.Name != c.wantName {
			t.Errorf("LookupProvider(%q) name = %q, want %q", c.cmd, p.Name, c.wantName)
		}
	}
}

// TestGeminiProviderTarget asserts the on-disk profile points at the public
// Gemini endpoint and reads the SDK-native env var. A regression here means
// `masqr gemini` silently routes traffic to the wrong service.
func TestGeminiProviderTarget(t *testing.T) {
	p, ok := LookupProvider("gemini")
	if !ok {
		t.Fatal("gemini profile missing")
	}
	if want := "https://generativelanguage.googleapis.com"; p.Target != want {
		t.Errorf("gemini target = %q, want %q", p.Target, want)
	}
	if !containsFold(p.EnvVars, "GOOGLE_GEMINI_BASE_URL") {
		t.Errorf("gemini EnvVars missing GOOGLE_GEMINI_BASE_URL: %v", p.EnvVars)
	}
	// The OAuth/CodeAssist path env var is the whole reason we ship a
	// second one — without it, free-tier Gemini CLI users (Google
	// sign-in, no API key) bypass the proxy entirely. Guard it here so
	// nobody silently drops it.
	if !containsFold(p.EnvVars, "CODE_ASSIST_ENDPOINT") {
		t.Errorf("gemini EnvVars missing CODE_ASSIST_ENDPOINT: %v", p.EnvVars)
	}
	if !containsFold(p.AuthHeaders, "x-goog-api-key") {
		t.Errorf("gemini AuthHeaders missing x-goog-api-key: %v", p.AuthHeaders)
	}
	if !containsFold(p.AuthQueryParams, "key") {
		t.Errorf("gemini AuthQueryParams missing 'key': %v", p.AuthQueryParams)
	}
	// Routes carry the Code Assist upstream; without this entry the
	// /v1internal* calls would all route to generativelanguage and 404.
	var hasCodeAssistRoute bool
	for _, r := range p.Routes {
		if r.PathPrefix == "/v1internal" &&
			r.Target == "https://cloudcode-pa.googleapis.com" {
			hasCodeAssistRoute = true
		}
	}
	if !hasCodeAssistRoute {
		t.Errorf("gemini Routes missing /v1internal → cloudcode-pa.googleapis.com: %+v", p.Routes)
	}
}

func containsFold(ss []string, want string) bool {
	for _, s := range ss {
		if strings.EqualFold(s, want) {
			return true
		}
	}
	return false
}

// TestRedactHeadersIncludesProviderKeys guards against new providers being
// added in providers.go without their auth headers reaching the global
// redaction set.
func TestRedactHeadersIncludesProviderKeys(t *testing.T) {
	for _, h := range []string{"x-goog-api-key", "x-api-key", "anthropic-api-key", "authorization"} {
		if _, ok := redactHeaders[h]; !ok {
			t.Errorf("redactHeaders missing %q", h)
		}
	}
}

// TestRedactRequestURIStripsGeminiKey covers the canonical Gemini-CLI URL
// shape `?key=AIza…`. The unredacted URL must still go upstream (we don't
// mutate the request); only the log-side string is redacted.
func TestRedactRequestURIStripsGeminiKey(t *testing.T) {
	raw := "/v1beta/models/gemini-1.5-pro:generateContent?key=AIzaSyA-secret-value-123456&alt=sse"
	u, err := url.Parse(raw)
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	got := redactRequestURI(u)
	if strings.Contains(got, "AIza") {
		t.Errorf("redactRequestURI leaked key: %s", got)
	}
	if !strings.Contains(got, "key=%3Credacted%3E") && !strings.Contains(got, "key=<redacted>") {
		t.Errorf("redactRequestURI did not redact key: %s", got)
	}
	if !strings.Contains(got, "alt=sse") {
		t.Errorf("redactRequestURI dropped harmless params: %s", got)
	}
}

// TestRedactRequestURIPassthroughForNoAuth keeps URIs without auth params
// byte-for-byte intact — the log line stays readable, no allocation overhead.
func TestRedactRequestURIPassthroughForNoAuth(t *testing.T) {
	raw := "/v1/messages?stream=true"
	u, _ := url.Parse(raw)
	if got := redactRequestURI(u); got != raw {
		t.Errorf("redactRequestURI(%q) = %q, want unchanged", raw, got)
	}
}

// TestScanRequestCatchesURLKey is the *behavioural* counterpart to the
// URL-redaction test: a leaked GCP key in the URL must trigger the scanner
// and produce a block, just like one smuggled in the body.
func TestScanRequestCatchesURLKey(t *testing.T) {
	u, _ := url.Parse("/v1beta/models/gemini-1.5-pro:generateContent?key=AIzaSyAabcdefghijklmnopqrstuvwxyz123456")
	matches := scanRequest(u, []byte(`{"contents":[{"parts":[{"text":"hello"}]}]}`))
	if len(matches) == 0 {
		t.Fatalf("expected URL-borne API key to be flagged, got 0 matches")
	}
	var hit bool
	for _, m := range matches {
		// gcp-api-key is the built-in rule ID for `AIza…` keys.
		if m.RuleID == "gcp-api-key" {
			hit = true
		}
	}
	if !hit {
		t.Errorf("expected gcp-api-key rule to fire, got: %+v", matches)
	}
}

// TestGeminiBlockEnvelopeShape verifies the policy emits Google's
// rpc.Status envelope (and a 451) when the request is bound for Gemini —
// not the Anthropic envelope. This is what lets the Gemini CLI render the
// reason through its native error renderer.
func TestGeminiBlockEnvelopeShape(t *testing.T) {
	gemini, _ := LookupProvider("gemini")
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		t.Errorf("upstream must not be hit")
	}))
	defer upstream.Close()
	u, _ := url.Parse(upstream.URL)

	policy := Policy{Threshold: SevCritical, Provider: gemini}
	h := newProxy(u, log.New(io.Discard, "", 0), policy, nil)

	body := strings.NewReader(`{"contents":[{"parts":[{"text":"key=AKIAIOSFODNN7EXAMPLE"}]}]}`)
	req := httptest.NewRequest(http.MethodPost, "/v1beta/models/gemini-1.5-pro:generateContent", body)
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()

	h.ServeHTTP(w, req)

	if w.Code != http.StatusUnavailableForLegalReasons {
		t.Fatalf("status = %d, want 451", w.Code)
	}

	var ge googleBlockedError
	if err := json.Unmarshal(w.Body.Bytes(), &ge); err != nil {
		t.Fatalf("decode google envelope: %v\nraw: %s", err, w.Body.String())
	}
	if ge.Error.Code == 0 || ge.Error.Status == "" {
		t.Errorf("google envelope missing code/status: %+v", ge.Error)
	}
	if !strings.Contains(ge.Error.Message, "masqr") {
		t.Errorf("google envelope message missing masqr tag: %q", ge.Error.Message)
	}
	if len(ge.Error.Details) == 0 || len(ge.Error.Details[0].Findings) == 0 {
		t.Errorf("google envelope details/findings empty: %+v", ge.Error.Details)
	}

	// And confirm it does NOT parse as the Anthropic envelope's
	// distinctive top-level "type" field — important so the Gemini SDK
	// never gets a shape it can't parse.
	var be blockedError
	if err := json.Unmarshal(w.Body.Bytes(), &be); err == nil && be.Type == "error" {
		t.Errorf("body parsed as Anthropic envelope when it should be Google-shaped")
	}
}

// TestAntigravityBlockEnvelopeShape guards the agy fix: a blocked Antigravity
// request must return the Google error envelope (not the Anthropic default,
// which agy's Code Assist client can't parse — it rendered as a generic
// "Agent execution terminated due to error"), at HTTP 400 so the message is
// surfaced to the user.
func TestAntigravityBlockEnvelopeShape(t *testing.T) {
	agy, _ := LookupProvider("agy")
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		t.Errorf("upstream must not be hit")
	}))
	defer upstream.Close()
	u, _ := url.Parse(upstream.URL)

	policy := Policy{Threshold: SevCritical, Provider: agy}
	h := newProxy(u, log.New(io.Discard, "", 0), policy, nil)

	body := strings.NewReader(`{"contents":[{"parts":[{"text":"key=AKIAIOSFODNN7EXAMPLE"}]}]}`)
	req := httptest.NewRequest(http.MethodPost, "/v1internal:streamGenerateContent", body)
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()

	h.ServeHTTP(w, req)

	if w.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want 400 (so agy shows the message)", w.Code)
	}
	var ge googleBlockedError
	if err := json.Unmarshal(w.Body.Bytes(), &ge); err != nil {
		t.Fatalf("decode google envelope: %v\nraw: %s", err, w.Body.String())
	}
	if ge.Error.Status != "INVALID_ARGUMENT" {
		t.Errorf("status = %q, want INVALID_ARGUMENT", ge.Error.Status)
	}
	if !strings.Contains(ge.Error.Message, "masqr blocked") {
		t.Errorf("message missing masqr reason: %q", ge.Error.Message)
	}
	// Must NOT be the Anthropic shape agy can't read.
	var be blockedError
	if err := json.Unmarshal(w.Body.Bytes(), &be); err == nil && be.Type == "error" {
		t.Errorf("body parsed as Anthropic envelope; agy needs the Google shape")
	}
}

// TestAnthropicBlockEnvelopeUnchanged is the regression guard for the
// historical envelope. Default provider (no profile / claude) keeps the
// Anthropic shape — Claude Code's renderer depends on it.
func TestAnthropicBlockEnvelopeUnchanged(t *testing.T) {
	claude, _ := LookupProvider("claude")
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		t.Errorf("upstream must not be hit")
	}))
	defer upstream.Close()
	u, _ := url.Parse(upstream.URL)

	policy := Policy{Threshold: SevCritical, Provider: claude}
	h := newProxy(u, log.New(io.Discard, "", 0), policy, nil)

	body := strings.NewReader(`{"prompt":"key=AKIAIOSFODNN7EXAMPLE"}`)
	req := httptest.NewRequest(http.MethodPost, "/v1/messages", body)
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()

	h.ServeHTTP(w, req)

	var be blockedError
	if err := json.Unmarshal(w.Body.Bytes(), &be); err != nil {
		t.Fatalf("decode anthropic envelope: %v", err)
	}
	if be.Type != "error" || be.Error.Type != "masqr_blocked" {
		t.Errorf("anthropic envelope changed: %+v", be)
	}
}

// TestOpenAIBlockEnvelopeShape covers the codex/openai branch end-to-end so
// adding a third provider doesn't accidentally fall through to Anthropic.
func TestOpenAIBlockEnvelopeShape(t *testing.T) {
	codex, _ := LookupProvider("codex")
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		t.Errorf("upstream must not be hit")
	}))
	defer upstream.Close()
	u, _ := url.Parse(upstream.URL)

	policy := Policy{Threshold: SevCritical, Provider: codex}
	h := newProxy(u, log.New(io.Discard, "", 0), policy, nil)

	body := strings.NewReader(`{"messages":[{"role":"user","content":"AKIAIOSFODNN7EXAMPLE"}]}`)
	req := httptest.NewRequest(http.MethodPost, "/v1/chat/completions", body)
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()

	h.ServeHTTP(w, req)

	var oe openAIBlockedError
	if err := json.Unmarshal(w.Body.Bytes(), &oe); err != nil {
		t.Fatalf("decode openai envelope: %v", err)
	}
	if oe.Error.Type != "masqr_blocked" || oe.Error.Code != "masqr_blocked" {
		t.Errorf("openai envelope changed: %+v", oe)
	}
	if len(oe.Error.Findings) == 0 {
		t.Errorf("openai envelope missing findings")
	}
}

// TestGeminiOAuthPathRoutesToCodeAssist is the critical regression: with
// the Gemini profile, requests whose path starts with `/v1internal` must
// reach the *Code Assist* upstream, not the public Gemini API host. The
// OAuth/free-tier code path inside the Gemini CLI emits these paths and
// honours only CODE_ASSIST_ENDPOINT — a single-upstream proxy with no
// per-path routing would silently 404 every OAuth user.
func TestGeminiOAuthPathRoutesToCodeAssist(t *testing.T) {
	var gotPath, gotHost string
	codeAssist := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotPath = r.URL.Path
		gotHost = r.Host
		w.WriteHeader(http.StatusOK)
	}))
	defer codeAssist.Close()

	// We use the public-API upstream as a *sink that must NOT receive
	// the call*. If our routing is broken the call lands here and the
	// assertion below catches it.
	publicAPI := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		t.Errorf("/v1internal call leaked to public API upstream %s", r.URL.Path)
	}))
	defer publicAPI.Close()

	publicURL, _ := url.Parse(publicAPI.URL)
	gemini, _ := LookupProvider("gemini")
	gemini.Target = publicAPI.URL
	gemini.Routes = []Route{{PathPrefix: "/v1internal", Target: codeAssist.URL}}

	policy := Policy{Threshold: SevCritical, Provider: gemini}
	h := newProxy(publicURL, log.New(io.Discard, "", 0), policy, nil)

	req := httptest.NewRequest(http.MethodPost,
		"/v1internal:loadCodeAssist",
		strings.NewReader(`{"metadata":{"ideType":"IDE_UNSPECIFIED"}}`))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	h.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200", w.Code)
	}
	if gotPath != "/v1internal:loadCodeAssist" {
		t.Errorf("upstream saw path %q, want %q", gotPath, "/v1internal:loadCodeAssist")
	}
	// Host header must reflect the Code Assist upstream, otherwise TLS
	// SNI / virtual-host routing breaks against real Google endpoints.
	caURL, _ := url.Parse(codeAssist.URL)
	if gotHost != caURL.Host {
		t.Errorf("upstream Host = %q, want %q", gotHost, caURL.Host)
	}
}

// TestGeminiAPIPathRoutesToPublicEndpoint is the converse guard: requests
// outside the route table fall through to the primary upstream. Without
// this the per-path routing could collapse into "everything goes to Code
// Assist" and break API-key users.
func TestGeminiAPIPathRoutesToPublicEndpoint(t *testing.T) {
	var publicHit, codeAssistHit bool
	publicAPI := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		publicHit = true
		w.WriteHeader(http.StatusOK)
	}))
	defer publicAPI.Close()
	codeAssist := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		codeAssistHit = true
	}))
	defer codeAssist.Close()

	publicURL, _ := url.Parse(publicAPI.URL)
	gemini, _ := LookupProvider("gemini")
	gemini.Target = publicAPI.URL
	gemini.Routes = []Route{{PathPrefix: "/v1internal", Target: codeAssist.URL}}

	policy := Policy{Threshold: SevCritical, Provider: gemini}
	h := newProxy(publicURL, log.New(io.Discard, "", 0), policy, nil)

	req := httptest.NewRequest(http.MethodPost,
		"/v1beta/models/gemini-1.5-pro:generateContent",
		strings.NewReader(`{"contents":[]}`))
	w := httptest.NewRecorder()
	h.ServeHTTP(w, req)

	if !publicHit {
		t.Error("public API upstream was not hit")
	}
	if codeAssistHit {
		t.Error("Code Assist upstream wrongly received a /v1beta call")
	}
}

// TestGeminiURLKeyBlocksRequest is the full-stack test: an unsuspecting
// dev pastes a Gemini key into the URL of a request, the policy blocks
// upstream traffic, AND the log line carries the redacted form.
func TestGeminiURLKeyBlocksRequest(t *testing.T) {
	gemini, _ := LookupProvider("gemini")
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		t.Errorf("upstream hit despite URL-borne key")
	}))
	defer upstream.Close()
	u, _ := url.Parse(upstream.URL)

	var logbuf strings.Builder
	policy := Policy{Threshold: SevLow, Provider: gemini}
	h := newProxy(u, log.New(&logbuf, "", 0), policy, nil)

	req := httptest.NewRequest(http.MethodPost,
		"/v1beta/models/gemini-1.5-pro:generateContent?key=AIzaSyAabcdefghijklmnopqrstuvwxyz123456",
		strings.NewReader(`{"contents":[]}`))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()

	h.ServeHTTP(w, req)

	if w.Code != http.StatusUnavailableForLegalReasons {
		t.Fatalf("URL-borne key should have been blocked, got %d", w.Code)
	}
	if strings.Contains(logbuf.String(), "AIzaSyAabcdefghijklmnopqrstuvwxyz123456") {
		t.Errorf("log contained raw API key — redaction failed:\n%s", logbuf.String())
	}
}
