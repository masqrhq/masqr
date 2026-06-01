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
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/pelletier/go-toml/v2"
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

		{"vibe", "mistral", true},
		{"/usr/local/bin/vibe", "mistral", true},
		{"mistral", "mistral", true},
		{"mistral-vibe", "mistral", true},
		{"VIBE", "mistral", true}, // case-insensitive

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

// TestGeminiBlockModelTurn verifies a blocked Gemini :generateContent request
// comes back as a renderable assistant turn — a 200 GenerateContentResponse
// whose model part carries the masqr block advice — rather than an error
// envelope, so the Gemini CLI shows it inline like a normal reply.
func TestGeminiBlockModelTurn(t *testing.T) {
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

	if w.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200 (model turn)", w.Code)
	}
	if w.Header().Get("X-Masqr-Blocked") != "1" {
		t.Errorf("missing X-Masqr-Blocked header")
	}
	// Public Gemini (/v1beta) is the flat GenerateContentResponse shape, not
	// the Code Assist {"response":…} envelope agy/v1internal uses.
	var env struct {
		Candidates []struct {
			Content struct {
				Parts []struct {
					Text string `json:"text"`
				} `json:"parts"`
			} `json:"content"`
		} `json:"candidates"`
	}
	if err := json.Unmarshal(w.Body.Bytes(), &env); err != nil {
		t.Fatalf("decode gemini model turn: %v\nraw: %s", err, w.Body.String())
	}
	if len(env.Candidates) == 0 || len(env.Candidates[0].Content.Parts) == 0 {
		t.Fatalf("no candidate text in model turn: %s", w.Body.String())
	}
	if !strings.Contains(env.Candidates[0].Content.Parts[0].Text, "masqr blocked") {
		t.Errorf("model turn missing block advice: %q", env.Candidates[0].Content.Parts[0].Text)
	}
}

// TestAntigravityProfileUsesCloudCodeURL locks in the plaintext-override path
// for agy: the profile redirects via the CLOUD_CODE_URL env var (the ordinary
// reverse-proxy path) and targets the Code Assist host. masqr is plaintext-only
// — there is no TLS-intercept path anymore.
func TestAntigravityProfileUsesCloudCodeURL(t *testing.T) {
	for _, cmd := range []string{"agy", "antigravity", "/usr/local/bin/agy", "AGY"} {
		p, ok := LookupProvider(cmd)
		if !ok {
			t.Fatalf("LookupProvider(%q): not found", cmd)
		}
		if len(p.EnvVars) != 1 || p.EnvVars[0] != "CLOUD_CODE_URL" {
			t.Errorf("LookupProvider(%q).EnvVars = %v, want [CLOUD_CODE_URL]", cmd, p.EnvVars)
		}
		if p.Target != "https://daily-cloudcode-pa.googleapis.com" {
			t.Errorf("LookupProvider(%q).Target = %q", cmd, p.Target)
		}
		if len(p.Routes) != 1 || p.Routes[0].PathPrefix != "/v1internal" {
			t.Errorf("LookupProvider(%q).Routes = %+v, want one /v1internal route", cmd, p.Routes)
		}
	}
}

// TestAntigravityBlockModelTurn guards agy on the *non-streaming* Code Assist
// path (:generateContent): a blocked request returns a 200 model turn nested
// under "response" (the Code Assist shape) carrying the advice, not an error
// envelope. The streaming path is covered by TestAntigravityStreamBlockReturnsSSE.
func TestAntigravityBlockModelTurn(t *testing.T) {
	agy, _ := LookupProvider("agy")
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		t.Errorf("upstream must not be hit")
	}))
	defer upstream.Close()
	u, _ := url.Parse(upstream.URL)

	policy := Policy{Threshold: SevCritical, Provider: agy}
	h := newProxy(u, log.New(io.Discard, "", 0), policy, nil)

	body := strings.NewReader(`{"contents":[{"parts":[{"text":"key=AKIAIOSFODNN7EXAMPLE"}]}]}`)
	req := httptest.NewRequest(http.MethodPost, "/v1internal:generateContent", body)
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()

	h.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200 (model turn)", w.Code)
	}
	if w.Header().Get("X-Masqr-Blocked") != "1" {
		t.Errorf("missing X-Masqr-Blocked header")
	}
	// Code Assist (/v1internal) nests the GenerateContentResponse under "response".
	var env struct {
		Response struct {
			Candidates []struct {
				Content struct {
					Parts []struct {
						Text string `json:"text"`
					} `json:"parts"`
				} `json:"content"`
			} `json:"candidates"`
		} `json:"response"`
	}
	if err := json.Unmarshal(w.Body.Bytes(), &env); err != nil {
		t.Fatalf("decode nested model turn: %v\nraw: %s", err, w.Body.String())
	}
	if len(env.Response.Candidates) == 0 || len(env.Response.Candidates[0].Content.Parts) == 0 {
		t.Fatalf("no candidate text in nested model turn: %s", w.Body.String())
	}
	if !strings.Contains(env.Response.Candidates[0].Content.Parts[0].Text, "masqr blocked") {
		t.Errorf("model turn missing block advice: %q", env.Response.Candidates[0].Content.Parts[0].Text)
	}
}

// TestAntigravityStreamBlockReturnsSSE locks in the streaming-block behavior:
// a blocked agy …:streamGenerateContent request must come back as a 200
// text/event-stream carrying a synthetic model turn with the advice text (agy
// swallows a JSON 4xx on this path), not the error envelope.
func TestAntigravityStreamBlockReturnsSSE(t *testing.T) {
	agy, _ := LookupProvider("agy")
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		t.Errorf("upstream must not be hit")
	}))
	defer upstream.Close()
	u, _ := url.Parse(upstream.URL)

	policy := Policy{Threshold: SevCritical, Provider: agy}
	h := newProxy(u, log.New(io.Discard, "", 0), policy, nil)

	body := strings.NewReader(`{"contents":[{"parts":[{"text":"key=AKIAIOSFODNN7EXAMPLE"}]}]}`)
	req := httptest.NewRequest(http.MethodPost, "/v1internal:streamGenerateContent?alt=sse", body)
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	h.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200 (agy swallows 4xx on the stream path)", w.Code)
	}
	if ct := w.Header().Get("Content-Type"); ct != "text/event-stream" {
		t.Errorf("content-type = %q, want text/event-stream", ct)
	}
	out := w.Body.String()
	if !strings.HasPrefix(out, "data: ") {
		t.Fatalf("response not SSE-framed: %.40q", out)
	}
	var env struct {
		Response struct {
			Candidates []struct {
				Content struct {
					Parts []struct {
						Text string `json:"text"`
					} `json:"parts"`
				} `json:"content"`
				FinishReason string `json:"finishReason"`
			} `json:"candidates"`
		} `json:"response"`
	}
	payload := strings.TrimSpace(strings.TrimPrefix(out, "data: "))
	if err := json.Unmarshal([]byte(payload), &env); err != nil {
		t.Fatalf("SSE payload is not valid JSON: %v\n%s", err, payload)
	}
	if len(env.Response.Candidates) == 0 || len(env.Response.Candidates[0].Content.Parts) == 0 {
		t.Fatalf("no candidate text in SSE response: %s", payload)
	}
	if env.Response.Candidates[0].FinishReason != "STOP" {
		t.Errorf("finishReason = %q, want STOP", env.Response.Candidates[0].FinishReason)
	}
	txt := env.Response.Candidates[0].Content.Parts[0].Text
	for _, want := range []string{"masqr blocked", "`mask`", "aws"} {
		if !strings.Contains(txt, want) {
			t.Errorf("advice text missing %q; got:\n%s", want, txt)
		}
	}
}

// TestMistralProfileUsesPrepare locks in vibe's redirect contract: vibe has no
// base-URL env var, so the profile carries a Prepare hook (not EnvVars) and
// targets the public Mistral API. A regression to the env-var approach would
// silently no-op (the env var is ignored by vibe) and is guarded here.
func TestMistralProfileUsesPrepare(t *testing.T) {
	for _, cmd := range []string{"vibe", "mistral", "mistral-vibe", "/usr/local/bin/vibe", "VIBE"} {
		p, ok := LookupProvider(cmd)
		if !ok {
			t.Fatalf("LookupProvider(%q): not found", cmd)
		}
		if p.Target != "https://api.mistral.ai" {
			t.Errorf("LookupProvider(%q).Target = %q, want https://api.mistral.ai", cmd, p.Target)
		}
		if p.Prepare == nil {
			t.Errorf("LookupProvider(%q).Prepare is nil; vibe can't be redirected by an env var", cmd)
		}
		if len(p.EnvVars) != 0 {
			t.Errorf("LookupProvider(%q).EnvVars = %v, want none (vibe ignores env base-URL overrides)", cmd, p.EnvVars)
		}
		if !containsFold(p.AuthHeaders, "authorization") {
			t.Errorf("LookupProvider(%q).AuthHeaders missing authorization: %v", cmd, p.AuthHeaders)
		}
	}
}

// TestWriteVibeConfigRewritesAPIBase is the core of the vibe redirect: given a
// real config.toml, the Mistral chat provider's api_base must be rewritten to
// <endpoint>/v1 (the /v1 is required — vibe strips it to derive the SDK
// server_url) while every other provider and setting is preserved.
func TestWriteVibeConfigRewritesAPIBase(t *testing.T) {
	dir := t.TempDir()
	src := filepath.Join(dir, "config.toml")
	const orig = `active_model = "mistral-medium-3.5"
api_timeout = 720.0

[[providers]]
name = "mistral"
api_base = "https://api.mistral.ai/v1"
backend = "mistral"

[[providers]]
name = "llamacpp"
api_base = "http://127.0.0.1:8080/v1"
backend = "generic"

[[tts_providers]]
name = "mistral"
api_base = "https://api.mistral.ai"
`
	if err := os.WriteFile(src, []byte(orig), 0o600); err != nil {
		t.Fatal(err)
	}
	dst := filepath.Join(dir, "out.toml")
	if err := writeVibeConfig(src, dst, "http://127.0.0.1:51234"); err != nil {
		t.Fatalf("writeVibeConfig: %v", err)
	}

	data, err := os.ReadFile(dst)
	if err != nil {
		t.Fatal(err)
	}
	var doc map[string]any
	if err := toml.Unmarshal(data, &doc); err != nil {
		t.Fatalf("decode rewritten config: %v", err)
	}
	provs, _ := doc["providers"].([]any)
	var mistral, llama map[string]any
	for _, p := range provs {
		m := p.(map[string]any)
		switch m["name"] {
		case "mistral":
			mistral = m
		case "llamacpp":
			llama = m
		}
	}
	if mistral == nil {
		t.Fatal("mistral provider missing after rewrite")
	}
	if got := mistral["api_base"]; got != "http://127.0.0.1:51234/v1" {
		t.Errorf("mistral api_base = %v, want http://127.0.0.1:51234/v1", got)
	}
	// Other providers and the chat backend tag must survive untouched.
	if mistral["backend"] != "mistral" {
		t.Errorf("mistral backend changed: %v", mistral["backend"])
	}
	if llama == nil || llama["api_base"] != "http://127.0.0.1:8080/v1" {
		t.Errorf("llamacpp provider altered: %v", llama)
	}
	// The tts_providers Mistral entry must NOT be rewritten (separate array).
	tts, _ := doc["tts_providers"].([]any)
	if len(tts) != 1 || tts[0].(map[string]any)["api_base"] != "https://api.mistral.ai" {
		t.Errorf("tts_providers wrongly modified: %v", tts)
	}
	if doc["active_model"] != "mistral-medium-3.5" {
		t.Errorf("unrelated setting lost: active_model = %v", doc["active_model"])
	}
}

// TestWriteVibeConfigSynthesizesWhenMissing: with no real config (or no mistral
// provider), masqr injects one so the redirect still applies.
func TestWriteVibeConfigSynthesizesWhenMissing(t *testing.T) {
	dir := t.TempDir()
	dst := filepath.Join(dir, "out.toml")
	if err := writeVibeConfig(filepath.Join(dir, "does-not-exist.toml"), dst, "http://127.0.0.1:9000"); err != nil {
		t.Fatalf("writeVibeConfig: %v", err)
	}
	data, _ := os.ReadFile(dst)
	var doc map[string]any
	if err := toml.Unmarshal(data, &doc); err != nil {
		t.Fatal(err)
	}
	provs, _ := doc["providers"].([]any)
	if len(provs) != 1 || provs[0].(map[string]any)["api_base"] != "http://127.0.0.1:9000/v1" {
		t.Fatalf("synthesized mistral provider missing/wrong: %v", provs)
	}
}

// TestPrepareVibeHomeMirrors checks the temp VIBE_HOME: it carries a rewritten
// config.toml and symlinks the user's other files (.env etc.) so auth survives,
// and cleanup removes it without touching the real home.
func TestPrepareVibeHomeMirrors(t *testing.T) {
	realHome := t.TempDir()
	if err := os.WriteFile(filepath.Join(realHome, "config.toml"),
		[]byte("[[providers]]\nname = \"mistral\"\napi_base = \"https://api.mistral.ai/v1\"\nbackend = \"mistral\"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(realHome, ".env"), []byte("MISTRAL_API_KEY=secret\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	t.Setenv("VIBE_HOME", realHome)

	env, cleanup, err := prepareVibeHome("http://127.0.0.1:7777")
	if err != nil {
		t.Fatalf("prepareVibeHome: %v", err)
	}
	defer cleanup()

	if len(env) != 1 || !strings.HasPrefix(env[0], "VIBE_HOME=") {
		t.Fatalf("env = %v, want one VIBE_HOME= entry", env)
	}
	tmpHome := strings.TrimPrefix(env[0], "VIBE_HOME=")
	if tmpHome == realHome {
		t.Fatal("temp VIBE_HOME must differ from the real one")
	}
	// .env must be reachable (symlinked) with the real key.
	if b, rerr := os.ReadFile(filepath.Join(tmpHome, ".env")); rerr != nil || !strings.Contains(string(b), "secret") {
		t.Errorf(".env not mirrored: err=%v body=%q", rerr, b)
	}
	// config.toml must be a rewritten copy, not the original.
	b, _ := os.ReadFile(filepath.Join(tmpHome, "config.toml"))
	if !strings.Contains(string(b), "http://127.0.0.1:7777/v1") {
		t.Errorf("temp config.toml not rewritten: %s", b)
	}
	// The real config.toml must be untouched.
	rb, _ := os.ReadFile(filepath.Join(realHome, "config.toml"))
	if !strings.Contains(string(rb), "https://api.mistral.ai/v1") {
		t.Errorf("real config.toml was modified: %s", rb)
	}

	cleanup()
	if _, serr := os.Stat(tmpHome); !os.IsNotExist(serr) {
		t.Errorf("cleanup did not remove temp VIBE_HOME (%v)", serr)
	}
	if _, serr := os.Stat(realHome); serr != nil {
		t.Errorf("cleanup removed the real home: %v", serr)
	}
}

// TestMistralBlockModelTurn: a blocked vibe /v1/chat/completions request comes
// back as a 200 OpenAI-style chat.completion whose assistant message carries the
// block advice, so vibe renders it inline as a normal reply.
func TestMistralBlockModelTurn(t *testing.T) {
	vibe, _ := LookupProvider("vibe")
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		t.Errorf("upstream must not be hit")
	}))
	defer upstream.Close()
	u, _ := url.Parse(upstream.URL)

	policy := Policy{Threshold: SevCritical, Provider: vibe}
	h := newProxy(u, log.New(io.Discard, "", 0), policy, nil)

	body := strings.NewReader(`{"messages":[{"role":"user","content":"AKIAIOSFODNN7EXAMPLE"}]}`)
	req := httptest.NewRequest(http.MethodPost, "/v1/chat/completions", body)
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()

	h.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200 (model turn)", w.Code)
	}
	if w.Header().Get("X-Masqr-Blocked") != "1" {
		t.Errorf("missing X-Masqr-Blocked header")
	}
	var cc struct {
		Object  string `json:"object"`
		Choices []struct {
			Message struct {
				Role    string `json:"role"`
				Content string `json:"content"`
			} `json:"message"`
			FinishReason string `json:"finish_reason"`
		} `json:"choices"`
	}
	if err := json.Unmarshal(w.Body.Bytes(), &cc); err != nil {
		t.Fatalf("decode chat.completion: %v\nraw: %s", err, w.Body.String())
	}
	if cc.Object != "chat.completion" || len(cc.Choices) == 0 {
		t.Fatalf("not a chat.completion model turn: %s", w.Body.String())
	}
	if cc.Choices[0].Message.Role != "assistant" || !strings.Contains(cc.Choices[0].Message.Content, "masqr blocked") {
		t.Errorf("model turn missing assistant advice: %+v", cc.Choices[0].Message)
	}
}

// TestAgyMaskConsentFlow exercises the full in-chat consent: a block offers
// `mask`, a `mask` reply consents, and a later turn carrying the same value is
// then masked-and-forwarded instead of blocked.
func TestAgyMaskConsentFlow(t *testing.T) {
	agy, _ := LookupProvider("agy")
	var forwarded int
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		forwarded++
		b, _ := io.ReadAll(r.Body)
		if strings.Contains(string(b), "info@example.com") {
			t.Errorf("upstream received the raw email: %s", b)
		}
		w.Header().Set("Content-Type", "text/event-stream")
		_, _ = w.Write([]byte("data: {\"response\":{\"candidates\":[{\"content\":{\"parts\":[{\"text\":\"ok\"}]}}]}}\n\n"))
	}))
	defer upstream.Close()
	// Point agy's /v1internal route at the test upstream so a forwarded
	// (masked) request lands here instead of the real Code Assist host.
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

	// 1. Email trips a block that offers `mask`.
	if w := post("email me at info@example.com"); w.Code != 200 || !strings.Contains(w.Body.String(), "`mask`") {
		t.Fatalf("first turn: want block offering mask; got %d\n%s", w.Code, w.Body.String())
	}
	if forwarded != 0 {
		t.Fatalf("nothing should have been forwarded yet (got %d)", forwarded)
	}
	// 2. `mask` reply consents.
	if w := post("mask"); !strings.Contains(w.Body.String(), "Masking enabled") {
		t.Fatalf("consent turn: want ack; got:\n%s", w.Body.String())
	}
	if forwarded != 0 {
		t.Fatalf("consent ack must not forward (got %d)", forwarded)
	}
	// 3. Re-sending the email is now masked and forwarded (not blocked).
	w := post("email me at info@example.com")
	if w.Code != 200 || strings.Contains(w.Body.String(), "masqr blocked") {
		t.Fatalf("post-consent turn should forward, not block; got %d\n%s", w.Code, w.Body.String())
	}
	if forwarded != 1 {
		t.Fatalf("post-consent turn should forward exactly once; forwarded=%d", forwarded)
	}
}

// TestAnthropicBlockModelTurn: a blocked claude /v1/messages request returns a
// 200 Anthropic Messages object whose assistant text carries the block advice,
// so Claude Code renders it inline rather than as an error.
func TestAnthropicBlockModelTurn(t *testing.T) {
	claude, _ := LookupProvider("claude")
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		t.Errorf("upstream must not be hit")
	}))
	defer upstream.Close()
	u, _ := url.Parse(upstream.URL)

	policy := Policy{Threshold: SevCritical, Provider: claude}
	h := newProxy(u, log.New(io.Discard, "", 0), policy, nil)

	body := strings.NewReader(`{"messages":[{"role":"user","content":"key=AKIAIOSFODNN7EXAMPLE"}]}`)
	req := httptest.NewRequest(http.MethodPost, "/v1/messages", body)
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()

	h.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200 (model turn)", w.Code)
	}
	if w.Header().Get("X-Masqr-Blocked") != "1" {
		t.Errorf("missing X-Masqr-Blocked header")
	}
	var msg struct {
		Type    string `json:"type"`
		Role    string `json:"role"`
		Content []struct {
			Type string `json:"type"`
			Text string `json:"text"`
		} `json:"content"`
	}
	if err := json.Unmarshal(w.Body.Bytes(), &msg); err != nil {
		t.Fatalf("decode anthropic message: %v\nraw: %s", err, w.Body.String())
	}
	if msg.Type != "message" || msg.Role != "assistant" || len(msg.Content) == 0 {
		t.Fatalf("not an assistant message turn: %s", w.Body.String())
	}
	if !strings.Contains(msg.Content[0].Text, "masqr blocked") {
		t.Errorf("model turn missing block advice: %q", msg.Content[0].Text)
	}
}

// TestOpenAIBlockModelTurn: a blocked codex POST /responses comes back as a 200
// Responses object whose output message carries the block advice, so codex
// renders it inline rather than aborting on an error.
func TestOpenAIBlockModelTurn(t *testing.T) {
	codex, _ := LookupProvider("codex")
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		t.Errorf("upstream must not be hit")
	}))
	defer upstream.Close()
	u, _ := url.Parse(upstream.URL)

	policy := Policy{Threshold: SevCritical, Provider: codex}
	h := newProxy(u, log.New(io.Discard, "", 0), policy, nil)

	body := strings.NewReader(`{"input":[{"role":"user","content":[{"type":"input_text","text":"AKIAIOSFODNN7EXAMPLE"}]}]}`)
	req := httptest.NewRequest(http.MethodPost, "/v1/responses", body)
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()

	h.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200 (model turn)", w.Code)
	}
	if w.Header().Get("X-Masqr-Blocked") != "1" {
		t.Errorf("missing X-Masqr-Blocked header")
	}
	var resp struct {
		Object string `json:"object"`
		Output []struct {
			Type    string `json:"type"`
			Role    string `json:"role"`
			Content []struct {
				Type string `json:"type"`
				Text string `json:"text"`
			} `json:"content"`
		} `json:"output"`
	}
	if err := json.Unmarshal(w.Body.Bytes(), &resp); err != nil {
		t.Fatalf("decode responses object: %v\nraw: %s", err, w.Body.String())
	}
	if resp.Object != "response" || len(resp.Output) == 0 || len(resp.Output[0].Content) == 0 {
		t.Fatalf("not a responses model turn: %s", w.Body.String())
	}
	if !strings.Contains(resp.Output[0].Content[0].Text, "masqr blocked") {
		t.Errorf("model turn missing block advice: %q", resp.Output[0].Content[0].Text)
	}
}

// TestGenericBlockEnvelopeFallback guards that an unknown provider (no model-turn
// support) still gets the plain Anthropic-shaped 451 block envelope — the
// fallback path writeBlockResponse serves for non-interactive providers and for
// non-chat endpoints.
func TestGenericBlockEnvelopeFallback(t *testing.T) {
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		t.Errorf("upstream must not be hit")
	}))
	defer upstream.Close()
	u, _ := url.Parse(upstream.URL)

	policy := Policy{Threshold: SevCritical, Provider: genericProvider}
	h := newProxy(u, log.New(io.Discard, "", 0), policy, nil)

	body := strings.NewReader(`{"prompt":"key=AKIAIOSFODNN7EXAMPLE"}`)
	req := httptest.NewRequest(http.MethodPost, "/v1/messages", body)
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()

	h.ServeHTTP(w, req)

	if w.Code != http.StatusUnavailableForLegalReasons {
		t.Fatalf("status = %d, want 451", w.Code)
	}
	var be blockedError
	if err := json.Unmarshal(w.Body.Bytes(), &be); err != nil {
		t.Fatalf("decode block envelope: %v", err)
	}
	if be.Type != "error" || be.Error.Type != "masqr_blocked" {
		t.Errorf("generic block envelope changed: %+v", be)
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

	// A URL-borne key can't be masked in place (rewriting the path would still
	// ship the key upstream), so it blocks — now surfaced as a model turn, with
	// the X-Masqr-Blocked marker and no upstream hit.
	if w.Header().Get("X-Masqr-Blocked") != "1" {
		t.Fatalf("URL-borne key should have been blocked; no X-Masqr-Blocked marker, got %d", w.Code)
	}
	if strings.Contains(logbuf.String(), "AIzaSyAabcdefghijklmnopqrstuvwxyz123456") {
		t.Errorf("log contained raw API key — redaction failed:\n%s", logbuf.String())
	}
}
