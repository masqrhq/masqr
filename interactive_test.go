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
	"io"
	"log"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"

	"github.com/klauspost/compress/zstd"
)

// TestLatestUserTextFor confirms each provider's request-body format is parsed
// down to the most recent user-authored text, so a bare `mask` reply is
// recognizable regardless of which CLI is wrapped.
func TestLatestUserTextFor(t *testing.T) {
	cases := []struct {
		name     string
		provider string
		body     string
		want     string
	}{
		{
			name:     "anthropic string content",
			provider: "anthropic",
			body:     `{"messages":[{"role":"user","content":"hi"},{"role":"assistant","content":"yo"},{"role":"user","content":"mask"}]}`,
			want:     "mask",
		},
		{
			name:     "anthropic array content",
			provider: "anthropic",
			body:     `{"messages":[{"role":"user","content":[{"type":"text","text":"ma"},{"type":"text","text":"sk"}]}]}`,
			want:     "mask",
		},
		{
			name:     "mistral chat messages",
			provider: "mistral",
			body:     `{"messages":[{"role":"system","content":"x"},{"role":"user","content":"mask"}]}`,
			want:     "mask",
		},
		{
			name:     "openai responses array input",
			provider: "openai",
			body:     `{"input":[{"role":"user","content":[{"type":"input_text","text":"mask"}]}]}`,
			want:     "mask",
		},
		{
			name:     "openai responses string input",
			provider: "openai",
			body:     `{"input":"mask"}`,
			want:     "mask",
		},
		{
			name:     "github-copilot responses input",
			provider: "github-copilot",
			body:     `{"model":"gpt-5-mini","input":[{"role":"user","content":[{"type":"input_text","text":"mask"}]}]}`,
			want:     "mask",
		},
		{
			name:     "gemini contents",
			provider: "google-gemini",
			body:     `{"contents":[{"role":"user","parts":[{"text":"mask"}]}]}`,
			want:     "mask",
		},
		{
			name:     "antigravity nested request",
			provider: "antigravity",
			body:     `{"request":{"contents":[{"role":"user","parts":[{"text":"mask"}]}]}}`,
			want:     "mask",
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := latestUserTextFor(tc.provider, []byte(tc.body)); got != tc.want {
				t.Errorf("latestUserTextFor(%s) = %q, want %q", tc.provider, got, tc.want)
			}
		})
	}
}

func mustZstd(t *testing.T, b []byte) []byte {
	t.Helper()
	enc, err := zstd.NewWriter(nil)
	if err != nil {
		t.Fatalf("zstd writer: %v", err)
	}
	defer enc.Close()
	return enc.EncodeAll(b, nil)
}

// runMaskFlow exercises the full interactive consent loop for one provider: a
// flagged value blocks (offering `mask`), a `mask` reply consents, and resending
// the same value is then masked-and-forwarded instead of blocked. makeBody wraps
// a turn's text in the provider's request shape (and may compress it).
func runMaskFlow(t *testing.T, providerName, path string, hdr map[string]string, makeBody func(text string) []byte) {
	t.Helper()
	p, ok := LookupProvider(providerName)
	if !ok {
		t.Fatalf("LookupProvider(%q): not found", providerName)
	}
	var forwarded int
	var rawSeen bool
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		forwarded++
		b, _ := io.ReadAll(r.Body)
		// We forward masked requests uncompressed (Content-Encoding stripped),
		// so a plain substring check is enough to catch a leaked raw value.
		if strings.Contains(string(b), "info@example.com") {
			rawSeen = true
		}
		w.Header().Set("Content-Type", "text/event-stream")
		_, _ = w.Write([]byte("data: {}\n\n"))
	}))
	defer upstream.Close()
	p.Target = upstream.URL
	p.Routes = nil // force fall-through to the test upstream
	u, _ := url.Parse(upstream.URL)
	h := newProxy(u, log.New(io.Discard, "", 0), Policy{Threshold: SevLow, Provider: p}, nil)

	post := func(text string) *httptest.ResponseRecorder {
		req := httptest.NewRequest(http.MethodPost, path, bytes.NewReader(makeBody(text)))
		req.Header.Set("Content-Type", "application/json")
		for k, v := range hdr {
			req.Header.Set(k, v)
		}
		w := httptest.NewRecorder()
		h.ServeHTTP(w, req)
		return w
	}

	// 1. Email trips a block that offers `mask`.
	w := post("email me at info@example.com")
	if w.Header().Get("X-Masqr-Blocked") != "1" || !strings.Contains(w.Body.String(), "`mask`") {
		t.Fatalf("first turn: want block offering mask; got code=%d\n%s", w.Code, w.Body.String())
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
	w = post("email me at info@example.com")
	if w.Header().Get("X-Masqr-Blocked") == "1" {
		t.Fatalf("post-consent turn should forward, not block:\n%s", w.Body.String())
	}
	if forwarded != 1 {
		t.Fatalf("post-consent turn should forward exactly once; forwarded=%d", forwarded)
	}
	if rawSeen {
		t.Errorf("upstream received the raw email after consent — masking failed")
	}
}

func TestClaudeMaskConsentFlow(t *testing.T) {
	runMaskFlow(t, "claude", "/v1/messages", nil, func(text string) []byte {
		return []byte(`{"model":"claude-x","stream":true,"messages":[{"role":"user","content":"` + text + `"}]}`)
	})
}

func TestVibeMaskConsentFlow(t *testing.T) {
	runMaskFlow(t, "vibe", "/v1/chat/completions", nil, func(text string) []byte {
		return []byte(`{"model":"mistral-x","stream":true,"messages":[{"role":"user","content":"` + text + `"}]}`)
	})
}

// TestCodexMaskConsentFlow additionally exercises the zstd request path: codex
// compresses its /responses body, so masqr must decode it to detect the `mask`
// reply and to redact the consented value, then forward the masked body
// uncompressed.
func TestCodexMaskConsentFlow(t *testing.T) {
	runMaskFlow(t, "codex", "/v1/responses", map[string]string{"Content-Encoding": "zstd"}, func(text string) []byte {
		j := `{"model":"gpt","stream":true,"input":[{"role":"user","content":[{"type":"input_text","text":"` + text + `"}]}]}`
		return mustZstd(t, []byte(j))
	})
}

// TestCopilotMaskConsentFlow locks in that GitHub Copilot's agent loop gets the
// interactive model-turn block + mask-and-continue flow on both of its observed
// conversation wires — the OpenAI Responses API (/responses, OpenAI models) and
// the Anthropic Messages API (/v1/messages, Claude models), selected by the
// active model. A regression that handled only one wire would silently
// hard-block the other.
func TestCopilotMaskConsentFlow(t *testing.T) {
	t.Run("responses", func(t *testing.T) {
		runMaskFlow(t, "copilot", "/responses", nil, func(text string) []byte {
			return []byte(`{"model":"gpt-5-mini","stream":true,"input":[{"role":"user","content":[{"type":"input_text","text":"` + text + `"}]}]}`)
		})
	})
	t.Run("v1-messages", func(t *testing.T) {
		runMaskFlow(t, "copilot", "/v1/messages", nil, func(text string) []byte {
			return []byte(`{"model":"claude-haiku-4.5","stream":true,"messages":[{"role":"user","content":"` + text + `"}]}`)
		})
	})
}

// TestAnthropicStreamModelTurnShape locks in the Anthropic Messages SSE event
// sequence for a streaming block, so Claude Code's stream parser renders it.
func TestAnthropicStreamModelTurnShape(t *testing.T) {
	w := httptest.NewRecorder()
	writeAnthropicModelTurn(w, "hello world", true, "claude-x")
	if ct := w.Header().Get("Content-Type"); ct != "text/event-stream" {
		t.Fatalf("content-type = %q, want text/event-stream", ct)
	}
	out := w.Body.String()
	for _, ev := range []string{"message_start", "content_block_start", "content_block_delta", "content_block_stop", "message_delta", "message_stop"} {
		if !strings.Contains(out, "event: "+ev) {
			t.Errorf("missing SSE event %q in:\n%s", ev, out)
		}
	}
	if !strings.Contains(out, "hello world") {
		t.Errorf("text not present in stream:\n%s", out)
	}
}

// TestOpenAIResponsesStreamModelTurnShape locks in the key Responses streaming
// events codex consumes to render an assistant turn.
func TestOpenAIResponsesStreamModelTurnShape(t *testing.T) {
	w := httptest.NewRecorder()
	writeOpenAIResponsesModelTurn(w, "hello world", true, "")
	out := w.Body.String()
	for _, ev := range []string{"response.created", "response.output_item.added", "response.output_text.delta", "response.completed"} {
		if !strings.Contains(out, "event: "+ev) {
			t.Errorf("missing SSE event %q in:\n%s", ev, out)
		}
	}
	if !strings.Contains(out, "hello world") {
		t.Errorf("text not present in stream:\n%s", out)
	}
}

// TestOpenAIChatStreamModelTurnShape verifies vibe's chat.completion.chunk SSE
// (data-only frames terminated by [DONE]).
func TestOpenAIChatStreamModelTurnShape(t *testing.T) {
	w := httptest.NewRecorder()
	writeOpenAIChatModelTurn(w, "hello world", true, "mistral-x")
	out := w.Body.String()
	if !strings.Contains(out, "chat.completion.chunk") {
		t.Errorf("missing chunk object:\n%s", out)
	}
	if !strings.Contains(out, "hello world") {
		t.Errorf("text not present:\n%s", out)
	}
	if !strings.Contains(out, "data: [DONE]") {
		t.Errorf("missing [DONE] terminator:\n%s", out)
	}
}
