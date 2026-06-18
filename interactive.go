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
	"encoding/json"
	"net/http"
	"strings"
)

// This file generalizes the rich-block-message + interactive mask-and-continue
// flow that originally shipped only for agy (antigravity). The block reason is
// delivered as a synthetic *assistant turn* in each provider's own wire shape —
// so every supported CLI renders masqr's explanation inline like a normal model
// reply and the user can answer `mask` to continue — instead of a terse error
// envelope. writeBlockResponse remains the fallback for non-chat endpoints and
// the generic provider.

// providerCommand maps a provider Name to the CLI command shown in advice text
// (e.g. "masqr --block-on=high <cmd>"). Falls back to a neutral placeholder.
func providerCommand(name string) string {
	switch name {
	case "antigravity":
		return "agy"
	case "anthropic":
		return "claude"
	case "openai":
		return "codex"
	case "github-copilot":
		return "copilot"
	case "google-gemini", "google-vertex":
		return "gemini"
	case "mistral":
		return "vibe"
	default:
		return "<cli>"
	}
}

// interactiveMaskProvider reports whether masqr knows this provider's request
// body format (to detect a `mask` reply) and response shape (to inject a model
// turn). Generic/unknown providers fall back to the plain block envelope.
func interactiveMaskProvider(name string) bool {
	switch name {
	case "antigravity", "anthropic", "openai", "google-gemini", "google-vertex", "mistral", "github-copilot":
		return true
	}
	return false
}

// isModelTurnPath reports whether path is a chat/generation endpoint for this
// provider — i.e. one where an injected assistant turn is what the CLI expects
// and will render. Metadata endpoints (countTokens, loadCodeAssist, embeddings,
// …) return false so they keep getting the plain block envelope.
func isModelTurnPath(name, path string) bool {
	lp := strings.ToLower(path)
	switch name {
	case "anthropic":
		return strings.Contains(lp, "/messages")
	case "openai":
		return strings.Contains(lp, "/responses")
	case "mistral", "github-copilot":
		return strings.Contains(lp, "/chat/completions")
	case "google-gemini", "google-vertex", "antigravity":
		return strings.Contains(lp, "generatecontent")
	}
	return false
}

// wantsStreaming reports whether the client expects an SSE stream rather than a
// single JSON object, so the synthetic turn is delivered in the matching shape.
// Gemini-family CLIs signal it by endpoint name (…:streamGenerateContent);
// everyone else uses a `"stream":true` body flag or an SSE Accept header.
func wantsStreaming(name string, r *http.Request, decodedBody []byte) bool {
	switch name {
	case "google-gemini", "google-vertex", "antigravity":
		return strings.Contains(strings.ToLower(r.URL.Path), "streamgeneratecontent")
	}
	if strings.Contains(strings.ToLower(r.Header.Get("Accept")), "text/event-stream") {
		return true
	}
	return bytes.Contains(decodedBody, []byte(`"stream":true`)) ||
		bytes.Contains(decodedBody, []byte(`"stream": true`))
}

// latestUserTextFor extracts the most recent user-authored text from a request
// body in the provider's format, so a bare `mask` reply is recognizable.
func latestUserTextFor(name string, body []byte) string {
	switch name {
	case "google-gemini", "google-vertex", "antigravity":
		return latestUserText(body) // Gemini {contents:[…]} (consent.go)
	case "anthropic", "mistral", "github-copilot":
		return lastUserFromMessages(body)
	case "openai":
		return lastUserFromResponsesInput(body)
	}
	return ""
}

// jsonStringField returns the top-level string value of key in body, or "".
func jsonStringField(body []byte, key string) string {
	var m map[string]json.RawMessage
	if json.Unmarshal(body, &m) != nil {
		return ""
	}
	raw, ok := m[key]
	if !ok {
		return ""
	}
	var s string
	if json.Unmarshal(raw, &s) == nil {
		return s
	}
	return ""
}

// chatContentText flattens a chat "content" field that may be a bare string or
// an array of typed parts ({"type":"text","text":…} / {"type":"input_text",…}).
func chatContentText(raw json.RawMessage) string {
	if len(raw) == 0 {
		return ""
	}
	var s string
	if json.Unmarshal(raw, &s) == nil {
		return s
	}
	var parts []struct {
		Text string `json:"text"`
	}
	if json.Unmarshal(raw, &parts) == nil {
		var b strings.Builder
		for _, p := range parts {
			b.WriteString(p.Text)
		}
		return b.String()
	}
	return ""
}

// lastUserFromMessages pulls the latest user turn from an OpenAI-/Anthropic-style
// {"messages":[{"role":…,"content":…}]} body. Covers claude (/v1/messages) and
// vibe/mistral (/v1/chat/completions), which share the messages+content shape.
func lastUserFromMessages(body []byte) string {
	var t struct {
		Messages []struct {
			Role    string          `json:"role"`
			Content json.RawMessage `json:"content"`
		} `json:"messages"`
	}
	if json.Unmarshal(body, &t) != nil {
		return ""
	}
	for i := len(t.Messages) - 1; i >= 0; i-- {
		if t.Messages[i].Role != "user" && t.Messages[i].Role != "" {
			continue
		}
		return chatContentText(t.Messages[i].Content)
	}
	return ""
}

// lastUserFromResponsesInput pulls the latest user turn from an OpenAI Responses
// {"input": …} body (codex). input is either a bare string or an array of items
// with a role and string/array content.
func lastUserFromResponsesInput(body []byte) string {
	var t struct {
		Input json.RawMessage `json:"input"`
	}
	if json.Unmarshal(body, &t) != nil || len(t.Input) == 0 {
		return ""
	}
	var s string
	if json.Unmarshal(t.Input, &s) == nil {
		return s
	}
	var items []struct {
		Role    string          `json:"role"`
		Content json.RawMessage `json:"content"`
	}
	if json.Unmarshal(t.Input, &items) == nil {
		for i := len(items) - 1; i >= 0; i-- {
			if items[i].Role != "user" && items[i].Role != "" {
				continue
			}
			return chatContentText(items[i].Content)
		}
	}
	return ""
}

// writeModelTurn delivers text as a synthetic assistant turn in the provider's
// wire shape (streaming SSE or a single JSON object). model echoes the request's
// model where the protocol carries one; gemini takes it from the URL instead.
func writeModelTurn(w http.ResponseWriter, provider Provider, text string, streaming bool, path, model string) {
	switch provider.Name {
	case "google-gemini", "google-vertex", "antigravity":
		nested := strings.Contains(strings.ToLower(path), "/v1internal")
		writeGeminiModelTurn(w, text, streaming, nested)
	case "anthropic":
		writeAnthropicModelTurn(w, text, streaming, model)
	case "openai":
		writeOpenAIResponsesModelTurn(w, text, streaming, model)
	case "mistral", "github-copilot":
		writeOpenAIChatModelTurn(w, text, streaming, model)
	default:
		// Should be unreachable (callers gate on interactiveMaskProvider),
		// but never leave the response unwritten.
		writeJSONStatus(w, http.StatusOK, map[string]string{"masqr": text})
	}
}

// --- low-level SSE / JSON writers -------------------------------------------

func sseStart(w http.ResponseWriter) {
	w.Header().Set("Content-Type", "text/event-stream")
	w.Header().Set("Cache-Control", "no-cache")
	w.Header().Set("X-Masqr-Blocked", "1")
	w.WriteHeader(http.StatusOK)
}

// sseEvent writes one SSE event. event may be "" to emit a data-only frame
// (the shape Gemini and the OpenAI chat API use).
func sseEvent(w http.ResponseWriter, event string, data any) {
	buf, err := json.Marshal(data)
	if err != nil {
		return
	}
	if event != "" {
		_, _ = w.Write([]byte("event: " + event + "\n"))
	}
	_, _ = w.Write([]byte("data: "))
	_, _ = w.Write(buf)
	_, _ = w.Write([]byte("\n\n"))
	if f, ok := w.(http.Flusher); ok {
		f.Flush()
	}
}

func sseRaw(w http.ResponseWriter, s string) {
	_, _ = w.Write([]byte(s))
	if f, ok := w.(http.Flusher); ok {
		f.Flush()
	}
}

func writeJSONStatus(w http.ResponseWriter, status int, obj any) {
	buf, err := json.Marshal(obj)
	if err != nil {
		buf = []byte(`{"error":{"message":"masqr blocked the request"}}`)
	}
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("X-Masqr-Blocked", "1")
	w.WriteHeader(status)
	_, _ = w.Write(buf)
}

// --- Gemini family (google-gemini, antigravity) -----------------------------

func geminiResponseObject(text string) map[string]any {
	return map[string]any{
		"candidates": []any{map[string]any{
			"content":      map[string]any{"role": "model", "parts": []any{map[string]any{"text": text}}},
			"finishReason": "STOP",
			"index":        0,
		}},
	}
}

func writeGeminiModelTurn(w http.ResponseWriter, text string, streaming, nested bool) {
	payload := any(geminiResponseObject(text))
	if nested {
		payload = map[string]any{"response": geminiResponseObject(text)}
	}
	if streaming {
		sseStart(w)
		sseEvent(w, "", payload)
		return
	}
	writeJSONStatus(w, http.StatusOK, payload)
}

// --- Anthropic (claude) -----------------------------------------------------

func writeAnthropicModelTurn(w http.ResponseWriter, text string, streaming bool, model string) {
	if model == "" {
		model = "claude-sonnet-4"
	}
	if !streaming {
		writeJSONStatus(w, http.StatusOK, map[string]any{
			"id":            "msg_masqr",
			"type":          "message",
			"role":          "assistant",
			"model":         model,
			"content":       []any{map[string]any{"type": "text", "text": text}},
			"stop_reason":   "end_turn",
			"stop_sequence": nil,
			"usage":         map[string]any{"input_tokens": 0, "output_tokens": 0},
		})
		return
	}
	sseStart(w)
	sseEvent(w, "message_start", map[string]any{
		"type": "message_start",
		"message": map[string]any{
			"id": "msg_masqr", "type": "message", "role": "assistant", "model": model,
			"content": []any{}, "stop_reason": nil, "stop_sequence": nil,
			"usage": map[string]any{"input_tokens": 0, "output_tokens": 0},
		},
	})
	sseEvent(w, "content_block_start", map[string]any{
		"type": "content_block_start", "index": 0,
		"content_block": map[string]any{"type": "text", "text": ""},
	})
	sseEvent(w, "content_block_delta", map[string]any{
		"type": "content_block_delta", "index": 0,
		"delta": map[string]any{"type": "text_delta", "text": text},
	})
	sseEvent(w, "content_block_stop", map[string]any{"type": "content_block_stop", "index": 0})
	sseEvent(w, "message_delta", map[string]any{
		"type":  "message_delta",
		"delta": map[string]any{"stop_reason": "end_turn", "stop_sequence": nil},
		"usage": map[string]any{"output_tokens": 0},
	})
	sseEvent(w, "message_stop", map[string]any{"type": "message_stop"})
}

// --- OpenAI Responses (codex) -----------------------------------------------

func openAIResponseObject(text, status string) map[string]any {
	return map[string]any{
		"id":     "resp_masqr",
		"object": "response",
		"status": status,
		"output": []any{map[string]any{
			"id": "msg_masqr", "type": "message", "status": "completed", "role": "assistant",
			"content": []any{map[string]any{"type": "output_text", "text": text, "annotations": []any{}}},
		}},
	}
}

func writeOpenAIResponsesModelTurn(w http.ResponseWriter, text string, streaming bool, model string) {
	_ = model
	if !streaming {
		writeJSONStatus(w, http.StatusOK, openAIResponseObject(text, "completed"))
		return
	}
	sseStart(w)
	sseEvent(w, "response.created", map[string]any{
		"type":     "response.created",
		"response": map[string]any{"id": "resp_masqr", "object": "response", "status": "in_progress", "output": []any{}},
	})
	sseEvent(w, "response.output_item.added", map[string]any{
		"type": "response.output_item.added", "output_index": 0,
		"item": map[string]any{"id": "msg_masqr", "type": "message", "status": "in_progress", "role": "assistant", "content": []any{}},
	})
	sseEvent(w, "response.content_part.added", map[string]any{
		"type": "response.content_part.added", "item_id": "msg_masqr", "output_index": 0, "content_index": 0,
		"part": map[string]any{"type": "output_text", "text": "", "annotations": []any{}},
	})
	sseEvent(w, "response.output_text.delta", map[string]any{
		"type": "response.output_text.delta", "item_id": "msg_masqr", "output_index": 0, "content_index": 0, "delta": text,
	})
	sseEvent(w, "response.output_text.done", map[string]any{
		"type": "response.output_text.done", "item_id": "msg_masqr", "output_index": 0, "content_index": 0, "text": text,
	})
	sseEvent(w, "response.content_part.done", map[string]any{
		"type": "response.content_part.done", "item_id": "msg_masqr", "output_index": 0, "content_index": 0,
		"part": map[string]any{"type": "output_text", "text": text, "annotations": []any{}},
	})
	sseEvent(w, "response.output_item.done", map[string]any{
		"type": "response.output_item.done", "output_index": 0,
		"item": map[string]any{"id": "msg_masqr", "type": "message", "status": "completed", "role": "assistant",
			"content": []any{map[string]any{"type": "output_text", "text": text, "annotations": []any{}}}},
	})
	sseEvent(w, "response.completed", map[string]any{
		"type": "response.completed", "response": openAIResponseObject(text, "completed"),
	})
}

// --- OpenAI chat completions (vibe / mistral) -------------------------------

func writeOpenAIChatModelTurn(w http.ResponseWriter, text string, streaming bool, model string) {
	if model == "" {
		model = "mistral-medium-latest"
	}
	if !streaming {
		writeJSONStatus(w, http.StatusOK, map[string]any{
			"id": "chatcmpl-masqr", "object": "chat.completion", "created": 0, "model": model,
			"choices": []any{map[string]any{
				"index":         0,
				"message":       map[string]any{"role": "assistant", "content": text},
				"finish_reason": "stop",
			}},
			"usage": map[string]any{"prompt_tokens": 0, "completion_tokens": 0, "total_tokens": 0},
		})
		return
	}
	sseStart(w)
	sseEvent(w, "", map[string]any{
		"id": "chatcmpl-masqr", "object": "chat.completion.chunk", "created": 0, "model": model,
		"choices": []any{map[string]any{
			"index":         0,
			"delta":         map[string]any{"role": "assistant", "content": text},
			"finish_reason": nil,
		}},
	})
	sseEvent(w, "", map[string]any{
		"id": "chatcmpl-masqr", "object": "chat.completion.chunk", "created": 0, "model": model,
		"choices": []any{map[string]any{"index": 0, "delta": map[string]any{}, "finish_reason": "stop"}},
	})
	sseRaw(w, "data: [DONE]\n\n")
}
