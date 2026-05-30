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

// TestRedactRoundTripJSON drives the full redact-then-restore loop: the
// fake upstream echoes the request body back as a JSON response, and we
// assert (1) the upstream never sees the email, (2) the response the
// client gets has the original email put back, (3) a follow-up request
// with the same email uses the same placeholder.
func TestRedactRoundTripJSON(t *testing.T) {
	gemini, _ := LookupProvider("gemini")

	var seenByUpstream []string
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		b, _ := io.ReadAll(r.Body)
		seenByUpstream = append(seenByUpstream, string(b))
		w.Header().Set("Content-Type", "application/json")
		// Echo a "model reply" that quotes the prompt back — same shape
		// the LLM would produce.
		_, _ = w.Write([]byte(`{"reply":"got your message: ` + string(b) + `"}`))
	}))
	defer upstream.Close()
	u, _ := url.Parse(upstream.URL)

	policy := Policy{Threshold: SevLow, Provider: gemini, OnFinding: OnFindingRedact}
	h := newProxy(u, log.New(io.Discard, "", 0), policy, nil)

	// First request — fresh memo. Expect __EMAIL_1__ in upstream view,
	// original in the response we get back.
	body := `{"contents":[{"parts":[{"text":"my email is info@test.com"}]}]}`
	req := httptest.NewRequest(http.MethodPost, "/v1beta/models/gemini-1.5-pro:generateContent", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	h.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200; body=%q", w.Code, w.Body.String())
	}
	if len(seenByUpstream) != 1 || !strings.Contains(seenByUpstream[0], "__EMAIL_1__") {
		t.Errorf("upstream did not receive placeholder; got=%q", seenByUpstream)
	}
	if strings.Contains(seenByUpstream[0], "info@test.com") {
		t.Errorf("upstream leaked original email: %q", seenByUpstream[0])
	}
	if got := w.Body.String(); !strings.Contains(got, "info@test.com") {
		t.Errorf("response missing restored email: %q", got)
	}
	if got := w.Body.String(); strings.Contains(got, "__EMAIL_1__") {
		t.Errorf("response still contains placeholder: %q", got)
	}

	// Second request with the *same* email — should reuse the same
	// placeholder (counter doesn't advance), still restore in response.
	req2 := httptest.NewRequest(http.MethodPost, "/v1beta/models/gemini-1.5-pro:generateContent",
		strings.NewReader(`{"contents":[{"parts":[{"text":"again info@test.com"}]}]}`))
	req2.Header.Set("Content-Type", "application/json")
	w2 := httptest.NewRecorder()
	h.ServeHTTP(w2, req2)

	if w2.Code != http.StatusOK {
		t.Fatalf("second request status = %d, want 200", w2.Code)
	}
	if !strings.Contains(seenByUpstream[1], "__EMAIL_1__") {
		t.Errorf("placeholder identity not reused: got=%q", seenByUpstream[1])
	}
	if strings.Contains(seenByUpstream[1], "__EMAIL_2__") {
		t.Errorf("counter advanced for the same value: %q", seenByUpstream[1])
	}
}

// TestRedactDistinctValuesGetDistinctCounters covers two different
// emails in two requests landing as __EMAIL_1__ and __EMAIL_2__.
func TestRedactDistinctValuesGetDistinctCounters(t *testing.T) {
	gemini, _ := LookupProvider("gemini")
	var seen []string
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		b, _ := io.ReadAll(r.Body)
		seen = append(seen, string(b))
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{}`))
	}))
	defer upstream.Close()
	u, _ := url.Parse(upstream.URL)
	policy := Policy{Threshold: SevLow, Provider: gemini, OnFinding: OnFindingRedact}
	h := newProxy(u, log.New(io.Discard, "", 0), policy, nil)

	for _, email := range []string{"a@example.com", "b@example.com"} {
		// `/v1beta/...` deliberately misses the gemini profile's
		// `/v1internal` route so our test upstream actually receives
		// the request.
		req := httptest.NewRequest(http.MethodPost, "/v1beta/models/x:generateContent",
			strings.NewReader(`{"text":"`+email+`"}`))
		req.Header.Set("Content-Type", "application/json")
		h.ServeHTTP(httptest.NewRecorder(), req)
	}
	if !strings.Contains(seen[0], "__EMAIL_1__") {
		t.Errorf("first email did not get __EMAIL_1__: %q", seen[0])
	}
	if !strings.Contains(seen[1], "__EMAIL_2__") {
		t.Errorf("second email did not get __EMAIL_2__: %q", seen[1])
	}
}

// TestRedactFallsBackToBlockOnURLFinding asserts that a URL-borne API
// key blocks the request even in redact mode — a rewrite of the path
// would still ship the key to the upstream.
func TestRedactFallsBackToBlockOnURLFinding(t *testing.T) {
	gemini, _ := LookupProvider("gemini")
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		t.Errorf("upstream must not be hit; URL=%q", r.URL.String())
	}))
	defer upstream.Close()
	u, _ := url.Parse(upstream.URL)
	policy := Policy{Threshold: SevLow, Provider: gemini, OnFinding: OnFindingRedact}
	h := newProxy(u, log.New(io.Discard, "", 0), policy, nil)

	req := httptest.NewRequest(http.MethodPost,
		"/v1beta/models/gemini-1.5-pro:generateContent?key=AIzaSyAabcdefghijklmnopqrstuvwxyz123456",
		strings.NewReader(`{"contents":[]}`))
	w := httptest.NewRecorder()
	h.ServeHTTP(w, req)

	if w.Code != http.StatusUnavailableForLegalReasons {
		t.Fatalf("URL key should block; got status=%d body=%q", w.Code, w.Body.String())
	}
}

// TestStreamRestorerPiecewise verifies the streaming restorer joins
// chunks that split a placeholder across reads — the SSE failure mode
// we'd hit on real LLM responses.
func TestStreamRestorerPiecewise(t *testing.T) {
	memo := newFindingMemo()
	memo.idToPlaceholder["x"] = "__EMAIL_1__"
	memo.placeholderToOriginal["__EMAIL_1__"] = "info@test.com"

	pairs := memo.snapshot()
	source := &chunkedReader{chunks: [][]byte{
		[]byte(`data: {"text":"contact us at __EM`),
		[]byte(`AIL_1__ today"}` + "\n\n"),
	}}
	r := newStreamRestorer(source, pairs)
	got, err := io.ReadAll(r)
	if err != nil {
		t.Fatalf("ReadAll: %v", err)
	}
	want := `data: {"text":"contact us at info@test.com today"}` + "\n\n"
	if string(got) != want {
		t.Errorf("stream restore mismatch:\n got: %q\nwant: %q", string(got), want)
	}
}

// chunkedReader emits its chunks one Read at a time so tests can
// simulate split-token streaming.
type chunkedReader struct {
	chunks [][]byte
	i      int
}

func (r *chunkedReader) Read(p []byte) (int, error) {
	if r.i >= len(r.chunks) {
		return 0, io.EOF
	}
	n := copy(p, r.chunks[r.i])
	r.chunks[r.i] = r.chunks[r.i][n:]
	if len(r.chunks[r.i]) == 0 {
		r.i++
	}
	return n, nil
}
