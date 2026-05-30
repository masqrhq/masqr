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
	"compress/flate"
	"compress/gzip"
	"compress/zlib"
	"context"
	"fmt"
	"io"
	"log"
	"net/http"
	"net/http/httputil"
	"net/url"
	"strings"
	"sync/atomic"

	"github.com/andybalholm/brotli"
	"github.com/klauspost/compress/zstd"
)

// redactHeaders is the union of every header name we never want to write
// verbatim into the session log. The set covers the historical Anthropic
// triplet plus all provider-specific auth headers declared in providers.go,
// so adding a new provider doesn't risk leaking its key into logs.
var redactHeaders = func() map[string]struct{} {
	m := map[string]struct{}{
		"authorization":     {},
		"x-api-key":         {},
		"anthropic-api-key": {},
		"cookie":            {},
		"set-cookie":        {},
	}
	for _, p := range builtinProviders {
		for _, h := range p.AuthHeaders {
			m[strings.ToLower(h)] = struct{}{}
		}
	}
	return m
}()

// redactQueryParams is the union of every query-parameter name we strip
// from request URIs before they hit the log. Google Gemini's `?key=…`
// pattern is the canonical case; we also cover the half-dozen
// adjacent spellings that show up across providers.
var redactQueryParams = func() map[string]struct{} {
	m := map[string]struct{}{
		"key":          {},
		"api_key":      {},
		"apikey":       {},
		"api-key":      {},
		"access_token": {},
		"token":        {},
		"auth":         {},
	}
	for _, p := range builtinProviders {
		for _, q := range p.AuthQueryParams {
			m[strings.ToLower(q)] = struct{}{}
		}
	}
	return m
}()

var reqCounter atomic.Uint64

// parsedRoute is the runtime, pre-parsed form of a provider Route. Building
// these once at proxy construction keeps the per-request rewrite hot path
// free of url.Parse calls.
type parsedRoute struct {
	prefix string
	url    *url.URL
}

// newProxy builds the scan/redact/block reverse-proxy handler. transport is
// optional: the plaintext providers pass nil (http.DefaultTransport is used);
// the transparent-intercept path passes a transport pinned to the real
// upstream IP so forwarding can't loop back through a hostname redirect.
func newProxy(upstream *url.URL, logger *log.Logger, policy Policy, transport http.RoundTripper) http.Handler {
	memo := newFindingMemo()

	// Pre-parse provider Routes. A bad URL is logged once at startup and
	// dropped from the table — it never silently breaks routing.
	var routes []parsedRoute
	for _, r := range policy.Provider.Routes {
		u, err := url.Parse(r.Target)
		if err != nil {
			logger.Printf("provider %q: skipping route %s → %s: %v",
				policy.Provider.Name, r.PathPrefix, r.Target, err)
			continue
		}
		routes = append(routes, parsedRoute{prefix: r.PathPrefix, url: u})
	}

	pickUpstream := func(p string) *url.URL {
		for _, route := range routes {
			if strings.HasPrefix(p, route.prefix) {
				return route.url
			}
		}
		return upstream
	}

	proxy := &httputil.ReverseProxy{
		// Rewrite (Go 1.20+) is the modern equivalent of Director. We
		// pick the upstream per request based on the path prefix table,
		// so a Gemini-OAuth `/v1internal:loadCodeAssist` call routes to
		// cloudcode-pa.googleapis.com while a Gemini-API-key
		// `/v1beta/models/…:generateContent` call routes to the public
		// generativelanguage endpoint, all from one local listener.
		Rewrite: func(pr *httputil.ProxyRequest) {
			u := pickUpstream(pr.In.URL.Path)
			pr.SetURL(u)
			pr.Out.Host = u.Host
		},
		ModifyResponse: func(resp *http.Response) error {
			id, _ := resp.Request.Context().Value(ctxKeyReqID).(uint64)
			logResponse(logger, id, resp)
			// Restore placeholders in the response so the user sees
			// their original values. Streaming bodies (SSE) are
			// wrapped with a buffered byte-level replacer; everything
			// else is round-tripped through restoreBytes in one shot.
			if pairs := memo.snapshot(); len(pairs) > 0 {
				ct := resp.Header.Get("Content-Type")
				if isStreaming(ct) {
					resp.Body = wrapRestorerReadCloser(resp.Body, pairs)
				} else if resp.Header.Get("Content-Encoding") == "" {
					buf, err := io.ReadAll(resp.Body)
					_ = resp.Body.Close()
					if err != nil {
						return err
					}
					restored := restoreBytes(buf, pairs)
					resp.Body = io.NopCloser(bytes.NewReader(restored))
					resp.ContentLength = int64(len(restored))
					resp.Header.Set("Content-Length", fmt.Sprintf("%d", len(restored)))
				}
				// Compressed non-streaming responses are passed
				// through unmodified: the request rewrite already
				// sets Accept-Encoding: identity, so this branch
				// should be unreachable in practice for redacted
				// requests. Logged via logResponse above.
			}
			return nil
		},
		ErrorHandler: func(w http.ResponseWriter, r *http.Request, err error) {
			id, _ := r.Context().Value(ctxKeyReqID).(uint64)
			logger.Printf("[#%d] proxy error: %v", id, err)
			http.Error(w, "upstream error: "+err.Error(), http.StatusBadGateway)
		},
	}
	if transport != nil {
		proxy.Transport = transport
	}

	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		id := reqCounter.Add(1)
		ctx := contextWithReqID(r.Context(), id)
		r = r.WithContext(ctx)

		// Short-circuit WebSocket upgrades. masqr is an HTTP reverse
		// proxy and can't inspect WS frames. Codex 0.134 probes
		// `ws://<base>/responses` before HTTPS, and only `404 Not
		// Found` triggers its native HTTPS fallback message
		// ("Falling back from WebSockets to HTTPS transport") with
		// zero retries. 5xx burns the retry budget (~5×45s); other
		// 4xx codes are treated as fatal and abort the session. 404
		// reads naturally as "the WS endpoint isn't here, try HTTP"
		// which is exactly what we want.
		if isWebSocketUpgrade(r) {
			logger.Printf("[#%d] REJECTED WebSocket upgrade (masqr is HTTP-only); codex will fall back to HTTPS",
				id)
			http.Error(w, "masqr does not proxy WebSocket transports; use HTTPS",
				http.StatusNotFound)
			return
		}

		body, _ := io.ReadAll(r.Body)
		_ = r.Body.Close()
		r.Body = io.NopCloser(bytes.NewReader(body))
		r.ContentLength = int64(len(body))

		matches := logRequest(logger, id, r, body)

		if blocking := policy.triggering(matches); len(blocking) > 0 {
			shift := urlPrefixLen(r.URL)

			// Classify: every triggering match is either redactable
			// (in-body span with a stable Identity) or not (URL hits,
			// base64 recursive sub-matches, sources that don't expose
			// raw bytes). If any match in this request isn't
			// redactable, we have to block — silently dropping a URL-
			// borne credential without rewriting the URL would still
			// forward it to the upstream.
			redactable := canRedactAll(blocking, body, shift, r.Header.Get("Content-Encoding"))

			if policy.OnFinding == OnFindingRedact && redactable {
				rewritten := redactSpans(body, blocking, shift, memo)
				logger.Printf("[#%d] REDACTED %d finding(s); forwarding %d-byte body (was %d)",
					id, len(blocking), len(rewritten), len(body))
				r.Body = io.NopCloser(bytes.NewReader(rewritten))
				r.ContentLength = int64(len(rewritten))
				r.Header.Set("Content-Length", fmt.Sprintf("%d", len(rewritten)))
				// Force the upstream to respond with identity encoding
				// so the response restorer can replace placeholders on
				// the wire without an in-memory gzip/br/zstd round-trip.
				r.Header.Set("Accept-Encoding", "identity")
				proxy.ServeHTTP(w, r)
				return
			}

			logger.Printf("[#%d] BLOCKED by policy (%d finding(s) >= %s)", id, len(blocking), policy.Threshold)
			writeBlockResponse(w, blocking, policy.Provider)
			return
		}

		proxy.ServeHTTP(w, r)
	})
}

// wrapRestorerReadCloser wraps a streaming response body so each chunk
// has placeholders substituted before it reaches the CLI. The wrapper
// keeps a rolling tail buffer sized at the longest placeholder so a
// match that straddles two chunks isn't half-emitted.
func wrapRestorerReadCloser(rc io.ReadCloser, pairs []replacementPair) io.ReadCloser {
	return &restorerReadCloser{
		reader: newStreamRestorer(rc, pairs),
		closer: rc,
	}
}

type restorerReadCloser struct {
	reader io.Reader
	closer io.Closer
}

func (r *restorerReadCloser) Read(p []byte) (int, error) { return r.reader.Read(p) }
func (r *restorerReadCloser) Close() error               { return r.closer.Close() }

// isWebSocketUpgrade reports whether r is a WebSocket handshake. RFC 6455
// requires Connection to contain (token-list) "upgrade" and Upgrade to
// equal "websocket" (case-insensitive). Go's http.Header.Get normalises
// neither, so we walk the tokens by hand.
func isWebSocketUpgrade(r *http.Request) bool {
	if !strings.EqualFold(r.Header.Get("Upgrade"), "websocket") {
		return false
	}
	for _, conn := range r.Header.Values("Connection") {
		for _, tok := range strings.Split(conn, ",") {
			if strings.EqualFold(strings.TrimSpace(tok), "upgrade") {
				return true
			}
		}
	}
	return false
}

// urlPrefixLen returns the length of the synthetic `url: …\n` preamble
// scanRequest prepends to the scan buffer. Subtracting it from a match's
// scanner Offset gives the offset in the raw request body.
func urlPrefixLen(u *url.URL) int {
	if u == nil {
		return 0
	}
	return len("url: ") + len(u.RequestURI()) + len("\n")
}

// canRedactAll reports whether every match can be safely replaced in the
// raw request body in place. URL-borne findings (offset inside the
// `url: …` preamble scanRequest prepends) and compressed bodies vote to
// block — masqr can't rewrite the request URL without forwarding the
// credential to the upstream, and rewriting compressed bytes would mean
// an in-memory recompress every request. Anything else — including
// findings without a pre-set Identity, which placeholderFor now derives
// on the fly — is fair game for redaction.
func canRedactAll(matches []Match, body []byte, shift int, contentEncoding string) bool {
	if contentEncoding != "" {
		return false
	}
	for _, m := range matches {
		if m.Offset < shift {
			return false
		}
		s, e := m.Offset-shift, m.End-shift
		if e <= s || e > len(body) {
			return false
		}
	}
	return true
}

func logRequest(logger *log.Logger, id uint64, r *http.Request, body []byte) []Match {
	var b strings.Builder
	fmt.Fprintf(&b, "\n--- [#%d] REQUEST %s %s ---\n", id, r.Method, redactRequestURI(r.URL))
	writeHeaders(&b, r.Header)
	writeBody(&b, body, r.Header.Get("Content-Type"))

	// Scan body + URI together so a key smuggled in a query parameter
	// (Google's `?key=AIza…` is the canonical case) is flagged + blocked
	// the same way as one smuggled in the body. The original body stays
	// untouched — only the scan input is augmented.
	//
	// Codex CLI sends zstd-compressed JSON (Content-Encoding: zstd) on
	// POST /responses; decode for scanning only so AKIA… in the prompt
	// is visible to the rule engine without mutating what we forward.
	scanBody := body
	if enc := r.Header.Get("Content-Encoding"); enc != "" && len(body) > 0 {
		if decoded, err := decode(body, enc); err == nil {
			scanBody = decoded
		}
	}
	matches := scanRequest(r.URL, scanBody)
	if len(matches) > 0 {
		fmt.Fprintf(&b, "\n--- [#%d] ALERTS (%d) ---\n", id, len(matches))
		for _, m := range matches {
			fmt.Fprintf(&b, "  [%s/%s] %s @%d..%d : %s\n",
				m.Severity, m.Category, m.RuleID, m.Offset, m.End, m.Snippet)
		}
	}
	logger.Print(b.String())
	return matches
}

// scanRequest runs the default scanner over body PLUS a `url:` line built
// from the unredacted URI. We prepend with a newline so byte offsets in
// the body stay readable, and so the scanner sees a well-formed boundary
// between URL text and body bytes.
func scanRequest(u *url.URL, body []byte) []Match {
	if u == nil {
		return DefaultScanner().Scan(body)
	}
	uri := u.RequestURI()
	prefix := "url: " + uri + "\n"
	buf := make([]byte, 0, len(prefix)+len(body))
	buf = append(buf, prefix...)
	buf = append(buf, body...)
	return DefaultScanner().Scan(buf)
}

// redactRequestURI returns the request URI with every value of every known
// auth-bearing query parameter replaced by "<redacted>". The original URL
// passed to the upstream is never modified — this is purely for log output.
func redactRequestURI(u *url.URL) string {
	if u == nil {
		return ""
	}
	q := u.Query()
	mutated := false
	for k := range q {
		if _, hit := redactQueryParams[strings.ToLower(k)]; hit {
			q.Set(k, "<redacted>")
			mutated = true
		}
	}
	if !mutated {
		return u.RequestURI()
	}
	clone := *u
	clone.RawQuery = q.Encode()
	return clone.RequestURI()
}

func logResponse(logger *log.Logger, id uint64, resp *http.Response) {
	var b strings.Builder
	fmt.Fprintf(&b, "\n--- [#%d] RESPONSE %d %s ---\n", id, resp.StatusCode, resp.Request.URL.RequestURI())
	writeHeaders(&b, resp.Header)

	ct := resp.Header.Get("Content-Type")
	if isStreaming(ct) {
		fmt.Fprintf(&b, "<body: streaming %s — not buffered>\n", ct)
		logger.Print(b.String())
		return
	}

	buf, err := io.ReadAll(resp.Body)
	_ = resp.Body.Close()
	resp.Body = io.NopCloser(bytes.NewReader(buf))
	if err != nil {
		fmt.Fprintf(&b, "<body read error: %v>\n", err)
		logger.Print(b.String())
		return
	}

	encoding := resp.Header.Get("Content-Encoding")
	logBody := buf
	if encoding != "" {
		decoded, derr := decode(buf, encoding)
		if derr != nil {
			fmt.Fprintf(&b, "<body: %d bytes %s — decode error: %v>\n", len(buf), encoding, derr)
			logger.Print(b.String())
			return
		}
		fmt.Fprintf(&b, "<body: %d bytes %s, decoded to %d bytes>\n", len(buf), encoding, len(decoded))
		logBody = decoded
	}
	writeBody(&b, logBody, ct)
	logger.Print(b.String())
}

func decode(buf []byte, encoding string) ([]byte, error) {
	var r io.ReadCloser
	switch strings.ToLower(strings.TrimSpace(encoding)) {
	case "gzip", "x-gzip":
		gr, err := gzip.NewReader(bytes.NewReader(buf))
		if err != nil {
			return nil, err
		}
		r = gr
	case "deflate":
		// Some servers send raw deflate, others zlib-wrapped — try zlib first.
		if zr, err := zlib.NewReader(bytes.NewReader(buf)); err == nil {
			r = zr
		} else {
			r = flate.NewReader(bytes.NewReader(buf))
		}
	case "br":
		r = io.NopCloser(brotli.NewReader(bytes.NewReader(buf)))
	case "zstd":
		zr, err := zstd.NewReader(bytes.NewReader(buf))
		if err != nil {
			return nil, err
		}
		r = zr.IOReadCloser()
	default:
		return nil, fmt.Errorf("unsupported encoding %q", encoding)
	}
	defer r.Close()
	return io.ReadAll(r)
}

func writeHeaders(b *strings.Builder, h http.Header) {
	for k, vs := range h {
		if _, redact := redactHeaders[strings.ToLower(k)]; redact {
			fmt.Fprintf(b, "%s: <redacted>\n", k)
			continue
		}
		for _, v := range vs {
			fmt.Fprintf(b, "%s: %s\n", k, v)
		}
	}
}

func writeBody(b *strings.Builder, body []byte, contentType string) {
	if len(body) == 0 {
		return
	}
	const max = 64 * 1024
	if len(body) > max {
		fmt.Fprintf(b, "\n<body truncated: %d bytes, showing first %d>\n", len(body), max)
		b.Write(body[:max])
		b.WriteString("\n")
		return
	}
	b.WriteString("\n")
	b.Write(body)
	if len(body) > 0 && body[len(body)-1] != '\n' {
		b.WriteString("\n")
	}
}

func isStreaming(contentType string) bool {
	ct := strings.ToLower(contentType)
	return strings.HasPrefix(ct, "text/event-stream") ||
		strings.Contains(ct, "stream+json")
}

type ctxKey int

const ctxKeyReqID ctxKey = 1

func contextWithReqID(parent context.Context, id uint64) context.Context {
	return context.WithValue(parent, ctxKeyReqID, id)
}
