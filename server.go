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

// forwardRewritten swaps in a masked request body and forwards it upstream,
// forcing identity response encoding so the restorer can swap placeholders back
// on the wire without an in-memory gzip/br/zstd round-trip.
func forwardRewritten(w http.ResponseWriter, r *http.Request, proxy http.Handler, body []byte) {
	r.Body = io.NopCloser(bytes.NewReader(body))
	r.ContentLength = int64(len(body))
	r.Header.Set("Content-Length", fmt.Sprintf("%d", len(body)))
	r.Header.Set("Accept-Encoding", "identity")
	proxy.ServeHTTP(w, r)
}

// forwardMaskedRequest redacts matches and forwards the rewritten body upstream,
// returning false (writing nothing) if any match can't be safely rewritten in
// place. For a compressed request (codex's zstd) it redacts the decoded payload
// — whose offsets the matches were computed against — and forwards it
// uncompressed, dropping Content-Encoding so the upstream reads plain JSON. The
// proxy's ModifyResponse restores originals into the reply stream.
func forwardMaskedRequest(w http.ResponseWriter, r *http.Request, proxy http.Handler, rawBody, decodedBody []byte, matches []Match, shift int, enc string, memo *findingMemo) bool {
	src := rawBody
	stripEncoding := false
	if enc != "" {
		// Body was compressed; redact the decoded view and forward it plain.
		src = decodedBody
		stripEncoding = true
	}
	if !canRedactAll(matches, src, shift, "") {
		return false
	}
	rewritten := redactSpans(src, matches, shift, memo)
	if stripEncoding {
		r.Header.Del("Content-Encoding")
	}
	forwardRewritten(w, r, proxy, rewritten)
	return true
}

// newProxy builds the scan/redact/block reverse-proxy handler. transport is an
// optional custom RoundTripper; callers pass nil to use http.DefaultTransport.
func newProxy(upstream *url.URL, logger *log.Logger, policy Policy, transport http.RoundTripper) http.Handler {
	memo := newFindingMemo()
	consent := newMaskConsent()

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
		debugScanTrace(id, r, body, matches)

		// decodedBody is the request payload the rule engine and the mask
		// machinery reason over: identical to body for plaintext requests, but
		// the decompressed form for a compressed one (codex sends zstd). Match
		// offsets are relative to this view, so masking redacts against it.
		decodedBody := body
		enc := r.Header.Get("Content-Encoding")
		if enc != "" && len(body) > 0 {
			if d, derr := decode(body, enc); derr == nil {
				decodedBody = d
			}
		}

		// interactive marks a chat/generation request to a provider whose body
		// format and response shape masqr understands — the providers that get
		// the rich, model-turn block message plus interactive mask-and-continue
		// (originally agy-only). Everything else falls back to writeBlockResponse.
		interactive := interactiveMaskProvider(policy.Provider.Name) &&
			isModelTurnPath(policy.Provider.Name, r.URL.Path)
		streaming := wantsStreaming(policy.Provider.Name, r, decodedBody)
		reqModel := jsonStringField(decodedBody, "model")

		// A `mask` reply consenting to a prior block is honored even though that
		// turn carries no finding of its own — so it's checked before the
		// has-findings gate. From here on the approved value(s) are auto-masked
		// instead of blocked.
		if interactive && consent.hasPending() &&
			isMaskAffirmation(extractUserRequest(latestUserTextFor(policy.Provider.Name, decodedBody))) {
			approved := consent.approvePending()
			logger.Printf("[#%d] MASK consent granted for %d value(s)", id, approved)
			debugOutcome(id, "MASK-CONSENT-ACK", nil)
			writeModelTurn(w, policy.Provider, maskAckText(approved), streaming, r.URL.Path, reqModel)
			return
		}

		if blocking := policy.triggering(matches); len(blocking) > 0 {
			shift := urlPrefixLen(r.URL)

			// Classify: every triggering match is either redactable
			// (in-body span with a stable Identity) or not (URL hits,
			// base64 recursive sub-matches, sources that don't expose
			// raw bytes). If any match in this request isn't
			// redactable, we have to block — silently dropping a URL-
			// borne credential without rewriting the URL would still
			// forward it to the upstream.
			if policy.OnFinding == OnFindingRedact &&
				forwardMaskedRequest(w, r, proxy, body, decodedBody, blocking, shift, enc, memo) {
				logger.Printf("[#%d] REDACTED %d finding(s); forwarding", id, len(blocking))
				debugOutcome(id, "REDACTED", nil)
				return
			}

			// Interactive providers support mask-and-continue. (Redact mode
			// already returned above; reaching here means block, or redact with
			// an un-redactable finding. The `mask` consent reply itself is
			// handled before the has-findings gate above.)
			if interactive {
				// (b) split into already-consented vs still-blocking.
				var consented, rest []Match
				for _, m := range blocking {
					if consent.isConsented(m.Identity) {
						consented = append(consented, m)
					} else {
						rest = append(rest, m)
					}
				}

				// (c) nothing left to block → mask the consented values, forward.
				if len(rest) == 0 &&
					forwardMaskedRequest(w, r, proxy, body, decodedBody, consented, shift, enc, memo) {
					logger.Printf("[#%d] MASKED %d consented finding(s); forwarding", id, len(consented))
					debugOutcome(id, "MASKED+FORWARDED (consented)", nil)
					return
				}

				// (d) fresh/partial block → remember the maskable values, offer `mask`.
				pending := maskableIdentities(rest)
				consent.setPending(pending)
				logger.Printf("[#%d] BLOCKED by policy (%d finding(s) >= %s); mask offered=%v",
					id, len(blocking), policy.Threshold, len(pending) > 0)
				debugOutcome(id, "BLOCKED (model turn)", nil)
				advice := blockAdvice(blocking, len(pending) > 0, providerCommand(policy.Provider.Name))
				writeModelTurn(w, policy.Provider, advice, streaming, r.URL.Path, reqModel)
				return
			}

			logger.Printf("[#%d] BLOCKED by policy (%d finding(s) >= %s)", id, len(blocking), policy.Threshold)
			debugOutcome(id, "BLOCKED", nil)
			writeBlockResponse(w, blocking, policy.Provider)
			return
		}

		debugOutcome(id, "FORWARDED (clean)", body)
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
	buf := body
	if u != nil {
		uri := u.RequestURI()
		prefix := "url: " + uri + "\n"
		b := make([]byte, 0, len(prefix)+len(body))
		b = append(b, prefix...)
		b = append(b, body...)
		buf = b
	}
	// Blank out provider protocol blobs (agy/Gemini echo a base64
	// `thoughtSignature` in every model turn) before scanning, so their
	// base64/base58 substrings don't trip generic-base64 / bitcoin-address.
	// Same-length blanking keeps every real finding's offset intact for
	// redaction, and removes the blob so the recursive base64 decode can't
	// re-scan it either.
	return DefaultScanner().Scan(neutralizeOpaqueFields(buf))
}

// opaqueFieldKeys are JSON string fields whose values are provider protocol
// metadata — model-internal blobs that are never user content, so any rule that
// matches inside them is a false positive. `thoughtSignature` is agy/Gemini's
// per-turn base64 thought signature; matching by bare key name is safe because
// it's unique to that protocol. Anthropic's thinking blocks are handled
// structurally instead (see thinkingBlockSpans) since `thinking`/`signature`
// are too generic to blank everywhere.
var opaqueFieldKeys = []string{"thoughtSignature"}

// neutralizeOpaqueFields returns buf with model-internal protocol blobs
// overwritten by spaces (same length, so match offsets elsewhere are
// unchanged): provider key-named blobs (opaqueFieldKeys) plus the `thinking`
// text and `signature` of Anthropic extended-thinking blocks. Returns buf
// itself when there's nothing to blank.
func neutralizeOpaqueFields(buf []byte) []byte {
	spans := append(opaqueSpans(buf), thinkingBlockSpans(buf)...)
	if len(spans) == 0 {
		return buf
	}
	out := append([]byte(nil), buf...)
	for _, s := range spans {
		for i := s[0]; i < s[1] && i < len(out); i++ {
			out[i] = ' '
		}
	}
	return out
}

// opaqueSpans returns the [start,end) byte ranges of the string values of every
// opaqueFieldKeys occurrence in buf. Values are base64 (no embedded quotes), but
// a backslash escape is handled defensively.
func opaqueSpans(buf []byte) [][2]int {
	var spans [][2]int
	for _, key := range opaqueFieldKeys {
		needle := []byte(`"` + key + `"`)
		for from := 0; ; {
			i := bytes.Index(buf[from:], needle)
			if i < 0 {
				break
			}
			i += from
			j := i + len(needle)
			for j < len(buf) && (buf[j] == ' ' || buf[j] == ':' || buf[j] == '\t' || buf[j] == '\n' || buf[j] == '\r') {
				j++
			}
			if j >= len(buf) || buf[j] != '"' {
				from = i + len(needle)
				continue
			}
			start := j + 1
			k := start
			for k < len(buf) {
				if buf[k] == '\\' {
					k += 2
					continue
				}
				if buf[k] == '"' {
					break
				}
				k++
			}
			spans = append(spans, [2]int{start, k})
			from = k + 1
		}
	}
	return spans
}

// thinkingBlockSpans returns the [start,end) byte ranges of the string values
// masqr must never flag or rewrite inside Anthropic extended-thinking content
// blocks: the `thinking` text and `signature` of a {"type":"thinking",…} block,
// and the `data` of a {"type":"redacted_thinking",…} block. The API signs those
// bytes and replays them verbatim; the `signature` reads as a generic-base64-
// blob (sometimes with a base58 substring that trips bitcoin-legacy-address),
// so masqr would otherwise mask it — and rewriting any signed byte makes the
// upstream reject the next turn with 400 "Invalid `signature` in `thinking`
// block". Blanking for scanning only (the forwarded body is untouched) keeps
// the signature valid while leaving the user's own text fully scanned.
//
// Unlike opaqueSpans this is structure-aware — it only blanks `thinking`/
// `signature`/`data` when they're siblings of a thinking `type`, so a field
// that merely shares one of those generic names elsewhere is still scanned.
// It's a best-effort raw-byte walk: on malformed JSON it returns the spans
// found before the parse gave up.
func thinkingBlockSpans(buf []byte) [][2]int {
	p := &jsonSpanScanner{b: buf}
	var spans [][2]int
	p.value(&spans)
	return spans
}

// jsonSpanScanner is a minimal raw-byte JSON walker that preserves exact
// string-value byte spans (encoding/json's tokenizer decodes escapes and so
// loses them, which would break same-length blanking).
type jsonSpanScanner struct {
	b []byte
	i int
}

func (p *jsonSpanScanner) skipWS() {
	for p.i < len(p.b) {
		switch p.b[p.i] {
		case ' ', '\t', '\n', '\r':
			p.i++
		default:
			return
		}
	}
}

// stringSpan assumes the cursor is on an opening quote and returns the
// [start,end) span of the string's contents (between the quotes), advancing
// the cursor past the closing quote. ok is false on an unterminated string.
func (p *jsonSpanScanner) stringSpan() (start, end int, ok bool) {
	if p.i >= len(p.b) || p.b[p.i] != '"' {
		return 0, 0, false
	}
	p.i++
	start = p.i
	for p.i < len(p.b) {
		switch p.b[p.i] {
		case '\\':
			p.i += 2
		case '"':
			end = p.i
			p.i++
			return start, end, true
		default:
			p.i++
		}
	}
	return 0, 0, false
}

// scalar consumes a number/true/false/null up to the next structural byte.
func (p *jsonSpanScanner) scalar() {
	for p.i < len(p.b) {
		switch p.b[p.i] {
		case ',', '}', ']', ' ', '\t', '\n', '\r':
			return
		default:
			p.i++
		}
	}
}

// value parses any JSON value at the cursor, appending thinking-block spans it
// finds. Returns false if it can't make progress (malformed/truncated input).
func (p *jsonSpanScanner) value(spans *[][2]int) bool {
	p.skipWS()
	if p.i >= len(p.b) {
		return false
	}
	switch p.b[p.i] {
	case '{':
		return p.object(spans)
	case '[':
		return p.array(spans)
	case '"':
		_, _, ok := p.stringSpan()
		return ok
	default:
		p.scalar()
		return true
	}
}

func (p *jsonSpanScanner) array(spans *[][2]int) bool {
	p.i++ // consume '['
	p.skipWS()
	if p.i < len(p.b) && p.b[p.i] == ']' {
		p.i++
		return true
	}
	for {
		if !p.value(spans) {
			return false
		}
		p.skipWS()
		if p.i >= len(p.b) {
			return false
		}
		switch p.b[p.i] {
		case ',':
			p.i++
		case ']':
			p.i++
			return true
		default:
			return false
		}
	}
}

func (p *jsonSpanScanner) object(spans *[][2]int) bool {
	p.i++ // consume '{'
	var (
		isThinking, isRedacted       bool
		thinkSpan, sigSpan, dataSpan [2]int
		haveThink, haveSig, haveData bool
	)
	p.skipWS()
	if p.i < len(p.b) && p.b[p.i] == '}' {
		p.i++
		return true
	}
	for {
		p.skipWS()
		ks, ke, ok := p.stringSpan()
		if !ok {
			return false
		}
		key := string(p.b[ks:ke])
		p.skipWS()
		if p.i >= len(p.b) || p.b[p.i] != ':' {
			return false
		}
		p.i++ // consume ':'
		p.skipWS()
		// Capture string-value spans for the keys we care about; recurse
		// into anything else so nested thinking blocks are still found.
		if p.i < len(p.b) && p.b[p.i] == '"' {
			vs, ve, ok := p.stringSpan()
			if !ok {
				return false
			}
			switch key {
			case "type":
				switch string(p.b[vs:ve]) {
				case "thinking":
					isThinking = true
				case "redacted_thinking":
					isRedacted = true
				}
			case "thinking":
				thinkSpan, haveThink = [2]int{vs, ve}, true
			case "signature":
				sigSpan, haveSig = [2]int{vs, ve}, true
			case "data":
				dataSpan, haveData = [2]int{vs, ve}, true
			}
		} else if !p.value(spans) {
			return false
		}
		p.skipWS()
		if p.i >= len(p.b) {
			return false
		}
		switch p.b[p.i] {
		case ',':
			p.i++
		case '}':
			p.i++
			if isThinking {
				if haveThink {
					*spans = append(*spans, thinkSpan)
				}
				if haveSig {
					*spans = append(*spans, sigSpan)
				}
			}
			if isRedacted && haveData {
				*spans = append(*spans, dataSpan)
			}
			return true
		default:
			return false
		}
	}
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
