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

// demo replays a masqr log file with color and pacing so you can show off what
// masqr intercepted during a session.
//
//	go run ./demo masqr-20260515-220022.log
//	go run ./demo --auto 1s masqr.log
//	go run ./demo --only-alerts masqr.log     # skip boring requests
package main

import (
	"bufio"
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"os"
	"os/signal"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"syscall"
	"time"

	"golang.org/x/term"
)

// --- ANSI palette (256-color, mirrors masqr's banner) -------------------------

const (
	reset  = "\x1b[0m"
	bold   = "\x1b[1m"
	dim    = "\x1b[2m"
	italic = "\x1b[3m"

	clrCritical = "\x1b[38;5;196m" // bright red
	clrHigh     = "\x1b[38;5;208m" // orange
	clrMedium   = "\x1b[38;5;220m" // gold
	clrLow      = "\x1b[38;5;39m"  // blue
	clrOK       = "\x1b[38;5;42m"  // green
	clrInfo     = "\x1b[38;5;111m" // soft blue
	clrMuted    = "\x1b[38;5;240m" // gray
	clrWhite    = "\x1b[38;5;255m"
	clrBlock    = "\x1b[48;5;160m\x1b[38;5;231m" // red bg, white fg
	clrRedact   = "\x1b[48;5;100m\x1b[38;5;231m" // olive bg, white fg
	clrForward  = "\x1b[48;5;28m\x1b[38;5;231m"  // green bg, white fg
	clrPlace    = "\x1b[38;5;213m"               // magenta — placeholder tokens
)

func sevColor(sev string) string {
	switch sev {
	case "critical":
		return clrCritical
	case "high":
		return clrHigh
	case "medium":
		return clrMedium
	case "low":
		return clrLow
	}
	return clrMuted
}

// --- Log parser --------------------------------------------------------------

type alert struct {
	Severity, Category, RuleID, Snippet string
	Offset                              int
	End                                 int // exclusive; 0 when the log was written by an older masqr
}

type event struct {
	kind   string // "request" | "alerts" | "response" | "blocked" | "redacted"
	id     int
	method string // request
	url    string
	status int // response
	body   string
	hdrs   []string
	alerts []alert
	// blocked
	blockedCount int
	blockedFloor string
	// redacted
	redactedCount      int
	redactedSizeBefore int
	redactedSizeAfter  int
}

var (
	reReq    = regexp.MustCompile(`^--- \[#(\d+)\] REQUEST (\S+) (.+) ---$`)
	reResp   = regexp.MustCompile(`^--- \[#(\d+)\] RESPONSE (\d+) (.+) ---$`)
	reAlerts = regexp.MustCompile(`^--- \[#(\d+)\] ALERTS \((\d+)\) ---$`)
	// `@N..M` is the current shape; `@N` is the older shape (no End). Both
	// must parse so a fresh demo binary can replay legacy log files.
	reAlert  = regexp.MustCompile(`^\s*\[(\w+)/([^\]]+)\]\s+(\S+)\s+@(\d+)(?:\.\.(\d+))?\s+:\s+(.+)$`)
	reBlock  = regexp.MustCompile(`\[#(\d+)\] BLOCKED by policy \((\d+) finding\(s\) >= (\w+)\)`)
	reRedact = regexp.MustCompile(`\[#(\d+)\] REDACTED (\d+) finding\(s\); forwarding (\d+)-byte body \(was (\d+)\)`)
	reStamp  = regexp.MustCompile(`^\d{4}/\d{2}/\d{2} \d{2}:\d{2}:\d{2}(?:\.\d+)?\s?`)
	reHdr    = regexp.MustCompile(`^[A-Za-z][A-Za-z0-9-]*:\s`)
)

// parser is an incremental, line-fed log parser. Feed lines as they arrive;
// each call returns any events that completed because of this line. Call Flush
// at EOF (only for non-follow reads) to drain a trailing in-progress event.
type parser struct {
	cur      *event
	inAlerts bool
}

func (p *parser) Feed(raw string) []event {
	line := reStamp.ReplaceAllString(raw, "")
	if line == "" {
		if p.cur != nil && !p.inAlerts {
			p.cur.body += "\n"
		}
		return nil
	}

	var out []event
	flush := func() {
		if p.cur != nil {
			out = append(out, *p.cur)
			p.cur = nil
			p.inAlerts = false
		}
	}

	if m := reReq.FindStringSubmatch(line); m != nil {
		flush()
		id, _ := strconv.Atoi(m[1])
		p.cur = &event{kind: "request", id: id, method: m[2], url: m[3]}
		return out
	}
	if m := reResp.FindStringSubmatch(line); m != nil {
		flush()
		id, _ := strconv.Atoi(m[1])
		st, _ := strconv.Atoi(m[2])
		p.cur = &event{kind: "response", id: id, status: st, url: m[3]}
		return out
	}
	if m := reAlerts.FindStringSubmatch(line); m != nil {
		p.inAlerts = true
		if p.cur == nil {
			id, _ := strconv.Atoi(m[1])
			p.cur = &event{kind: "alerts", id: id}
		} else {
			// Alerts arrive inside the REQUEST block in masqr's logger; keep
			// them attached to that request.
			p.cur.kind = "request"
		}
		return out
	}
	if m := reBlock.FindStringSubmatch(line); m != nil {
		id, _ := strconv.Atoi(m[1])
		cnt, _ := strconv.Atoi(m[2])
		out = append(out, event{kind: "blocked", id: id, blockedCount: cnt, blockedFloor: m[3]})
		return out
	}
	if m := reRedact.FindStringSubmatch(line); m != nil {
		id, _ := strconv.Atoi(m[1])
		cnt, _ := strconv.Atoi(m[2])
		after, _ := strconv.Atoi(m[3])
		before, _ := strconv.Atoi(m[4])
		out = append(out, event{
			kind: "redacted", id: id,
			redactedCount: cnt, redactedSizeBefore: before, redactedSizeAfter: after,
		})
		return out
	}

	if p.cur == nil {
		return nil
	}
	if p.inAlerts {
		if a := reAlert.FindStringSubmatch(line); a != nil {
			off, _ := strconv.Atoi(a[4])
			end, _ := strconv.Atoi(a[5]) // empty for legacy logs → 0
			p.cur.alerts = append(p.cur.alerts, alert{
				Severity: a[1], Category: a[2], RuleID: a[3],
				Offset: off, End: end, Snippet: a[6],
			})
		}
		return nil
	}
	if reHdr.MatchString(line) {
		p.cur.hdrs = append(p.cur.hdrs, line)
	} else {
		p.cur.body += line + "\n"
	}
	return nil
}

func (p *parser) Flush() []event {
	if p.cur == nil {
		return nil
	}
	out := []event{*p.cur}
	p.cur = nil
	p.inAlerts = false
	return out
}

// --- Scene grouping ----------------------------------------------------------

type scene struct {
	id       int
	req      *event
	blocked  *event
	redacted *event
	response *event
}

func toScenes(events []event) []scene {
	idx := map[int]*scene{}
	var order []int
	for i := range events {
		e := &events[i]
		s, ok := idx[e.id]
		if !ok {
			s = &scene{id: e.id}
			idx[e.id] = s
			order = append(order, e.id)
		}
		switch e.kind {
		case "request", "alerts":
			s.req = e
		case "blocked":
			s.blocked = e
		case "redacted":
			s.redacted = e
		case "response":
			s.response = e
		}
	}
	out := make([]scene, 0, len(order))
	for _, id := range order {
		out = append(out, *idx[id])
	}
	return out
}

// --- Redaction reconstruction -------------------------------------------------
//
// The masqr log captures the original request body plus alert spans (offset,
// end). We replay masqr's placeholder allocation in the demo so we can render
// "sent upstream" alongside "original". The label table mirrors
// redact.go:labelOverrides — kept duplicated rather than importing the masqr
// package because the demo lives in its own main package.

var demoLabelOverrides = map[string]string{
	"email-address":           "EMAIL",
	"credit-card":             "CARD",
	"private-ipv4":            "IP",
	"private-ipv6":            "IP",
	"generic-base64-blob":     "SECRET",
	"aws-access-key-id":       "AWS_KEY",
	"aws-secret-access-key":   "AWS_KEY",
	"anthropic-api-key":       "ANTHROPIC_KEY",
	"openai-api-key":          "OPENAI_KEY",
	"gcp-api-key":             "GCP_KEY",
	"gcp-service-account-key": "GCP_KEY",
	"github-pat":              "GH_TOKEN",
	"github-fine-grained-pat": "GH_TOKEN",
	"gitlab-pat":              "GL_TOKEN",
	"slack-bot-or-user-token": "SLACK_TOKEN",
	"slack-webhook":           "SLACK_WEBHOOK",
	"jwt":                     "JWT",
	"private-key-pem":         "PRIVATE_KEY",
	"stripe-live-key":         "STRIPE_KEY",
}

func demoLabel(ruleID string) string {
	// Strip the recursive-decode suffix the scanner adds when a base64 blob
	// is decoded and rescanned (e.g. `aws-access-key-id/base64-decoded`).
	if i := strings.Index(ruleID, "/"); i >= 0 {
		ruleID = ruleID[:i]
	}
	if v, ok := demoLabelOverrides[ruleID]; ok {
		return v
	}
	return "VAR"
}

type replacement struct {
	Placeholder string
	Raw         string
}

// applyRedactions returns the body masqr would have forwarded upstream plus
// the placeholder ↔ original mapping. urlShift is the length of the synthetic
// `url: <uri>\n` preamble scanRequest prepends to its scan buffer — every
// alert offset in the log is relative to that buffer, so the demo has to
// subtract it before indexing into the body.
//
// Returns ("", nil) when the math doesn't line up (legacy log without End
// offsets, or a URL whose log-time redaction shifted lengths). The caller
// falls back to showing only the original in that case.
func applyRedactions(body string, alerts []alert, urlShift int) (string, []replacement) {
	type span struct {
		start, end  int
		placeholder string
	}
	nextN := map[string]int{}
	byIdentity := map[string]string{}
	rawOf := map[string]string{}

	spans := make([]span, 0, len(alerts))
	for _, a := range alerts {
		if a.End <= a.Offset {
			return "", nil // legacy log (no End)
		}
		s := a.Offset - urlShift
		e := a.End - urlShift
		if s < 0 || e > len(body) {
			return "", nil
		}
		raw := body[s:e]
		identity := a.RuleID + "\x00" + raw
		ph, ok := byIdentity[identity]
		if !ok {
			label := demoLabel(a.RuleID)
			nextN[label]++
			ph = fmt.Sprintf("__%s_%d__", label, nextN[label])
			byIdentity[identity] = ph
			rawOf[ph] = raw
		}
		spans = append(spans, span{s, e, ph})
	}
	sort.Slice(spans, func(i, j int) bool { return spans[i].start < spans[j].start })

	var sb strings.Builder
	cursor := 0
	for _, sp := range spans {
		if sp.start < cursor {
			continue
		}
		sb.WriteString(body[cursor:sp.start])
		sb.WriteString(sp.placeholder)
		cursor = sp.end
	}
	sb.WriteString(body[cursor:])

	reps := make([]replacement, 0, len(rawOf))
	for ph, raw := range rawOf {
		reps = append(reps, replacement{Placeholder: ph, Raw: raw})
	}
	sort.Slice(reps, func(i, j int) bool { return reps[i].Placeholder < reps[j].Placeholder })

	return sb.String(), reps
}

// --- Renderer ----------------------------------------------------------------

const lineWidth = 72

func hr(s string, color string) string {
	pad := lineWidth - len(s) - 4
	if pad < 1 {
		pad = 1
	}
	return color + "── " + bold + s + reset + color + " " + strings.Repeat("─", pad) + reset
}

func renderScene(w io.Writer, s scene) {
	fmt.Fprintln(w)
	fmt.Fprintln(w, hr(fmt.Sprintf("REQUEST #%d", s.id), clrInfo))

	// If masqr REDACTED this request, reconstruct the redacted body now so
	// we can render the "original" and "sent upstream" prompts side by side
	// (and the placeholder ↔ original mapping at the bottom).
	var (
		redactedBody string
		mapping      []replacement
	)
	if s.req != nil && s.redacted != nil && len(s.req.alerts) > 0 {
		shift := len("url: ") + len(s.req.url) + 1 // "url: <uri>\n"
		redactedBody, mapping = applyRedactions(strings.TrimSpace(s.req.body), s.req.alerts, shift)
	}

	if s.req != nil {
		fmt.Fprintf(w, "  %s%s %s%s\n", bold, s.req.method, s.req.url, reset)
		ct := pickHeader(s.req.hdrs, "Content-Type")
		if ct != "" {
			fmt.Fprintf(w, "  %scontent-type%s %s\n", dim, reset, ct)
		}
		body := strings.TrimSpace(s.req.body)
		if body != "" {
			origMsgs := extractPromptMessages(body, ct)
			switch {
			case redactedBody != "" && len(origMsgs) > 0:
				fmt.Fprintln(w, dim+"  prompts (original — what the user typed):"+reset)
				renderPromptMessages(w, origMsgs)
				if redMsgs := extractPromptMessages(redactedBody, ct); len(redMsgs) > 0 {
					fmt.Fprintln(w)
					fmt.Fprintln(w, dim+"  prompts (sent upstream — masqr-redacted):"+reset)
					renderPromptMessages(w, redMsgs)
				}
			case len(origMsgs) > 0:
				fmt.Fprintln(w, dim+"  prompts:"+reset)
				renderPromptMessages(w, origMsgs)
			default:
				fmt.Fprintln(w, dim+"  body:"+reset)
				for _, line := range truncate(body, 6, 110) {
					fmt.Fprintf(w, "    %s\n", line)
				}
				if redactedBody != "" {
					fmt.Fprintln(w)
					fmt.Fprintln(w, dim+"  body (sent upstream):"+reset)
					for _, line := range truncate(redactedBody, 6, 110) {
						fmt.Fprintf(w, "    %s\n", line)
					}
				}
			}
		}
	} else {
		fmt.Fprintln(w, dim+"  <no request body captured>"+reset)
	}

	if s.req != nil && len(s.req.alerts) > 0 {
		fmt.Fprintln(w)
		fmt.Fprintf(w, "  %sscanner%s  %d finding(s)\n", clrInfo, reset, len(s.req.alerts))
		for _, a := range s.req.alerts {
			c := sevColor(a.Severity)
			span := fmt.Sprintf("@%d", a.Offset)
			if a.End > a.Offset {
				span = fmt.Sprintf("@%d..%d", a.Offset, a.End)
			}
			fmt.Fprintf(w, "    %s%-9s%s  %s%-28s%s  %s%-14s%s  %s\n",
				c+bold, "["+a.Severity+"]", reset,
				clrWhite, a.RuleID, reset,
				dim, span, reset,
				a.Snippet,
			)
		}
	} else if s.req != nil {
		fmt.Fprintln(w)
		fmt.Fprintf(w, "  %sscanner%s  clean (no findings)\n", clrOK, reset)
	}

	if len(mapping) > 0 {
		fmt.Fprintln(w)
		fmt.Fprintf(w, "  %sredaction map%s\n", clrInfo, reset)
		for _, m := range mapping {
			fmt.Fprintf(w, "    %s%-18s%s  ↔  %s\n",
				clrPlace+bold, m.Placeholder, reset, m.Raw)
		}
	}

	fmt.Fprintln(w)
	switch {
	case s.blocked != nil:
		fmt.Fprintf(w, "  %s MASQR BLOCKED %s  HTTP 451 returned to client  %s(%d finding(s) >= %s)%s\n",
			clrBlock, reset, dim, s.blocked.blockedCount, s.blocked.blockedFloor, reset)
		fmt.Fprintf(w, "  %supstream never contacted%s\n", italic+dim, reset)
	case s.redacted != nil && s.response != nil:
		statusColor := clrOK
		if s.response.status >= 400 {
			statusColor = clrHigh
		}
		if s.response.status >= 500 {
			statusColor = clrCritical
		}
		saved := s.redacted.redactedSizeBefore - s.redacted.redactedSizeAfter
		fmt.Fprintf(w, "  %s MASQR REDACTED %s  upstream → %s%d%s  %s(%d finding(s) replaced, %d bytes saved)%s\n",
			clrRedact, reset, statusColor+bold, s.response.status, reset,
			dim, s.redacted.redactedCount, saved, reset)
		fmt.Fprintf(w, "  %splaceholders restored before reaching the client%s\n", italic+dim, reset)
	case s.redacted != nil:
		fmt.Fprintf(w, "  %s MASQR REDACTED %s  %s(%d finding(s); response not captured yet)%s\n",
			clrRedact, reset, dim, s.redacted.redactedCount, reset)
	case s.response != nil:
		statusColor := clrOK
		if s.response.status >= 400 {
			statusColor = clrHigh
		}
		if s.response.status >= 500 {
			statusColor = clrCritical
		}
		fmt.Fprintf(w, "  %s FORWARDED %s  upstream → %s%d%s %s\n",
			clrForward, reset, statusColor+bold, s.response.status, reset, s.response.url)
	default:
		fmt.Fprintf(w, "  %s(no response captured in log)%s\n", dim, reset)
	}
}

func pickHeader(hdrs []string, key string) string {
	prefix := strings.ToLower(key) + ":"
	for _, h := range hdrs {
		if strings.HasPrefix(strings.ToLower(h), prefix) {
			return strings.TrimSpace(h[len(prefix):])
		}
	}
	return ""
}

func truncate(body string, maxLines, maxCols int) []string {
	lines := strings.Split(body, "\n")
	out := make([]string, 0, maxLines+1)
	for i, ln := range lines {
		if i >= maxLines {
			out = append(out, dim+fmt.Sprintf("… (+%d lines)", len(lines)-i)+reset)
			break
		}
		if len(ln) > maxCols {
			ln = ln[:maxCols] + dim + " …" + reset
		}
		out = append(out, ln)
	}
	return out
}

// --- Prompt extraction (Anthropic / OpenAI shape) -----------------------------

type promptMsg struct {
	Role string
	Text string
}

// extractPromptMessages parses a JSON body and pulls out role-tagged messages
// (Anthropic + OpenAI shape — both put `system` and `messages[]` at the top
// level). Returns nil if the body isn't JSON or has no recognizable prompts.
func extractPromptMessages(body, contentType string) []promptMsg {
	if !strings.Contains(strings.ToLower(contentType), "json") {
		return nil
	}
	var raw map[string]json.RawMessage
	if err := json.Unmarshal([]byte(body), &raw); err != nil {
		return nil
	}
	var out []promptMsg
	if sys, ok := raw["system"]; ok {
		if t := extractText(sys); t != "" {
			out = append(out, promptMsg{Role: "system", Text: t})
		}
	}
	if msgs, ok := raw["messages"]; ok {
		var arr []map[string]json.RawMessage
		if err := json.Unmarshal(msgs, &arr); err == nil {
			for _, m := range arr {
				role := jsonString(m["role"])
				text := extractText(m["content"])
				if text == "" {
					continue
				}
				out = append(out, promptMsg{Role: role, Text: text})
			}
		}
	}
	return out
}

// extractText decodes a JSON value that may be either a bare string or an
// array of {type:"text", text:"..."} blocks (Anthropic content array shape).
func extractText(raw json.RawMessage) string {
	if len(raw) == 0 {
		return ""
	}
	var s string
	if err := json.Unmarshal(raw, &s); err == nil {
		return s
	}
	var arr []map[string]json.RawMessage
	if err := json.Unmarshal(raw, &arr); err == nil {
		var parts []string
		for _, item := range arr {
			if jsonString(item["type"]) != "text" {
				continue
			}
			if t := jsonString(item["text"]); t != "" {
				parts = append(parts, t)
			}
		}
		return strings.Join(parts, "\n")
	}
	return ""
}

func jsonString(raw json.RawMessage) string {
	var s string
	_ = json.Unmarshal(raw, &s)
	return s
}

// renderPromptMessages prints each message with a role tag and the message
// text, truncated for readability. The last user message is shown with a
// taller cap so the actual question the user just typed is visible.
func renderPromptMessages(w io.Writer, msgs []promptMsg) {
	lastUser := -1
	for i, m := range msgs {
		if strings.EqualFold(m.Role, "user") {
			lastUser = i
		}
	}
	for i, m := range msgs {
		c := clrMuted
		switch strings.ToLower(m.Role) {
		case "user":
			c = clrInfo
		case "assistant":
			c = clrOK
		case "system":
			c = clrMedium
		}
		role := strings.ToLower(m.Role)
		if role == "" {
			role = "?"
		}
		fmt.Fprintf(w, "    %s%-9s%s\n", c+bold, role, reset)
		maxLines := 4
		if i == lastUser {
			maxLines = 12
		}
		for _, line := range truncate(strings.TrimSpace(m.Text), maxLines, 100) {
			fmt.Fprintf(w, "      %s\n", line)
		}
	}
}

// --- Interactive loop --------------------------------------------------------

func runInteractive(scenes []scene, auto time.Duration, onlyAlerts bool) {
	tty := term.IsTerminal(int(os.Stdin.Fd()))
	var restore func()
	if tty && auto == 0 {
		old, err := term.MakeRaw(int(os.Stdin.Fd()))
		if err == nil {
			restore = func() { _ = term.Restore(int(os.Stdin.Fd()), old) }
			defer restore()
		}
	}

	visible := 0
	for _, s := range scenes {
		if !shouldShow(s, onlyAlerts) {
			continue
		}
		visible++
	}
	fmt.Printf("%s%smasqr demo%s  replaying %d scene(s)%s%s\n",
		clrInfo, bold, reset, visible,
		controlsHint(auto, tty), reset)

	shown := 0
	for _, s := range scenes {
		if !shouldShow(s, onlyAlerts) {
			continue
		}
		renderScene(os.Stdout, s)
		shown++
		if shown == visible {
			break
		}
		if auto > 0 {
			time.Sleep(auto)
			continue
		}
		if !tty {
			continue
		}
		fmt.Printf("\n  %s[space/enter] next  · [q] quit  · %d/%d%s\r",
			dim, shown, visible, reset)
		if !waitKey() {
			fmt.Println()
			return
		}
		fmt.Print("\r\x1b[K") // clear hint line
	}
	fmt.Printf("\n%s── end of replay (%d scenes) ─%s\n", clrInfo, shown, reset)
}

func controlsHint(auto time.Duration, tty bool) string {
	if auto > 0 {
		return fmt.Sprintf("  %sauto-advance every %s%s", dim, auto, reset)
	}
	if !tty {
		return fmt.Sprintf("  %s(non-tty: printing all)%s", dim, reset)
	}
	return fmt.Sprintf("  %s(space=next, q=quit)%s", dim, reset)
}

// waitKey blocks until the user presses a key; returns false if user quit.
func waitKey() bool {
	buf := make([]byte, 1)
	for {
		n, err := os.Stdin.Read(buf)
		if err != nil || n == 0 {
			return false
		}
		switch buf[0] {
		case 'q', 'Q', 3 /* ^C */, 4 /* ^D */ :
			return false
		case ' ', '\r', '\n':
			return true
		}
	}
}

// --- Follow / tail loop ------------------------------------------------------

func shouldShow(s scene, onlyAlerts bool) bool {
	if !onlyAlerts {
		return true
	}
	if s.blocked != nil || s.redacted != nil {
		return true
	}
	return s.req != nil && len(s.req.alerts) > 0
}

// followLoop tails the log file from its current offset, rendering each new
// scene as it completes. Runs until ctx is cancelled (e.g. Ctrl-C).
func followLoop(ctx context.Context, f *os.File, p *parser, rendered map[int]bool, onlyAlerts bool, poll time.Duration) {
	fmt.Printf("\n%s── following %s · Ctrl-C to quit ─%s\n", clrInfo, f.Name(), reset)

	reader := bufio.NewReader(f)
	scenes := map[int]*scene{}
	var partial strings.Builder

	apply := func(e event) {
		s, ok := scenes[e.id]
		if !ok {
			s = &scene{id: e.id}
			scenes[e.id] = s
		}
		ev := e
		switch e.kind {
		case "request", "alerts":
			s.req = &ev
		case "blocked":
			s.blocked = &ev
		case "redacted":
			s.redacted = &ev
		case "response":
			s.response = &ev
		}
		// A scene is "complete enough" to render when we've seen a verdict
		// (response or blocked) for it. A "redacted" line alone is not a
		// terminal state — the upstream response still has to land.
		if !rendered[e.id] && s.req != nil && (s.blocked != nil || s.response != nil) {
			if shouldShow(*s, onlyAlerts) {
				renderScene(os.Stdout, *s)
			}
			rendered[e.id] = true
		}
	}

	for {
		for {
			line, err := reader.ReadString('\n')
			if len(line) > 0 {
				if !strings.HasSuffix(line, "\n") {
					partial.WriteString(line)
					break
				}
				full := partial.String() + strings.TrimRight(line, "\r\n")
				partial.Reset()
				for _, e := range p.Feed(full) {
					apply(e)
				}
			}
			if err == io.EOF {
				break
			}
			if err != nil {
				fmt.Fprintf(os.Stderr, "read: %v\n", err)
				return
			}
		}
		select {
		case <-ctx.Done():
			fmt.Printf("\n%s── stopped tailing ─%s\n", clrInfo, reset)
			return
		case <-time.After(poll):
		}
	}
}

// --- main --------------------------------------------------------------------

func main() {
	auto := flag.Duration("auto", 0, "auto-advance with this delay (0 = wait for keypress)")
	onlyAlerts := flag.Bool("only-alerts", false, "skip scenes with no findings or block")
	follow := flag.Bool("follow", true, "after replaying the backlog, keep tailing the log for new requests (Ctrl-C to quit)")
	poll := flag.Duration("poll", 200*time.Millisecond, "polling interval for --follow")
	flag.Usage = func() {
		fmt.Fprintf(os.Stderr, "usage: %s [flags] <masqr-log-file>\n\nflags:\n", os.Args[0])
		flag.PrintDefaults()
	}
	flag.Parse()

	if flag.NArg() != 1 {
		flag.Usage()
		os.Exit(2)
	}
	path := flag.Arg(0)

	f, err := os.Open(path)
	if err != nil {
		fmt.Fprintf(os.Stderr, "open %s: %v\n", path, err)
		os.Exit(1)
	}
	defer f.Close()

	// Parse the backlog with a stateful parser so we can keep using it for
	// follow mode (preserves any in-progress event at EOF).
	p := &parser{}
	sc := bufio.NewScanner(f)
	sc.Buffer(make([]byte, 0, 1<<20), 1<<24)
	var events []event
	for sc.Scan() {
		events = append(events, p.Feed(sc.Text())...)
	}
	if err := sc.Err(); err != nil {
		fmt.Fprintf(os.Stderr, "parse %s: %v\n", path, err)
		os.Exit(1)
	}
	// Only flush in non-follow mode. In follow mode the trailing event may
	// still receive its RESPONSE/ALERTS lines as more bytes arrive, and
	// flushing now would lock in an incomplete scene.
	if !*follow {
		events = append(events, p.Flush()...)
	}
	scenes := toScenes(events)

	rendered := map[int]bool{}
	for _, s := range scenes {
		rendered[s.id] = true
	}
	if len(scenes) > 0 {
		runInteractive(scenes, *auto, *onlyAlerts)
	} else if !*follow {
		fmt.Fprintf(os.Stderr, "no REQUEST/RESPONSE blocks found in %s\n", path)
		os.Exit(1)
	}

	if *follow {
		ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
		defer stop()
		followLoop(ctx, f, p, rendered, *onlyAlerts, *poll)
	}
}
