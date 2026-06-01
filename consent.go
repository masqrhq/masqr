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
	"strings"
	"sync"
)

// maskConsent tracks, for one masqr session, which flagged values the user has
// approved to auto-mask. On agy's streaming path a blocked turn offers "reply
// `mask` to mask and continue"; when the user does, the pending findings move
// into the consented set and are redacted on every later turn instead of
// blocking — so the conversation continues without the value ever reaching the
// model in the clear. One masqr process wraps one session, so process-level
// state is the session.
type maskConsent struct {
	mu        sync.Mutex
	pending   []string        // finding identities offered in the last block, awaiting `mask`
	consented map[string]bool // approved identities, masked from here on
}

func newMaskConsent() *maskConsent { return &maskConsent{consented: map[string]bool{}} }

func (c *maskConsent) isConsented(id string) bool {
	if id == "" {
		return false
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.consented[id]
}

func (c *maskConsent) hasPending() bool {
	c.mu.Lock()
	defer c.mu.Unlock()
	return len(c.pending) > 0
}

func (c *maskConsent) setPending(ids []string) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.pending = ids
}

// approvePending moves the pending identities into the consented set and returns
// how many newly distinct values were approved.
func (c *maskConsent) approvePending() int {
	c.mu.Lock()
	defer c.mu.Unlock()
	n := 0
	for _, id := range c.pending {
		if !c.consented[id] {
			c.consented[id] = true
			n++
		}
	}
	c.pending = nil
	return n
}

// maskableIdentities returns the distinct, non-empty Identity fingerprints among
// matches — the values that *can* be masked (an empty Identity means the source
// won't commit to a stable raw form, so it can only block).
func maskableIdentities(ms []Match) []string {
	var ids []string
	seen := map[string]bool{}
	for _, m := range ms {
		if m.Identity != "" && !seen[m.Identity] {
			seen[m.Identity] = true
			ids = append(ids, m.Identity)
		}
	}
	return ids
}

// isMaskAffirmation reports whether a bare user reply means "yes, mask it".
func isMaskAffirmation(s string) bool {
	switch strings.ToLower(strings.TrimSpace(s)) {
	case "mask", "mask it", "yes", "y", "redact", "ok":
		return true
	}
	return false
}

type contentTurn struct {
	Role  string `json:"role"`
	Parts []struct {
		Text string `json:"text"`
	} `json:"parts"`
}

// latestUserText returns the concatenated text of the most recent user turn in a
// Gemini / Code Assist request body ({"contents":[…]} — agy nests it under
// "request"). Empty when it can't be parsed.
func latestUserText(body []byte) string {
	var top struct {
		Contents []contentTurn `json:"contents"`
		Request  *struct {
			Contents []contentTurn `json:"contents"`
		} `json:"request"`
	}
	if err := json.Unmarshal(body, &top); err != nil {
		return ""
	}
	contents := top.Contents
	if len(contents) == 0 && top.Request != nil {
		contents = top.Request.Contents
	}
	for i := len(contents) - 1; i >= 0; i-- {
		if contents[i].Role == "user" || contents[i].Role == "" {
			var b strings.Builder
			for _, p := range contents[i].Parts {
				b.WriteString(p.Text)
			}
			return b.String()
		}
	}
	return ""
}

// extractUserRequest pulls the user's actual words out of agy's prompt envelope
// (it wraps each turn in <USER_REQUEST>…</USER_REQUEST> alongside metadata), so
// a bare "mask" reply is recognisable. Returns the trimmed text unchanged when
// no envelope is present.
func extractUserRequest(s string) string {
	const open, close = "<USER_REQUEST>", "</USER_REQUEST>"
	if i := strings.Index(s, open); i >= 0 {
		s = s[i+len(open):]
		if j := strings.Index(s, close); j >= 0 {
			s = s[:j]
		}
	}
	return strings.TrimSpace(s)
}
