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
	"fmt"
	"log"
	"net/http"
	"os"
	"strings"
	"time"
)

// debugLog, when non-nil (the DEBUG env var is set), receives a verbose trace in
// a *separate* file so an agent can verify, per request: which scanners ran, the
// exact bytes that came in, every finding, the block/mask decision, and the
// exact bytes the remote model received. Off by default.
//
//	DEBUG=1            → human-readable prose  (<session>.debug.log)
//	DEBUG=json         → NDJSON, one event/line (<session>.debug.jsonl)  ← for agents
//	DEBUG=/path/x.log  → that exact path (prose unless the name ends .jsonl)
var (
	debugLog  *log.Logger
	debugJSON bool
)

func setupDebugLog(mainLogPath string) (func(), error) {
	v := os.Getenv("DEBUG")
	if v == "" {
		return func() {}, nil
	}
	debugJSON = strings.EqualFold(v, "json")
	ext := ".debug.log"
	if debugJSON {
		ext = ".debug.jsonl"
	}
	path := strings.TrimSuffix(mainLogPath, ".log") + ext
	if strings.ContainsAny(v, "/\\") || strings.HasSuffix(v, ".log") || strings.HasSuffix(v, ".jsonl") {
		path = v
		debugJSON = strings.HasSuffix(v, ".jsonl")
	}
	f, err := os.OpenFile(path, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0o644)
	if err != nil {
		return func() {}, err
	}
	flags := 0 // JSON lines carry their own ts field; prose gets timestamp flags
	if !debugJSON {
		flags = log.LstdFlags | log.Lmicroseconds
	}
	debugLog = log.New(f, "", flags)
	if !debugJSON {
		debugLog.Printf("DEBUG trace enabled → %s", path)
	}
	return func() { _ = f.Close(); debugLog = nil }, nil
}

func emitJSON(ev map[string]any) {
	ev["ts"] = time.Now().UTC().Format(time.RFC3339Nano)
	b, err := json.Marshal(ev)
	if err != nil {
		return
	}
	debugLog.Println(string(b))
}

// debugScanTrace records scan coverage (so every regex rule + external source is
// provably exercised), the incoming body, and every finding.
func debugScanTrace(id uint64, r *http.Request, body []byte, matches []Match) {
	if debugLog == nil {
		return
	}
	sc := DefaultScanner()
	if debugJSON {
		findings := make([]map[string]any, 0, len(matches))
		for _, m := range matches {
			findings = append(findings, map[string]any{
				"rule": m.RuleID, "category": m.Category, "severity": string(m.Severity),
				"offset": m.Offset, "end": m.End, "snippet": m.Snippet, "identity": m.Identity,
			})
		}
		emitJSON(map[string]any{
			"id": id, "event": "scan", "method": r.Method, "path": r.URL.RequestURI(),
			"coverage": map[string]any{"rules": sc.RuleCount(), "sources": sc.SourceNames()},
			"req_bytes": len(body), "req": string(body), "findings": findings,
		})
		return
	}
	var b strings.Builder
	fmt.Fprintf(&b, "\n========== [#%d] %s %s ==========\n", id, r.Method, r.URL.RequestURI())
	fmt.Fprintf(&b, "scanned by: %d builtin regex rules + sources [%s]\n",
		sc.RuleCount(), strings.Join(sc.SourceNames(), ", "))
	fmt.Fprintf(&b, "--- request body in (%d bytes — what arrived) ---\n%s\n", len(body), body)
	if len(matches) == 0 {
		b.WriteString("--- findings: NONE (clean) ---\n")
	} else {
		fmt.Fprintf(&b, "--- findings (%d) ---\n", len(matches))
		for _, m := range matches {
			fmt.Fprintf(&b, "  [%s/%s] %s @%d..%d snippet=%q identity=%q\n",
				m.Severity, m.Category, m.RuleID, m.Offset, m.End, m.Snippet, m.Identity)
		}
	}
	debugLog.Print(b.String())
}

// debugOutcome records the decision and the exact bytes the remote model
// received. A nil forwarded body means the request was answered locally
// (blocked/consent-ack) and the model got NONE of this prompt.
func debugOutcome(id uint64, decision string, forwarded []byte) {
	if debugLog == nil {
		return
	}
	if debugJSON {
		ev := map[string]any{"id": id, "event": "outcome", "decision": decision, "sent_upstream": forwarded != nil}
		if forwarded == nil {
			ev["forwarded"] = nil
		} else {
			ev["forwarded"] = string(forwarded)
			ev["fwd_bytes"] = len(forwarded)
		}
		emitJSON(ev)
		return
	}
	if forwarded == nil {
		debugLog.Printf("[#%d] OUTCOME %s — nothing sent upstream; the remote model received NONE of this prompt", id, decision)
		return
	}
	debugLog.Printf("[#%d] OUTCOME %s — sent to remote model (%d bytes — what the model got):\n%s", id, decision, len(forwarded), forwarded)
}
