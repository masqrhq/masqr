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
	"regexp"
	"strconv"
)

// API request envelopes are dense with machine-generated date/time values —
// RFC 3339 timestamps ("current time" metadata) and millisecond Unix epochs
// (request IDs, createdAt fields). Several digit/format-only national-ID rules
// match those by shape alone: the Thai TIN (`th-tnin`, 13 digits + checksum)
// collides with a 13-digit ms epoch (~1 in 11 epochs even pass the checksum),
// and the Singapore UEN (`sg-uen`, \d{9}[A-Z]) collides with the
// fractional-seconds+`Z` tail of a nanosecond ISO timestamp. That blocked
// essentially every Antigravity prompt on the metadata alone.
//
// suppressMachineTimestamps drops any finding whose matched span is, *in
// context*, genuinely a timestamp or ms epoch — verified, not merely numeric,
// so a real ID typed in prose (not slash/JSON-delimited, not inside a full
// RFC 3339 string) is left to fire normally. Runs at recursion depth 0 where
// the full surrounding bytes are available.
func suppressMachineTimestamps(body []byte, in []Match) []Match {
	if len(in) == 0 {
		return in
	}
	out := in[:0]
	for _, m := range in {
		if m.Offset >= 0 && m.End > m.Offset && m.End <= len(body) &&
			(spanIsWithinTimestamp(body, m.Offset, m.End) || spanIsEpochMillis(body, m.Offset, m.End)) {
			continue
		}
		out = append(out, m)
	}
	return out
}

// rfc3339Re matches an RFC 3339 / ISO 8601 date-time, with optional
// fractional seconds and optional `Z`/offset. Used to confirm a finding sits
// *inside* a real timestamp rather than coincidentally resembling part of one.
var rfc3339Re = regexp.MustCompile(`\d{4}-\d{2}-\d{2}[Tt ]\d{2}:\d{2}:\d{2}(?:\.\d+)?(?:[Zz]|[+-]\d{2}:?\d{2})?`)

// spanIsWithinTimestamp reports whether [off,end) is fully covered by an
// RFC 3339 timestamp in the surrounding window — e.g. the `321937990Z` tail a
// UEN rule grabbed out of `2026-05-30T00:22:27.321937990Z`.
func spanIsWithinTimestamp(body []byte, off, end int) bool {
	lo := max(0, off-48)
	hi := min(len(body), end+16)
	for _, loc := range rfc3339Re.FindAllIndex(body[lo:hi], -1) {
		if lo+loc[0] <= off && lo+loc[1] >= end {
			return true
		}
	}
	return false
}

// epochKeys are JSON/structured-field name fragments whose value is, by
// convention, a timestamp — used to confirm a 13-digit run is an epoch.
var epochKeys = [][]byte{
	[]byte("time"), []byte("timestamp"), []byte("epoch"), []byte("requestid"),
	[]byte("created"), []byte("updated"), []byte("date"), []byte("_at"),
	[]byte("expir"), []byte("millis"), []byte("instant"),
}

// spanIsEpochMillis reports whether [off,end) is a standalone 13-digit token
// that is (a) a plausible millisecond Unix epoch (≈2001‑09‑09 … 2100) and
// (b) in a machine context — a `/`-delimited ID path segment, or adjacent to a
// time-ish field name. Both gates must hold, so a bare 13-digit national ID in
// natural-language text is NOT suppressed.
func spanIsEpochMillis(body []byte, off, end int) bool {
	if end-off != 13 {
		return false
	}
	for i := off; i < end; i++ {
		if body[i] < '0' || body[i] > '9' {
			return false
		}
	}
	// Must be a standalone run (not a slice of a longer number).
	if off > 0 && body[off-1] >= '0' && body[off-1] <= '9' {
		return false
	}
	if end < len(body) && body[end] >= '0' && body[end] <= '9' {
		return false
	}
	ms, err := strconv.ParseInt(string(body[off:end]), 10, 64)
	if err != nil || ms < 1_000_000_000_000 || ms > 4_102_444_800_000 {
		return false
	}
	return epochInMachineContext(body, off, end)
}

func epochInMachineContext(body []byte, off, end int) bool {
	var left, right byte
	if off > 0 {
		left = body[off-1]
	}
	if end < len(body) {
		right = body[end]
	}
	// `…/<epoch>/…` path segment (e.g. request IDs).
	if left == '/' && right == '/' {
		return true
	}
	// JSON value preceded by a time-ish key within a short window.
	if left == ':' || left == '"' || left == ' ' || left == '/' {
		win := bytes.ToLower(body[max(0, off-64):off])
		for _, k := range epochKeys {
			if bytes.Contains(win, k) {
				return true
			}
		}
	}
	return false
}
