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
	"regexp"
	"strconv"
	"strings"
)

// unicodeEscapeRunPattern matches runs of 4+ contiguous \uXXXX escapes.
var unicodeEscapeRunPattern = regexp.MustCompile(`(?:\\u[0-9A-Fa-f]{4}){4,}`)

func findUnicodeEscapeCandidates(body []byte) []base64Hit {
	locs := unicodeEscapeRunPattern.FindAllIndex(body, -1)
	if len(locs) == 0 {
		return nil
	}
	out := make([]base64Hit, 0, len(locs))
	for _, l := range locs {
		out = append(out, base64Hit{text: string(body[l[0]:l[1]]), offset: l[0]})
	}
	return out
}

func decodeUnicodeEscapes(s string) (string, bool) {
	var b strings.Builder
	for i := 0; i+6 <= len(s); i += 6 {
		v, err := strconv.ParseUint(s[i+2:i+6], 16, 32)
		if err != nil {
			return "", false
		}
		b.WriteRune(rune(v))
	}
	return b.String(), b.Len() > 0
}
