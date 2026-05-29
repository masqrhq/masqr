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
	"fmt"
	"io"
	"os"

	"golang.org/x/term"
)

var bannerLogo = []string{
	"▟█▙ ▟█▙",
	"▜█▄▄▄█▛",
	" ▘   ▘ ",
}

// Crimson → gold gradient.
var bannerGradient = []int{160, 208, 220}

func printBanner(w io.Writer, endpoint string, provider Provider, logPath string) {
	color := shouldColor(w)
	paint := func(c int, s string) string {
		if !color {
			return s
		}
		return fmt.Sprintf("\x1b[38;5;%dm%s\x1b[0m", c, s)
	}
	dim := func(s string) string {
		if !color {
			return s
		}
		return "\x1b[2m" + s + "\x1b[0m"
	}
	bold := func(s string) string {
		if !color {
			return s
		}
		return "\x1b[1m" + s + "\x1b[0m"
	}

	// Provider tag only renders when we recognised the child — the generic
	// fall-through (no profile) shows the bare arrow so we don't claim to
	// support something we didn't recognise.
	tag := ""
	if provider.Name != "" && provider.Name != "generic" {
		tag = dim(" [") + paint(bannerGradient[2], provider.Name) + dim("]")
	}

	// Routes line ("+ /v1internal → cloudcode-pa.googleapis.com") only
	// appears when the profile carries a route. Crucial for the Gemini
	// OAuth user — without this hint, a glance at the banner reads as
	// "only generativelanguage.googleapis.com is proxied", which is
	// misleading the moment they're not in API-key mode.
	logLine := dim("log: ") + logPath
	if len(provider.Routes) > 0 {
		r := provider.Routes[0]
		logLine = dim("+ ") + r.PathPrefix + dim(" → ") + r.Target
	}

	info := []string{
		bold("masqr") + dim("  · deep prompt inspection") + tag,
		endpoint + dim(" → ") + provider.Target,
		logLine,
	}

	fmt.Fprintln(w)
	for i, line := range bannerLogo {
		fmt.Fprintf(w, " %s   %s\n", paint(bannerGradient[i], line), info[i])
	}
	// When a route line displaced the log path on the third banner line,
	// emit the log path on its own dim line so it doesn't disappear.
	if len(provider.Routes) > 0 {
		fmt.Fprintf(w, "          %s\n", dim("log: ")+logPath)
	}
	fmt.Fprintln(w)
}

func shouldColor(w io.Writer) bool {
	if os.Getenv("NO_COLOR") != "" {
		return false
	}
	if os.Getenv("TERM") == "dumb" {
		return false
	}
	f, ok := w.(*os.File)
	if !ok {
		return false
	}
	return term.IsTerminal(int(f.Fd()))
}
