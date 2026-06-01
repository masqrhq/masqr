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
	"os"
	"path/filepath"
	"strings"
)

// Provider is a built-in profile for an LLM CLI: which upstream API(s) the
// proxy should forward to, which environment variables the child CLI reads
// to discover the override base URL, and which header / query-parameter
// names that provider uses for its API key (so we can redact them in logs).
//
// Provider profiles let `masqr gemini` Just Work without the user passing
// `--target` and `--env`. Explicit `--target` / `--env` always win, and an
// explicit `--target` also disables provider Routes (one user-specified
// upstream covers everything).
type Provider struct {
	// Name is a stable identifier used in the banner, in the per-request
	// log header, and to pick a provider-specific error envelope when
	// writing a 451 block response. One of: "anthropic", "google-gemini",
	// "openai", or "generic".
	Name string

	// Target is the primary upstream API base URL the reverse proxy
	// forwards to. Used when no entry in Routes matches the request path.
	Target string

	// Routes are per-path-prefix upstream overrides. They exist because
	// some CLIs talk to multiple Google services from the same binary
	// depending on auth mode — Gemini CLI in OAuth mode hits
	// `cloudcode-pa.googleapis.com/v1internal…`, while the same CLI in
	// API-key mode hits `generativelanguage.googleapis.com/v1beta…`. A
	// single profile with two Routes covers both auth modes off one
	// `masqr gemini` invocation.
	Routes []Route

	// EnvVars are the environment variables the child CLI consults to
	// learn the override base URL. masqr exports each one set to the
	// local listen endpoint before exec'ing the child. Gemini needs two
	// (GOOGLE_GEMINI_BASE_URL for the @google/genai SDK path,
	// CODE_ASSIST_ENDPOINT for the OAuth CodeAssistServer path) — without
	// both, an OAuth-signed-in user's traffic bypasses the proxy
	// entirely.
	EnvVars []string

	// AuthHeaders are headers that may carry the API key. They're added to
	// the global redaction set so they never land in the session log.
	AuthHeaders []string

	// AuthQueryParams are query parameter names that may carry the API key
	// (e.g. Google's `?key=AIza…`). The request-line printer redacts these
	// before writing the log, and the scanner runs over the URL too so a
	// leaked key still gets flagged + blocked even when not in the body.
	AuthQueryParams []string

	// ExtraArgs are command-line flags prepended to the child CLI's
	// argv. They exist because some CLIs ignore the SDK env vars and
	// require an explicit config override. Codex 0.134 is the canonical
	// case: it does not honor OPENAI_BASE_URL, so masqr has to pass
	// `-c openai_base_url="…"` to actually redirect its traffic.
	//
	// Each entry may include the placeholder `{{endpoint}}`, which
	// runCLI substitutes with the masqr listener URL right before exec.
	ExtraArgs []string
}

// Route binds a request-path prefix to an upstream URL. The first matching
// prefix wins; if nothing matches, the proxy falls through to Provider.Target.
type Route struct {
	// PathPrefix is matched against the incoming request's URL path with
	// strings.HasPrefix — case-sensitive, no globbing. For Gemini CLI the
	// canonical prefix is "/v1internal" (which covers loadCodeAssist /
	// onboardUser / countTokens / streamGenerateContent on the Code
	// Assist path).
	PathPrefix string

	// Target is the upstream base URL requests under PathPrefix forward
	// to. Same shape as Provider.Target.
	Target string
}

// genericProvider is the fall-through used when masqr is invoked against a
// command name we don't have a profile for. It carries empty defaults; the
// CLI uses whatever the user supplied via --target / --env.
var genericProvider = Provider{Name: "generic"}

// geminiProfile is shared between the `gemini` and `gemini-cli` aliases so
// edits stay in one place. The two-env-var + two-route setup is the whole
// reason this profile is special: a user signed in via Google OAuth hits
// `cloudcode-pa.googleapis.com/v1internal…` and ignores
// GOOGLE_GEMINI_BASE_URL entirely, so without CODE_ASSIST_ENDPOINT + the
// `/v1internal` route the proxy is a no-op for the free tier.
var geminiProfile = Provider{
	Name:   "google-gemini",
	Target: "https://generativelanguage.googleapis.com",
	Routes: []Route{
		{PathPrefix: "/v1internal", Target: "https://cloudcode-pa.googleapis.com"},
	},
	EnvVars:         []string{"GOOGLE_GEMINI_BASE_URL", "CODE_ASSIST_ENDPOINT"},
	AuthHeaders:     []string{"x-goog-api-key", "authorization"},
	AuthQueryParams: []string{"key", "api_key", "apikey", "access_token"},
}

var anthropicProfile = Provider{
	Name:        "anthropic",
	Target:      "https://api.anthropic.com",
	EnvVars:     []string{"ANTHROPIC_BASE_URL"},
	AuthHeaders: []string{"x-api-key", "anthropic-api-key", "authorization"},
}

// antigravityProfile drives Google's Antigravity CLI (`agy`). Its Code Assist
// client talks to {daily-,}cloudcode-pa.googleapis.com over a path
// (`/v1internal:streamGenerateContent` etc.) identical to Gemini CLI's OAuth
// surface, and ignores GOOGLE_GEMINI_BASE_URL / CODE_ASSIST_ENDPOINT /
// HTTPS_PROXY. It does, however, honor the CLOUD_CODE_URL env var as a full
// endpoint override (recovered from (*CLIAuthProvider).UpdateEndpointURL in the
// v1.0.3 binary), and the scheme of that URL selects the transport: an http://
// value makes the client speak *plaintext* HTTP. So masqr just exports
// CLOUD_CODE_URL=http://<listener> and takes the same plaintext reverse-proxy
// path as every other provider — no transparent-TLS intercept, forged CA,
// LD_PRELOAD shim, /etc/hosts redirect, or :443/sudo needed. The single Route
// mirrors the Target so request rewriting in newProxy stays uniform.
var antigravityProfile = Provider{
	Name:   "antigravity",
	Target: "https://daily-cloudcode-pa.googleapis.com",
	Routes: []Route{
		{PathPrefix: "/v1internal", Target: "https://daily-cloudcode-pa.googleapis.com"},
	},
	EnvVars:     []string{"CLOUD_CODE_URL"},
	AuthHeaders: []string{"authorization", "x-goog-api-key"},
}

// openAIProfileFor builds the openai/codex profile at lookup time so it
// can branch on the user's current auth state. Codex picks one of two
// upstreams depending on how they signed in:
//
//   - `auth_mode: "chatgpt"` (set by `codex login` ChatGPT flow) → the
//     bearer is a ChatGPT session token and only authenticates against
//     `https://chatgpt.com/backend-api/codex/...`. The API-key endpoint
//     at api.openai.com rejects it with 401 "Missing scopes:
//     api.responses.write".
//   - `auth_mode: "apikey"` (or no auth.json) → standard OpenAI API key,
//     routes to `https://api.openai.com/v1/...`.
//
// Codex builds URLs as `<openai_base_url>/responses` with no automatic
// version segment, so the override URL has to already point at the
// final per-mode path: the bare ChatGPT-backend root for ChatGPT auth,
// `{{endpoint}}/v1` for API-key auth. Overriding
// `model_providers.openai.base_url` instead is rejected at startup
// because codex marks every built-in provider ID as reserved.
func openAIProfileFor(cmd string) Provider {
	chatgpt := isCodexChatGPTAuth()
	target := "https://api.openai.com"
	baseURL := `openai_base_url="{{endpoint}}/v1"`
	if chatgpt {
		target = "https://chatgpt.com/backend-api/codex"
		baseURL = `openai_base_url="{{endpoint}}"`
	}
	// Disable both v1 and v2 of the WebSocket Responses transport so
	// codex goes straight to HTTPS. masqr is an HTTP reverse proxy and
	// can't 101-upgrade a `ws://` connection; without these flags
	// codex spends 5-30s on the doomed WebSocket attempt before
	// falling back, which dominates the first-turn latency.
	extraArgs := []string{
		`-c`, baseURL,
		`--disable`, `responses_websockets_v2`,
		`--disable`, `responses_websockets`,
	}
	return Provider{
		Name:        "openai",
		Target:      target,
		EnvVars:     []string{"OPENAI_BASE_URL"},
		AuthHeaders: []string{"authorization", "openai-organization", "openai-project"},
		ExtraArgs:   extraArgs,
	}
}

// isCodexChatGPTAuth returns true when `~/.codex/auth.json` says the
// active auth mode is `chatgpt`. Any error (missing file, parse error,
// permission denied) collapses to false so masqr falls back to the
// API-key upstream — which is the safer default for unknown setups.
func isCodexChatGPTAuth() bool {
	home, err := os.UserHomeDir()
	if err != nil {
		return false
	}
	data, err := os.ReadFile(filepath.Join(home, ".codex", "auth.json"))
	if err != nil {
		return false
	}
	var a struct {
		AuthMode string `json:"auth_mode"`
	}
	if err := json.Unmarshal(data, &a); err != nil {
		return false
	}
	return strings.EqualFold(a.AuthMode, "chatgpt")
}

// builtinProviders maps every command name (and common aliases) to its
// provider profile. Lookup is by basename of args[0] so installation paths
// like /usr/local/bin/claude and ~/.npm-global/bin/gemini both resolve.
// The "codex" and "openai" entries are resolved through
// openAIProfileFor() at LookupProvider time so they can branch on the
// user's current auth state — the placeholder Provider here is replaced
// before it ever reaches the caller.
var builtinProviders = map[string]Provider{
	"claude":      anthropicProfile,
	"claude-code": anthropicProfile,
	"gemini":      geminiProfile,
	"gemini-cli":  geminiProfile,
	"codex":       {Name: "openai"}, // placeholder, see openAIProfileFor
	"openai":      {Name: "openai"}, // placeholder, see openAIProfileFor
	"agy":         antigravityProfile,
	"antigravity": antigravityProfile,
}

// LookupProvider returns the provider profile for the given child command,
// falling back to genericProvider if there's no match. The lookup is
// case-insensitive and strips the directory portion and a trailing ".exe".
// Both `/` and `\` are honoured as separators so Windows-shape command
// paths resolve even when masqr is cross-compiled to a non-Windows host.
func LookupProvider(cmd string) (Provider, bool) {
	// filepath.Base only treats os.PathSeparator as a separator, so on
	// Linux the literal `C:\tools\gemini.exe` returns unchanged. Do a
	// portable split on the last `/` or `\` before delegating.
	if i := strings.LastIndexAny(cmd, "/\\"); i >= 0 {
		cmd = cmd[i+1:]
	}
	base := strings.ToLower(filepath.Base(cmd))
	base = strings.TrimSuffix(base, ".exe")
	if p, ok := builtinProviders[base]; ok {
		if p.Name == "openai" {
			return openAIProfileFor(base), true
		}
		return p, true
	}
	return genericProvider, false
}

// providerNames returns the set of known basenames, sorted, for use in
// help text and the --providers flag listing.
func providerNames() []string {
	seen := map[string]bool{}
	var out []string
	for k, p := range builtinProviders {
		if seen[p.Name] {
			continue
		}
		seen[p.Name] = true
		_ = k
		out = append(out, p.Name)
	}
	// Sorted for stable help output; tiny slice so bubble-sort is fine.
	for i := 0; i < len(out); i++ {
		for j := i + 1; j < len(out); j++ {
			if out[j] < out[i] {
				out[i], out[j] = out[j], out[i]
			}
		}
	}
	return out
}
