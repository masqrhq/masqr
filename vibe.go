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
	"os"
	"path/filepath"

	"github.com/pelletier/go-toml/v2"
)

// vibeHomeDir returns vibe's config directory the same way the CLI resolves it:
// $VIBE_HOME if set (tilde-expanded), otherwise ~/.vibe. Mirrors
// vibe/core/paths/_vibe_home.py so masqr reads the exact config vibe would.
func vibeHomeDir() string {
	if h := os.Getenv("VIBE_HOME"); h != "" {
		if h[0] == '~' {
			if home, err := os.UserHomeDir(); err == nil {
				return filepath.Join(home, h[1:])
			}
		}
		return h
	}
	home, err := os.UserHomeDir()
	if err != nil {
		return ".vibe"
	}
	return filepath.Join(home, ".vibe")
}

// prepareVibeHome builds a throwaway VIBE_HOME that mirrors the user's real one
// but points vibe's Mistral provider at the masqr listener. vibe has no env-var
// base-URL override (its `providers` config is a list that isn't addressable by
// an env var — verified), so the only redirect lever is the config.toml
// api_base field. masqr symlinks every entry of the real VIBE_HOME (so the
// .env carrying MISTRAL_API_KEY, trusted_folders.toml, history and logs all
// keep working) except config.toml, which it copies with the Mistral provider's
// api_base rewritten. The real VIBE_HOME is never modified; the temp dir (only
// symlinks + one rewritten file) is removed on exit.
func prepareVibeHome(endpoint string) (env []string, cleanup func(), err error) {
	realHome := vibeHomeDir()
	tmp, err := os.MkdirTemp("", "masqr-vibe-")
	if err != nil {
		return nil, nil, fmt.Errorf("create temp VIBE_HOME: %w", err)
	}
	cleanup = func() { _ = os.RemoveAll(tmp) }

	// Mirror everything except config.toml as symlinks back to the real home,
	// so vibe sees the user's auth/trust/history unchanged.
	if entries, derr := os.ReadDir(realHome); derr == nil {
		for _, e := range entries {
			if e.Name() == "config.toml" {
				continue
			}
			src := filepath.Join(realHome, e.Name())
			if lerr := os.Symlink(src, filepath.Join(tmp, e.Name())); lerr != nil {
				cleanup()
				return nil, nil, fmt.Errorf("mirror %s: %w", e.Name(), lerr)
			}
		}
	}

	src := filepath.Join(realHome, "config.toml")
	if werr := writeVibeConfig(src, filepath.Join(tmp, "config.toml"), endpoint); werr != nil {
		cleanup()
		return nil, nil, werr
	}
	return []string{"VIBE_HOME=" + tmp}, cleanup, nil
}

// writeVibeConfig reads srcPath (vibe's real config.toml, may be absent),
// rewrites the Mistral chat provider's api_base to <endpoint>/v1, and writes the
// result to dstPath. The trailing /v1 is required: vibe derives the SDK
// server_url by stripping a /v<N> suffix off api_base and rejects a value
// without one.
func writeVibeConfig(srcPath, dstPath, endpoint string) error {
	apiBase := endpoint + "/v1"

	doc := map[string]any{}
	if data, err := os.ReadFile(srcPath); err == nil {
		if uerr := toml.Unmarshal(data, &doc); uerr != nil {
			return fmt.Errorf("parse vibe config %s: %w", srcPath, uerr)
		}
	} else if !os.IsNotExist(err) {
		return fmt.Errorf("read vibe config %s: %w", srcPath, err)
	}

	rewriteMistralAPIBase(doc, apiBase)

	out, err := toml.Marshal(doc)
	if err != nil {
		return fmt.Errorf("encode vibe config: %w", err)
	}
	if err := os.WriteFile(dstPath, out, 0o600); err != nil {
		return fmt.Errorf("write vibe config %s: %w", dstPath, err)
	}
	return nil
}

// rewriteMistralAPIBase sets the api_base of the Mistral chat provider in a
// decoded config.toml document to apiBase. It only touches the top-level
// `[[providers]]` entry named "mistral" with the "mistral" backend — never the
// separate transcribe_providers / tts_providers arrays (those use wss:// and a
// non-/v1 https:// base and aren't part of the chat path masqr proxies). If no
// such provider entry exists (e.g. the user relies on vibe's built-in
// defaults), one is appended so the redirect still applies.
func rewriteMistralAPIBase(doc map[string]any, apiBase string) {
	provs, _ := doc["providers"].([]any)
	found := false
	for _, p := range provs {
		m, ok := p.(map[string]any)
		if !ok {
			continue
		}
		if name, _ := m["name"].(string); name != "mistral" {
			continue
		}
		// A `backend` key is present in real configs; when it is, require it to
		// be "mistral" so a user who repurposed the name for a generic backend
		// isn't silently retargeted.
		if be, ok := m["backend"].(string); ok && be != "mistral" {
			continue
		}
		m["api_base"] = apiBase
		found = true
	}
	if !found {
		doc["providers"] = append(provs, map[string]any{
			"name":            "mistral",
			"api_base":        apiBase,
			"api_key_env_var": "MISTRAL_API_KEY",
			"backend":         "mistral",
		})
	}
}
