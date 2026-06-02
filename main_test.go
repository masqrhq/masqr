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
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

// TestDefaultLogPathUsesUserCacheDir checks that the default session log lands
// under the OS-native user cache dir and that the directory is created. The
// cache root is redirected per-platform (the env var os.UserCacheDir honours on
// each OS) so the test neither pollutes the real cache dir nor depends on it.
func TestDefaultLogPathUsesUserCacheDir(t *testing.T) {
	tmp := t.TempDir()
	switch runtime.GOOS {
	case "windows":
		t.Setenv("LocalAppData", tmp) // os.UserCacheDir -> %LocalAppData%
	case "darwin":
		t.Setenv("HOME", tmp) // os.UserCacheDir -> $HOME/Library/Caches
	default: // linux and other unix
		t.Setenv("XDG_CACHE_HOME", tmp) // os.UserCacheDir -> $XDG_CACHE_HOME
	}

	wantDir := masqrCacheDir() // recomputed under the redirected env
	if wantDir == "" {
		t.Fatal("masqrCacheDir() empty after redirecting the cache root")
	}
	if !strings.HasPrefix(wantDir, tmp) {
		t.Fatalf("cache root %q not under the redirected temp dir %q", wantDir, tmp)
	}

	got := defaultLogPath()
	if filepath.Dir(got) != wantDir {
		t.Errorf("defaultLogPath() dir = %q, want %q", filepath.Dir(got), wantDir)
	}
	base := filepath.Base(got)
	if !strings.HasPrefix(base, "masqr-") || !strings.HasSuffix(base, ".log") {
		t.Errorf("defaultLogPath() = %q, want masqr-<ts>.log", got)
	}
	if fi, err := os.Stat(wantDir); err != nil || !fi.IsDir() {
		t.Errorf("expected %q to be created as a directory: %v", wantDir, err)
	}
}
