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
	"crypto/x509"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

// TestAntigravityProfileUsesCloudCodeURL locks in the plaintext-override path
// for agy: the profile redirects via the CLOUD_CODE_URL env var (so run() takes
// the ordinary reverse-proxy path, not the transparent-TLS intercept), and it
// targets the Code Assist host. No provider sets Intercept anymore — agy's
// CLOUD_CODE_URL override made the transparent-MITM path unnecessary.
func TestAntigravityProfileUsesCloudCodeURL(t *testing.T) {
	for _, cmd := range []string{"agy", "antigravity", "/usr/local/bin/agy", "AGY"} {
		p, ok := LookupProvider(cmd)
		if !ok {
			t.Fatalf("LookupProvider(%q): not found", cmd)
		}
		if p.Intercept {
			t.Errorf("LookupProvider(%q).Intercept = true, want false (CLOUD_CODE_URL plaintext path)", cmd)
		}
		if len(p.EnvVars) != 1 || p.EnvVars[0] != "CLOUD_CODE_URL" {
			t.Errorf("LookupProvider(%q).EnvVars = %v, want [CLOUD_CODE_URL]", cmd, p.EnvVars)
		}
		if p.Target != "https://daily-cloudcode-pa.googleapis.com" {
			t.Errorf("LookupProvider(%q).Target = %q", cmd, p.Target)
		}
		if len(p.Routes) != 1 || p.Routes[0].PathPrefix != "/v1internal" {
			t.Errorf("LookupProvider(%q).Routes = %+v, want one /v1internal route", cmd, p.Routes)
		}
	}
	// No provider should request the transparent-TLS intercept path.
	for _, cmd := range []string{"claude", "gemini", "codex", "openai", "agy", "somethingelse"} {
		if p, _ := LookupProvider(cmd); p.Intercept {
			t.Errorf("LookupProvider(%q) unexpectedly has Intercept=true", cmd)
		}
	}
}

// TestCertFactoryLeafVerifies confirms per-SNI leaves chain to the CA and carry
// the right SAN, so the intercepted client accepts them.
func TestCertFactoryLeafVerifies(t *testing.T) {
	cf, err := newCertFactory()
	if err != nil {
		t.Fatalf("newCertFactory: %v", err)
	}
	const host = "daily-cloudcode-pa.googleapis.com"
	leaf, err := cf.leafFor(host)
	if err != nil {
		t.Fatalf("leafFor: %v", err)
	}
	crt, err := x509.ParseCertificate(leaf.Certificate[0])
	if err != nil {
		t.Fatalf("parse leaf: %v", err)
	}
	roots := x509.NewCertPool()
	roots.AddCert(cf.caCert)
	if _, err := crt.Verify(x509.VerifyOptions{DNSName: host, Roots: roots}); err != nil {
		t.Fatalf("leaf does not verify against CA: %v", err)
	}
	// Second call must hit the cache and return the identical cert.
	leaf2, _ := cf.leafFor(host)
	if leaf2 != leaf {
		t.Errorf("leafFor not cached: got a fresh cert for the same host")
	}
}

// TestTrustBundleIncludesCAAndSystemRoots verifies the bundle is (system roots
// ++ masqr CA) — the CA alone would break the child's un-redirected TLS calls.
func TestTrustBundleIncludesCAAndSystemRoots(t *testing.T) {
	cf, err := newCertFactory()
	if err != nil {
		t.Fatalf("newCertFactory: %v", err)
	}
	dir := t.TempDir()
	path, err := writeTrustBundle(cf.caPEM, dir)
	if err != nil {
		t.Fatalf("writeTrustBundle: %v", err)
	}
	got, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read bundle: %v", err)
	}
	if !bytes.Contains(got, cf.caPEM) {
		t.Errorf("bundle does not contain the masqr CA")
	}
	// If the host has a system CA bundle, ours must be appended after it
	// (bundle strictly larger than the CA alone).
	for _, p := range systemCABundleFiles {
		if _, err := os.Stat(p); err == nil {
			if len(got) <= len(cf.caPEM) {
				t.Errorf("system bundle %s exists but trust bundle (%d B) is not larger than CA alone (%d B)", p, len(got), len(cf.caPEM))
			}
			break
		}
	}
}

// TestLDPreloadResolver builds the shim and checks the injected env. Skipped
// where no C compiler is available (the runtime falls back to /etc/hosts).
func TestLDPreloadResolver(t *testing.T) {
	if _, err := exec.LookPath("cc"); err != nil {
		if _, err := exec.LookPath("gcc"); err != nil {
			t.Skip("no C compiler; LD_PRELOAD path not testable here")
		}
	}
	dir := t.TempDir()
	r := &ldPreloadResolver{host: "daily-cloudcode-pa.googleapis.com", bundle: filepath.Join(dir, "bundle.pem"), dir: dir}
	if err := r.setup(); err != nil {
		t.Fatalf("setup (compile shim): %v", err)
	}
	if _, err := os.Stat(r.shimPath); err != nil {
		t.Fatalf("shim .so not produced: %v", err)
	}
	env := strings.Join(r.Env(), "\n")
	for _, want := range []string{
		"GODEBUG=netdns=cgo",
		"LD_PRELOAD=" + r.shimPath,
		"MASQR_REDIRECT_HOST=daily-cloudcode-pa.googleapis.com",
		"MASQR_REDIRECT_IP=127.0.0.1",
		"SSL_CERT_FILE=",
	} {
		if !strings.Contains(env, want) {
			t.Errorf("Env() missing %q; got:\n%s", want, env)
		}
	}
	if err := r.Teardown(); err != nil {
		t.Errorf("Teardown: %v", err)
	}
}

// TestPersistentCARoundTrip covers the macOS path's CA persistence: a generated
// CA written to disk and reloaded must still sign verifiable leaves. Runs on any
// OS (the file ops are platform-agnostic).
func TestPersistentCARoundTrip(t *testing.T) {
	cf, keyPEM, err := generatePersistentCA()
	if err != nil {
		t.Fatalf("generatePersistentCA: %v", err)
	}
	dir := t.TempDir()
	certPath := filepath.Join(dir, "ca.pem")
	keyPath := filepath.Join(dir, "ca-key.pem")
	if err := os.WriteFile(certPath, cf.caPEM, 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(keyPath, keyPEM, 0o600); err != nil {
		t.Fatal(err)
	}
	loaded, err := loadPersistentCA(certPath, keyPath)
	if err != nil {
		t.Fatalf("loadPersistentCA: %v", err)
	}
	if loaded.caCert.Subject.CommonName != macCAName {
		t.Errorf("loaded CA CN = %q, want %q", loaded.caCert.Subject.CommonName, macCAName)
	}
	leaf, err := loaded.leafFor("daily-cloudcode-pa.googleapis.com")
	if err != nil {
		t.Fatalf("leafFor on reloaded CA: %v", err)
	}
	crt, _ := x509.ParseCertificate(leaf.Certificate[0])
	roots := x509.NewCertPool()
	roots.AddCert(loaded.caCert)
	if _, err := crt.Verify(x509.VerifyOptions{DNSName: "daily-cloudcode-pa.googleapis.com", Roots: roots}); err != nil {
		t.Errorf("leaf from reloaded persistent CA does not verify: %v", err)
	}
}

func TestShellSingleQuote(t *testing.T) {
	cases := map[string]string{
		"abc":                           "'abc'",
		"a b":                           "'a b'",
		"it's":                          `'it'\''s'`,
		"127.0.0.1 h # masqr-intercept": "'127.0.0.1 h # masqr-intercept'",
	}
	for in, want := range cases {
		if got := shellSingleQuote(in); got != want {
			t.Errorf("shellSingleQuote(%q) = %q, want %q", in, got, want)
		}
	}
}
