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
	"context"
	"crypto/tls"
	"crypto/x509"
	"io"
	"log"
	"net"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// newTestCA fails the test on any CA setup error.
func newTestCA(t *testing.T) *mitmCA {
	t.Helper()
	ca, err := newMITMCA()
	if err != nil {
		t.Fatalf("newMITMCA: %v", err)
	}
	return ca
}

// TestMITMCALeafChainsToCA verifies a minted leaf is a valid server cert for
// the requested host and chains to the masqr CA — the property TLS clients
// rely on after we hand them SSL_CERT_FILE/ca.pem.
func TestMITMCALeafChainsToCA(t *testing.T) {
	ca := newTestCA(t)

	crt, err := ca.leafFor("example.com")
	if err != nil {
		t.Fatalf("leafFor: %v", err)
	}
	leaf, err := x509.ParseCertificate(crt.Certificate[0])
	if err != nil {
		t.Fatalf("parse leaf: %v", err)
	}

	roots := x509.NewCertPool()
	if !roots.AppendCertsFromPEM(ca.certPEM) {
		t.Fatal("failed to load CA PEM into pool")
	}
	if _, err := leaf.Verify(x509.VerifyOptions{
		DNSName:     "example.com",
		Roots:       roots,
		KeyUsages:   []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		CurrentTime: time.Now(),
	}); err != nil {
		t.Fatalf("leaf does not verify against masqr CA: %v", err)
	}

	// Same host must be served from cache (identical pointer).
	crt2, err := ca.leafFor("example.com")
	if err != nil {
		t.Fatalf("leafFor (cached): %v", err)
	}
	if crt2 != crt {
		t.Error("leafFor did not cache the certificate for a repeated host")
	}
}

// TestMITMCALeafForIP places an IP literal in an IP SAN, not a DNS SAN.
func TestMITMCALeafForIP(t *testing.T) {
	ca := newTestCA(t)
	crt, err := ca.leafFor("127.0.0.1")
	if err != nil {
		t.Fatalf("leafFor: %v", err)
	}
	leaf, err := x509.ParseCertificate(crt.Certificate[0])
	if err != nil {
		t.Fatalf("parse leaf: %v", err)
	}
	if len(leaf.IPAddresses) != 1 || leaf.IPAddresses[0].String() != "127.0.0.1" {
		t.Errorf("IPAddresses = %v, want [127.0.0.1]", leaf.IPAddresses)
	}
	if len(leaf.DNSNames) != 0 {
		t.Errorf("DNSNames = %v, want empty for an IP host", leaf.DNSNames)
	}
}

func TestWriteCAFile(t *testing.T) {
	ca := newTestCA(t)
	path := filepath.Join(t.TempDir(), "masqr-ca.pem")
	if err := ca.writeCAFile(path); err != nil {
		t.Fatalf("writeCAFile: %v", err)
	}
	got, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read back: %v", err)
	}
	if !strings.Contains(string(got), "BEGIN CERTIFICATE") {
		t.Errorf("CA file is not PEM:\n%s", got)
	}
	pool := x509.NewCertPool()
	if !pool.AppendCertsFromPEM(got) {
		t.Error("written CA PEM does not parse as a certificate")
	}
}

// startForwardProxy boots the forward proxy on a loopback listener and returns
// an *http.Client whose proxy is masqr and whose root store trusts the masqr
// CA — i.e. a wrapped child configured exactly as childProxyEnv arranges.
func startForwardProxy(t *testing.T, policy Policy) (*http.Client, *mitmCA) {
	t.Helper()
	ca := newTestCA(t)
	fp := newForwardProxy(ca, log.New(io.Discard, "", 0), policy)

	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	srv := &http.Server{
		Handler:           fp.dispatch(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(http.StatusOK) })),
		ReadHeaderTimeout: 5 * time.Second,
	}
	go func() { _ = srv.Serve(ln) }()
	t.Cleanup(func() { _ = srv.Close() })

	proxyURL, _ := url.Parse("http://" + ln.Addr().String())
	roots := x509.NewCertPool()
	if !roots.AppendCertsFromPEM(ca.certPEM) {
		t.Fatal("load CA into client pool")
	}
	client := &http.Client{
		Timeout: 10 * time.Second,
		Transport: &http.Transport{
			Proxy:           http.ProxyURL(proxyURL),
			TLSClientConfig: &tls.Config{RootCAs: roots},
		},
	}
	return client, ca
}

// TestForwardProxyBlocksSecretOverCONNECT is the core MITM contract: a secret
// in an HTTPS request body to an ARBITRARY host is decrypted, scanned, and
// blocked exactly like the reverse path — masqr never contacts the upstream.
// The target host is unroutable (.invalid), proving no upstream call happens.
func TestForwardProxyBlocksSecretOverCONNECT(t *testing.T) {
	client, _ := startForwardProxy(t, Policy{Threshold: SevLow, Provider: genericProvider})

	body := strings.NewReader(`{"prompt":"my key is AKIAIOSFODNN7EXAMPLE"}`)
	resp, err := client.Post("https://blocked.invalid/v1/messages", "application/json", body)
	if err != nil {
		t.Fatalf("request through MITM proxy failed: %v", err)
	}
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode != http.StatusUnavailableForLegalReasons {
		t.Fatalf("status = %d, want 451 (blocked)", resp.StatusCode)
	}
	if got := resp.Header.Get("X-Masqr-Blocked"); got != "1" {
		t.Errorf("X-Masqr-Blocked = %q, want 1", got)
	}
	raw, _ := io.ReadAll(resp.Body)
	if !strings.Contains(string(raw), "aws-access-key-id") {
		t.Errorf("block body should name the tripping rule, got: %s", raw)
	}
}

// TestForwardProxyForwardsCleanOverCONNECT verifies a clean request is
// decrypted, found harmless, and forwarded upstream — masqr is transparent
// when there's nothing to block. The upstream is a real TLS server whose CA we
// inject into masqr's per-host transport via a custom RoundTripper.
func TestForwardProxyForwardsCleanOverCONNECT(t *testing.T) {
	// Upstream echo server (HTTPS) with its own self-signed CA.
	upstreamCA := newTestCA(t)
	upLeaf, err := upstreamCA.leafFor("upstream.test")
	if err != nil {
		t.Fatalf("upstream leaf: %v", err)
	}
	var gotBody string
	upLn, err := tls.Listen("tcp", "127.0.0.1:0", &tls.Config{Certificates: []tls.Certificate{*upLeaf}})
	if err != nil {
		t.Fatalf("tls listen: %v", err)
	}
	upSrv := &http.Server{
		Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			b, _ := io.ReadAll(r.Body)
			gotBody = string(b)
			_, _ = w.Write([]byte("ok"))
		}),
		ReadHeaderTimeout: 5 * time.Second,
	}
	go func() { _ = upSrv.Serve(upLn) }()
	defer func() { _ = upSrv.Close() }()

	// masqr forward proxy whose per-host transport trusts the upstream CA and
	// dials our loopback listener instead of the real internet.
	upRoots := x509.NewCertPool()
	upRoots.AppendCertsFromPEM(upstreamCA.certPEM)
	dialAddr := upLn.Addr().String()

	ca := newTestCA(t)
	policy := Policy{Threshold: SevLow, Provider: genericProvider}
	rt := &redirectTransport{to: dialAddr, roots: upRoots, serverName: "upstream.test"}
	fp := &forwardProxy{ca: ca, logger: log.New(io.Discard, "", 0), policy: policy}
	// Seed the per-host handler so it uses our redirecting transport instead of
	// the default (which would try the real internet).
	hostURL := &url.URL{Scheme: "https", Host: "upstream.test:443"}
	fp.handlers.Store("https://upstream.test:443", newProxy(hostURL, fp.logger, fp.policy, rt))

	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	srv := &http.Server{Handler: fp.dispatch(http.NotFoundHandler()), ReadHeaderTimeout: 5 * time.Second}
	go func() { _ = srv.Serve(ln) }()
	defer func() { _ = srv.Close() }()

	proxyURL, _ := url.Parse("http://" + ln.Addr().String())
	roots := x509.NewCertPool()
	roots.AppendCertsFromPEM(ca.certPEM)
	client := &http.Client{
		Timeout: 10 * time.Second,
		Transport: &http.Transport{
			Proxy:           http.ProxyURL(proxyURL),
			TLSClientConfig: &tls.Config{RootCAs: roots},
		},
	}

	resp, err := client.Post("https://upstream.test/echo", "application/json", strings.NewReader(`{"prompt":"all clear"}`))
	if err != nil {
		t.Fatalf("clean request failed: %v", err)
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status = %d, want 200 (forwarded)", resp.StatusCode)
	}
	if gotBody != `{"prompt":"all clear"}` {
		t.Errorf("upstream got body %q, want the original clean payload", gotBody)
	}
}

// redirectTransport sends every request to a fixed loopback address while
// presenting the original SNI, so a MITM forward to "upstream.test:443"
// actually reaches our in-test TLS server.
type redirectTransport struct {
	to         string
	roots      *x509.CertPool
	serverName string
}

func (rt *redirectTransport) RoundTrip(r *http.Request) (*http.Response, error) {
	tr := &http.Transport{
		TLSClientConfig: &tls.Config{RootCAs: rt.roots, ServerName: rt.serverName},
		DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
			var d net.Dialer
			return d.DialContext(ctx, "tcp", rt.to)
		},
	}
	return tr.RoundTrip(r)
}

// TestForwardProxyForwardsAuthHeaderInBlockMode is the auth-safety contract: a
// request bearing the agent's own Authorization header AND a body that would
// otherwise trip a finding is, when sent to an OAuth credential endpoint in
// --on-finding block mode, FORWARDED (not 451). Blocking the agent's own
// credentials would break its ability to authenticate.
func TestForwardProxyForwardsAuthHeaderInBlockMode(t *testing.T) {
	// Upstream stand-in for oauth2.googleapis.com, with its own self-signed CA.
	upstreamCA := newTestCA(t)
	upLeaf, err := upstreamCA.leafFor("oauth2.googleapis.com")
	if err != nil {
		t.Fatalf("upstream leaf: %v", err)
	}
	var gotAuth, gotBody string
	upLn, err := tls.Listen("tcp", "127.0.0.1:0", &tls.Config{Certificates: []tls.Certificate{*upLeaf}})
	if err != nil {
		t.Fatalf("tls listen: %v", err)
	}
	upSrv := &http.Server{
		Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			gotAuth = r.Header.Get("Authorization")
			b, _ := io.ReadAll(r.Body)
			gotBody = string(b)
			_, _ = w.Write([]byte("ok"))
		}),
		ReadHeaderTimeout: 5 * time.Second,
	}
	go func() { _ = upSrv.Serve(upLn) }()
	defer func() { _ = upSrv.Close() }()

	upRoots := x509.NewCertPool()
	upRoots.AppendCertsFromPEM(upstreamCA.certPEM)

	ca := newTestCA(t)
	// BLOCK mode: a finding would normally yield 451. The auth-host passthrough
	// must override that. transport redirects oauth2.googleapis.com to our
	// loopback TLS server while presenting the real SNI.
	fp := &forwardProxy{
		ca:        ca,
		logger:    log.New(io.Discard, "", 0),
		policy:    Policy{Threshold: SevLow, Provider: genericProvider, OnFinding: OnFindingBlock},
		transport: &redirectTransport{to: upLn.Addr().String(), roots: upRoots, serverName: "oauth2.googleapis.com"},
	}

	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	srv := &http.Server{Handler: fp.dispatch(http.NotFoundHandler()), ReadHeaderTimeout: 5 * time.Second}
	go func() { _ = srv.Serve(ln) }()
	defer func() { _ = srv.Close() }()

	proxyURL, _ := url.Parse("http://" + ln.Addr().String())
	roots := x509.NewCertPool()
	roots.AppendCertsFromPEM(ca.certPEM)
	client := &http.Client{
		Timeout: 10 * time.Second,
		Transport: &http.Transport{
			Proxy:           http.ProxyURL(proxyURL),
			TLSClientConfig: &tls.Config{RootCAs: roots},
		},
	}

	// Body carries credential-shaped material (an AWS key) AND a refresh-token
	// exchange — exactly the kind of payload block mode would 451 on any other
	// host. Plus the agent's own bearer token in the Authorization header.
	body := `{"grant_type":"refresh_token","client_secret":"AKIAIOSFODNN7EXAMPLE"}`
	req, err := http.NewRequest(http.MethodPost, "https://oauth2.googleapis.com/token", strings.NewReader(body))
	if err != nil {
		t.Fatalf("new request: %v", err)
	}
	req.Header.Set("Authorization", "Bearer ya29.agent-own-token")
	req.Header.Set("Content-Type", "application/json")

	resp, err := client.Do(req)
	if err != nil {
		t.Fatalf("auth request through MITM proxy failed: %v", err)
	}
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode == http.StatusUnavailableForLegalReasons {
		t.Fatalf("auth exchange was BLOCKED (451); the agent's own credentials must pass through in block mode")
	}
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status = %d, want 200 (forwarded)", resp.StatusCode)
	}
	if gotAuth != "Bearer ya29.agent-own-token" {
		t.Errorf("upstream Authorization = %q, want the agent's own token forwarded intact", gotAuth)
	}
	if gotBody != body {
		t.Errorf("upstream body = %q, want the token-exchange body forwarded intact", gotBody)
	}
}

func TestIsAuthExchangeHost(t *testing.T) {
	pass := []string{
		"accounts.google.com",
		"oauth2.googleapis.com:443",
		"www.googleapis.com",
		"OAUTH2.GOOGLEAPIS.COM",
		"accounts.google.com.", // trailing dot (FQDN form)
	}
	for _, h := range pass {
		if !isAuthExchangeHost(h) {
			t.Errorf("isAuthExchangeHost(%q) = false, want true", h)
		}
	}
	block := []string{"api.anthropic.com", "evil.googleapis.com.attacker.com", "generativelanguage.googleapis.com"}
	for _, h := range block {
		if isAuthExchangeHost(h) {
			t.Errorf("isAuthExchangeHost(%q) = true, want false", h)
		}
	}
}

// TestCAPersistFirstRunGeneratesAndPersists covers the first-install path:
// loadOrCreateCA on an empty dir generates a CA, writes cert+key+version, and
// the key file is owner-only (0600).
func TestCAPersistFirstRunGeneratesAndPersists(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "ca")
	logger := log.New(io.Discard, "", 0)

	ca, err := loadOrCreateCA(dir, "v1.0.0", logger)
	if err != nil {
		t.Fatalf("loadOrCreateCA: %v", err)
	}
	if ca == nil || len(ca.certPEM) == 0 {
		t.Fatal("expected a generated CA with cert PEM")
	}

	for _, f := range []string{caCertFile, caKeyFile, caVersionFile} {
		if _, err := os.Stat(filepath.Join(dir, f)); err != nil {
			t.Errorf("expected %s to be persisted: %v", f, err)
		}
	}
	info, err := os.Stat(filepath.Join(dir, caKeyFile))
	if err != nil {
		t.Fatalf("stat key: %v", err)
	}
	if perm := info.Mode().Perm(); perm != 0o600 {
		t.Errorf("CA key file mode = %o, want 600", perm)
	}
	stamp, _ := os.ReadFile(filepath.Join(dir, caVersionFile))
	if strings.TrimSpace(string(stamp)) != "v1.0.0" {
		t.Errorf("version stamp = %q, want v1.0.0", strings.TrimSpace(string(stamp)))
	}
}

// TestCAPersistSecondRunReuses is the core persistence contract: a second run
// at the same version REUSES the identical CA rather than regenerating.
func TestCAPersistSecondRunReuses(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "ca")
	logger := log.New(io.Discard, "", 0)

	first, err := loadOrCreateCA(dir, "v1.0.0", logger)
	if err != nil {
		t.Fatalf("first loadOrCreateCA: %v", err)
	}
	second, err := loadOrCreateCA(dir, "v1.0.0", logger)
	if err != nil {
		t.Fatalf("second loadOrCreateCA: %v", err)
	}

	if !bytes.Equal(first.certPEM, second.certPEM) {
		t.Error("second run did not reuse the persisted CA (cert PEM differs)")
	}
	if first.cert.SerialNumber.Cmp(second.cert.SerialNumber) != 0 {
		t.Error("reused CA has a different serial number — it was regenerated, not reused")
	}
	// The reloaded key must still sign leaves that chain to the cert.
	if _, err := second.leafFor("example.com"); err != nil {
		t.Errorf("reused CA cannot mint a leaf: %v", err)
	}
}

// TestCAPersistVersionMismatchRegenerates covers an upgrade: a different stamped
// version forces a fresh unique CA, and the new version is persisted.
func TestCAPersistVersionMismatchRegenerates(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "ca")
	logger := log.New(io.Discard, "", 0)

	old, err := loadOrCreateCA(dir, "v1.0.0", logger)
	if err != nil {
		t.Fatalf("v1 loadOrCreateCA: %v", err)
	}
	upgraded, err := loadOrCreateCA(dir, "v2.0.0", logger)
	if err != nil {
		t.Fatalf("v2 loadOrCreateCA: %v", err)
	}

	if bytes.Equal(old.certPEM, upgraded.certPEM) {
		t.Error("version change did not regenerate the CA (cert PEM identical)")
	}
	stamp, _ := os.ReadFile(filepath.Join(dir, caVersionFile))
	if strings.TrimSpace(string(stamp)) != "v2.0.0" {
		t.Errorf("version stamp after upgrade = %q, want v2.0.0", strings.TrimSpace(string(stamp)))
	}
	// And the new version is now itself stable across runs.
	again, err := loadOrCreateCA(dir, "v2.0.0", logger)
	if err != nil {
		t.Fatalf("v2 reuse: %v", err)
	}
	if !bytes.Equal(upgraded.certPEM, again.certPEM) {
		t.Error("v2 CA was not reused on the subsequent run")
	}
}

func TestChildProxyEnv(t *testing.T) {
	env := childProxyEnv("http://127.0.0.1:9999", "/tmp/ca.pem", "/tmp/bundle.pem")
	want := map[string]string{
		"HTTP_PROXY":          "http://127.0.0.1:9999",
		"HTTPS_PROXY":         "http://127.0.0.1:9999",
		"SSL_CERT_FILE":       "/tmp/bundle.pem",
		"NODE_EXTRA_CA_CERTS": "/tmp/ca.pem",
	}
	got := map[string]string{}
	for _, kv := range env {
		if i := strings.IndexByte(kv, '='); i >= 0 {
			got[kv[:i]] = kv[i+1:]
		}
	}
	for k, v := range want {
		if got[k] != v {
			t.Errorf("%s = %q, want %q", k, got[k], v)
		}
	}
	if !strings.Contains(got["NO_PROXY"], "127.0.0.1") {
		t.Errorf("NO_PROXY = %q, want it to exclude loopback", got["NO_PROXY"])
	}
	// With no bundle, SSL_CERT_FILE must be omitted (degrade gracefully).
	for _, kv := range childProxyEnv("http://x", "/tmp/ca.pem", "") {
		if strings.HasPrefix(kv, "SSL_CERT_FILE=") {
			t.Errorf("SSL_CERT_FILE should be omitted when no bundle is available: %q", kv)
		}
	}
}
