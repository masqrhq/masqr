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
