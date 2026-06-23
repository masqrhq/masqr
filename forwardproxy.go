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

// Forward-proxy + MITM mode. The reverse proxy (server.go) only inspects the
// ONE upstream a provider profile points at; a wrapped agent still talks
// directly to oauth2.googleapis.com, telemetry, auto-updaters, … that bypass
// inspection entirely. This file makes masqr ALSO act as an HTTP forward proxy:
// it answers `CONNECT host:port`, terminates TLS with an on-the-fly leaf cert
// signed by a masqr-generated CA, runs the SAME scan/block/redact engine over
// the decrypted request (via newProxy), then re-encrypts to the real upstream.
//
// The child is pointed at masqr automatically (HTTPS_PROXY + SSL_CERT_FILE in
// childProxyEnv); everything degrades gracefully when the CA can't be created
// or written, leaving the reverse-proxy path untouched.

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"fmt"
	"log"
	"math/big"
	"net"
	"net/http"
	"net/http/httputil"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"
)

// mitmCA is a self-signed certificate authority masqr generates once per run.
// It mints (and caches) a leaf certificate per SNI host so the forward proxy
// can terminate TLS for arbitrary upstreams. The private key never leaves the
// process; only the CA certificate PEM is exposed (writeCAFile / certPEM).
type mitmCA struct {
	cert    *x509.Certificate
	key     *ecdsa.PrivateKey
	certPEM []byte

	mu     sync.Mutex
	leaves map[string]*tls.Certificate
}

// newMITMCA generates a fresh in-memory CA. ECDSA/P-256 keeps key generation
// fast (leaf mint is on the connection hot path) while staying universally
// accepted by TLS clients.
func newMITMCA() (*mitmCA, error) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, fmt.Errorf("generate CA key: %w", err)
	}
	serial, err := randSerial()
	if err != nil {
		return nil, err
	}
	now := time.Now()
	tmpl := &x509.Certificate{
		SerialNumber: serial,
		Subject: pkix.Name{
			CommonName:   "masqr MITM CA",
			Organization: []string{"masqr"},
		},
		NotBefore:             now.Add(-time.Hour),
		NotAfter:              now.Add(10 * 365 * 24 * time.Hour),
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign | x509.KeyUsageDigitalSignature,
		BasicConstraintsValid: true,
		IsCA:                  true,
		MaxPathLenZero:        true,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		return nil, fmt.Errorf("self-sign CA: %w", err)
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		return nil, fmt.Errorf("parse CA: %w", err)
	}
	return &mitmCA{
		cert:    cert,
		key:     key,
		certPEM: pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}),
		leaves:  make(map[string]*tls.Certificate),
	}, nil
}

// caFromPEM rebuilds a *mitmCA from a previously persisted certificate and
// (PKCS#8) private-key PEM pair. It verifies the key matches the certificate's
// public key, so a corrupt or mismatched key store is rejected (callers then
// regenerate) rather than producing leaves that won't validate.
func caFromPEM(certPEM, keyPEM []byte) (*mitmCA, error) {
	certBlock, _ := pem.Decode(certPEM)
	if certBlock == nil || certBlock.Type != "CERTIFICATE" {
		return nil, fmt.Errorf("CA cert PEM: no CERTIFICATE block")
	}
	cert, err := x509.ParseCertificate(certBlock.Bytes)
	if err != nil {
		return nil, fmt.Errorf("parse CA cert: %w", err)
	}
	keyBlock, _ := pem.Decode(keyPEM)
	if keyBlock == nil {
		return nil, fmt.Errorf("CA key PEM: no PEM block")
	}
	parsed, err := x509.ParsePKCS8PrivateKey(keyBlock.Bytes)
	if err != nil {
		return nil, fmt.Errorf("parse CA key: %w", err)
	}
	key, ok := parsed.(*ecdsa.PrivateKey)
	if !ok {
		return nil, fmt.Errorf("CA key is %T, want *ecdsa.PrivateKey", parsed)
	}
	pub, ok := cert.PublicKey.(*ecdsa.PublicKey)
	if !ok || !pub.Equal(&key.PublicKey) {
		return nil, fmt.Errorf("CA private key does not match certificate")
	}
	return &mitmCA{
		cert:    cert,
		key:     key,
		certPEM: pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: cert.Raw}),
		leaves:  make(map[string]*tls.Certificate),
	}, nil
}

// keyPEM marshals the CA private key as a PKCS#8 PEM block for persistence.
func (c *mitmCA) keyPEM() ([]byte, error) {
	der, err := x509.MarshalPKCS8PrivateKey(c.key)
	if err != nil {
		return nil, fmt.Errorf("marshal CA key: %w", err)
	}
	return pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: der}), nil
}

func randSerial() (*big.Int, error) {
	serial, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	if err != nil {
		return nil, fmt.Errorf("serial: %w", err)
	}
	return serial, nil
}

// writeCAFile writes the CA certificate (PEM) to path so the wrapped child —
// and the proof script — can trust masqr's on-the-fly leaf certs.
func (c *mitmCA) writeCAFile(path string) error {
	return os.WriteFile(path, c.certPEM, 0o644)
}

// leafFor returns a CA-signed leaf certificate for host, minting and caching
// it on first use. host is the SNI name (no port); an IP literal is placed in
// an IP SAN, anything else in a DNS SAN.
func (c *mitmCA) leafFor(host string) (*tls.Certificate, error) {
	if host == "" {
		return nil, fmt.Errorf("leafFor: empty host")
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	if crt, ok := c.leaves[host]; ok {
		return crt, nil
	}
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, fmt.Errorf("generate leaf key: %w", err)
	}
	serial, err := randSerial()
	if err != nil {
		return nil, err
	}
	now := time.Now()
	tmpl := &x509.Certificate{
		SerialNumber:          serial,
		Subject:               pkix.Name{CommonName: host},
		NotBefore:             now.Add(-time.Hour),
		NotAfter:              now.Add(825 * 24 * time.Hour),
		KeyUsage:              x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
	}
	if ip := net.ParseIP(host); ip != nil {
		tmpl.IPAddresses = []net.IP{ip}
	} else {
		tmpl.DNSNames = []string{host}
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, c.cert, &key.PublicKey, c.key)
	if err != nil {
		return nil, fmt.Errorf("sign leaf for %s: %w", host, err)
	}
	crt := &tls.Certificate{
		Certificate: [][]byte{der, c.cert.Raw},
		PrivateKey:  key,
	}
	c.leaves[host] = crt
	return crt, nil
}

// forwardProxy answers CONNECT (HTTPS MITM) and absolute-form HTTP proxy
// requests, reusing the reverse-proxy scan/block/redact engine (newProxy) for
// each destination host. One newProxy handler is built and cached per
// origin (scheme://host:port) so the destination is fixed by the request
// itself, not by the provider's route table.
type forwardProxy struct {
	ca     *mitmCA
	logger *log.Logger
	policy Policy
	// transport, when non-nil, is the RoundTripper handed to every per-origin
	// handler built by handlerFor (production leaves it nil for the default
	// transport; tests inject one that redirects to a loopback upstream).
	transport http.RoundTripper
	handlers  sync.Map // origin "scheme://host" -> http.Handler
}

// authExchangeHosts are Google's credential endpoints. A wrapped agent posts
// its OWN OAuth token exchanges here (grant_type=refresh_token with the
// client_secret/refresh_token in the body), so the SAME scan engine would,
// in block mode, mistake those credentials for a leak and 451 the exchange —
// breaking the agent's ability to authenticate. These hosts are therefore
// forwarded WITHOUT inspection so the agent's own credentials always pass
// through intact. Leak scanning of arbitrary app egress is unaffected.
var authExchangeHosts = map[string]struct{}{
	"accounts.google.com":   {},
	"oauth2.googleapis.com": {},
	"www.googleapis.com":    {},
}

// isAuthExchangeHost reports whether host (optionally "host:port") is one of the
// agent's own credential endpoints that must never be blocked or stripped.
func isAuthExchangeHost(host string) bool {
	if h, _, err := net.SplitHostPort(host); err == nil {
		host = h
	}
	host = strings.ToLower(strings.TrimSuffix(host, "."))
	_, ok := authExchangeHosts[host]
	return ok
}

// newForwardProxy builds a forward proxy. Provider Routes are dropped from the
// policy copy: routes multiplex the single reverse-proxy listener across Google
// services, but a forward-proxy destination is already pinned by CONNECT/host,
// so an unrelated path prefix must never redirect a forwarded request.
func newForwardProxy(ca *mitmCA, logger *log.Logger, policy Policy) *forwardProxy {
	p := policy
	p.Provider.Routes = nil
	return &forwardProxy{ca: ca, logger: logger, policy: p}
}

// handlerFor returns the cached scan/block proxy handler for one upstream
// origin, building it on first use. The underlying newProxy forwards to
// scheme://host with the default transport (real TLS, system roots).
func (fp *forwardProxy) handlerFor(scheme, host string) http.Handler {
	key := scheme + "://" + host
	if h, ok := fp.handlers.Load(key); ok {
		return h.(http.Handler)
	}
	u := &url.URL{Scheme: scheme, Host: host}
	var h http.Handler
	if isAuthExchangeHost(host) {
		// The agent's own credential endpoint: forward without inspection so
		// its OAuth token exchange is never blocked/redacted, even in block mode.
		h = newPassthroughProxy(u, fp.logger, fp.transport)
	} else {
		h = newProxy(u, fp.logger, fp.policy, fp.transport)
	}
	actual, _ := fp.handlers.LoadOrStore(key, h)
	return actual.(http.Handler)
}

// newPassthroughProxy forwards every request to upstream verbatim — no scan, no
// block, no redact. It exists solely for the agent's own credential endpoints
// (see authExchangeHosts). It re-injects Proxy-Authorization, which Go's
// ReverseProxy would otherwise drop as a hop-by-hop header, so the agent's
// proxy credential also passes through intact. The request body and the
// Authorization header are forwarded untouched.
func newPassthroughProxy(upstream *url.URL, logger *log.Logger, transport http.RoundTripper) http.Handler {
	logger.Printf("forward-proxy: %s is an auth/OAuth endpoint; forwarding credentials without inspection", upstream.Host)
	proxy := &httputil.ReverseProxy{
		Rewrite: func(pr *httputil.ProxyRequest) {
			pr.SetURL(upstream)
			pr.Out.Host = upstream.Host
			if v := pr.In.Header.Get("Proxy-Authorization"); v != "" {
				pr.Out.Header.Set("Proxy-Authorization", v)
			}
		},
		ErrorHandler: func(w http.ResponseWriter, _ *http.Request, err error) {
			logger.Printf("forward-proxy: auth passthrough error for %s: %v", upstream.Host, err)
			http.Error(w, "upstream error: "+err.Error(), http.StatusBadGateway)
		},
	}
	if transport != nil {
		proxy.Transport = transport
	}
	return proxy
}

// handleHTTP serves a plain-HTTP forward-proxy request (absolute-form URI),
// which arrives when the child honours HTTP_PROXY for an http:// target.
func (fp *forwardProxy) handleHTTP(w http.ResponseWriter, r *http.Request) {
	scheme := r.URL.Scheme
	if scheme == "" {
		scheme = "http"
	}
	fp.handlerFor(scheme, r.URL.Host).ServeHTTP(w, r)
}

// handleConnect terminates `CONNECT host:port`, completes a MITM TLS handshake
// with a CA-signed leaf for the requested host, then serves every request on
// the decrypted connection through the per-host scan/block proxy. Blocking and
// redaction behave exactly as on the reverse path. Any failure before the
// handshake closes the connection without contacting the upstream.
func (fp *forwardProxy) handleConnect(w http.ResponseWriter, r *http.Request) {
	hostport := r.Host
	if hostport == "" {
		hostport = r.URL.Host
	}
	host := hostport
	if h, _, err := net.SplitHostPort(hostport); err == nil {
		host = h
	}

	hj, ok := w.(http.Hijacker)
	if !ok {
		http.Error(w, "masqr: connection hijacking unsupported", http.StatusInternalServerError)
		return
	}
	clientConn, _, err := hj.Hijack()
	if err != nil {
		fp.logger.Printf("forward-proxy: hijack failed for %s: %v", hostport, err)
		return
	}
	// The main server may have left a header-read deadline on the conn; clear
	// it so the MITM TLS session isn't torn down mid-handshake.
	_ = clientConn.SetDeadline(time.Time{})
	if _, err := clientConn.Write([]byte("HTTP/1.1 200 Connection Established\r\n\r\n")); err != nil {
		_ = clientConn.Close()
		return
	}

	tlsConn := tls.Server(clientConn, &tls.Config{
		MinVersion: tls.VersionTLS12,
		GetCertificate: func(hello *tls.ClientHelloInfo) (*tls.Certificate, error) {
			name := hello.ServerName
			if name == "" {
				name = host
			}
			return fp.ca.leafFor(name)
		},
	})
	if err := tlsConn.HandshakeContext(r.Context()); err != nil {
		fp.logger.Printf("forward-proxy: client TLS handshake for %s failed: %v", hostport, err)
		_ = tlsConn.Close()
		return
	}

	handler := http.HandlerFunc(func(rw http.ResponseWriter, req *http.Request) {
		fp.handlerFor("https", hostport).ServeHTTP(rw, req)
	})
	done := make(chan struct{})
	srv := &http.Server{
		Handler:           handler,
		ErrorLog:          fp.logger,
		ReadHeaderTimeout: 30 * time.Second,
		IdleTimeout:       90 * time.Second,
	}
	// Serve blocks until the (single) connection closes — the listener's
	// second Accept unblocks on Close and returns net.ErrClosed.
	_ = srv.Serve(&singleConnListener{
		conn: &notifyConn{Conn: tlsConn, done: done},
		done: done,
	})
}

// ServeHTTP makes forwardProxy a drop-in dispatcher: CONNECT and absolute-form
// requests are handled here, everything else (origin-form requests the child
// sends to the reverse-proxy BASE_URL) falls through to next.
func (fp *forwardProxy) dispatch(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.Method == http.MethodConnect:
			fp.handleConnect(w, r)
		case r.URL.IsAbs() && r.URL.Host != "":
			fp.handleHTTP(w, r)
		default:
			next.ServeHTTP(w, r)
		}
	})
}

// notifyConn closes done exactly once when the connection is closed, letting
// singleConnListener wake its blocked Accept so http.Server.Serve can return.
type notifyConn struct {
	net.Conn
	once sync.Once
	done chan struct{}
}

func (c *notifyConn) Close() error {
	c.once.Do(func() { close(c.done) })
	return c.Conn.Close()
}

// singleConnListener feeds exactly one already-established connection to
// http.Server.Serve, then blocks subsequent Accepts until that connection is
// closed so Serve returns cleanly (no goroutine leak, keep-alive preserved).
type singleConnListener struct {
	conn net.Conn
	once sync.Once
	done chan struct{}
}

func (l *singleConnListener) Accept() (net.Conn, error) {
	first := false
	l.once.Do(func() { first = true })
	if first {
		return l.conn, nil
	}
	<-l.done
	return nil, net.ErrClosed
}

func (l *singleConnListener) Close() error   { return nil }
func (l *singleConnListener) Addr() net.Addr { return l.conn.LocalAddr() }

// CA store filenames inside the per-install CA directory. The certificate is
// world-readable (clients must trust it); the key is owner-only (0600).
const (
	caCertFile    = "ca-cert.pem"
	caKeyFile     = "ca-key.pem"
	caVersionFile = "version"
)

// masqrCADir is the stable per-install directory that holds the source-of-truth
// MITM CA (certificate + private key + version stamp). It lives under the OS
// config dir — <UserConfigDir>/masqr/ca — falling back to the cache dir, and is
// deliberately NOT $PWD so the CA is reused across runs from any directory.
// Returns "" when neither a config nor cache dir is resolvable.
func masqrCADir() string {
	if base, err := os.UserConfigDir(); err == nil && base != "" {
		return filepath.Join(base, "masqr", "ca")
	}
	if c := masqrCacheDir(); c != "" {
		return filepath.Join(c, "ca")
	}
	return ""
}

// loadOrCreateCA implements the persistent per-install CA contract: if dir holds
// a valid CA whose stamped masqr version matches the running binary, that CA is
// REUSED; otherwise (missing, unreadable, key/cert mismatch, expired, or a
// version change from an upgrade) a fresh unique CA is generated and persisted.
// It logs which path was taken and where. The version stamp guarantees a new
// release regenerates, so leaf certs always trace to the binary that minted them.
func loadOrCreateCA(dir, version string, logger *log.Logger) (*mitmCA, error) {
	if ca := tryLoadCA(dir, version); ca != nil {
		logger.Printf("forward-proxy: reusing persisted MITM CA (masqr %s) at %s", version, dir)
		return ca, nil
	}
	ca, err := newMITMCA()
	if err != nil {
		return nil, err
	}
	if err := persistCA(ca, dir, version); err != nil {
		return nil, err
	}
	logger.Printf("forward-proxy: generated new MITM CA (masqr %s) and persisted it at %s", version, dir)
	return ca, nil
}

// tryLoadCA returns a usable CA from dir only when the cert+key+version files
// are all present, the stamped version matches, the key matches the cert, and
// the cert is a currently-valid CA. Any deviation returns nil so the caller
// regenerates — we never reuse a stale or tampered store.
func tryLoadCA(dir, version string) *mitmCA {
	certPEM, err := os.ReadFile(filepath.Join(dir, caCertFile))
	if err != nil {
		return nil
	}
	keyPEM, err := os.ReadFile(filepath.Join(dir, caKeyFile))
	if err != nil {
		return nil
	}
	stamp, err := os.ReadFile(filepath.Join(dir, caVersionFile))
	if err != nil || strings.TrimSpace(string(stamp)) != version {
		return nil
	}
	ca, err := caFromPEM(certPEM, keyPEM)
	if err != nil {
		return nil
	}
	now := time.Now()
	if !ca.cert.IsCA || now.Before(ca.cert.NotBefore) || now.After(ca.cert.NotAfter) {
		return nil
	}
	return ca
}

// persistCA writes the CA cert, private key (mode 0600), and version stamp into
// dir, creating it owner-only. The key is written first under a restrictive mode
// so the private material is never momentarily world-readable.
func persistCA(ca *mitmCA, dir, version string) error {
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return fmt.Errorf("create CA dir %s: %w", dir, err)
	}
	keyPEM, err := ca.keyPEM()
	if err != nil {
		return err
	}
	if err := os.WriteFile(filepath.Join(dir, caKeyFile), keyPEM, 0o600); err != nil {
		return fmt.Errorf("write CA key: %w", err)
	}
	if err := os.WriteFile(filepath.Join(dir, caCertFile), ca.certPEM, 0o644); err != nil {
		return fmt.Errorf("write CA cert: %w", err)
	}
	if err := os.WriteFile(filepath.Join(dir, caVersionFile), []byte(version+"\n"), 0o644); err != nil {
		return fmt.Errorf("write CA version stamp: %w", err)
	}
	return nil
}

// setupForwardProxy resolves the persistent per-install MITM CA (reusing it
// across runs, regenerating on first install or after an upgrade — see
// loadOrCreateCA), exports its certificate PEM so the wrapped child can trust
// masqr's leaves, and builds the forward proxy. The source-of-truth CA lives in
// masqrCADir; MASQR_CA_FILE only overrides WHERE the cert PEM is exported for
// clients. On any failure it logs and returns a nil proxy so the caller
// transparently keeps the reverse-proxy-only behaviour.
func setupForwardProxy(logger *log.Logger, policy Policy) (fp *forwardProxy, caPath, bundlePath string) {
	var ca *mitmCA
	storeDir := masqrCADir()
	if storeDir != "" {
		if c, err := loadOrCreateCA(storeDir, version, logger); err != nil {
			logger.Printf("forward-proxy: persistent CA store unavailable (%v); falling back to an ephemeral in-memory CA", err)
		} else {
			ca = c
		}
	}
	if ca == nil {
		c, err := newMITMCA()
		if err != nil {
			logger.Printf("forward-proxy disabled: %v", err)
			return nil, "", ""
		}
		ca = c
		logger.Printf("forward-proxy: using an ephemeral in-memory MITM CA (no persistent store available)")
	}

	// MASQR_CA_FILE overrides where the cert PEM is EXPORTED for clients; the
	// source-of-truth CA still lives in storeDir. With no override the child is
	// pointed straight at the persisted cert (no copy in $PWD).
	sourceCert := ""
	if storeDir != "" {
		sourceCert = filepath.Join(storeDir, caCertFile)
	}
	caPath = os.Getenv("MASQR_CA_FILE")
	if caPath == "" {
		if sourceCert != "" {
			caPath = sourceCert
		} else if wd, err := os.Getwd(); err == nil {
			caPath = filepath.Join(wd, "masqr-ca.pem")
		} else {
			caPath = "masqr-ca.pem"
		}
	}
	// Export the cert PEM unless caPath already IS the persisted source file
	// (which loadOrCreateCA already wrote/validated).
	if caPath != sourceCert {
		if err := ca.writeCAFile(caPath); err != nil {
			logger.Printf("forward-proxy disabled: cannot write CA file %s: %v", caPath, err)
			return nil, "", ""
		}
	}
	logger.Printf("forward-proxy MITM enabled; CA certificate available at %s", caPath)

	// Build a trust bundle (system roots + masqr CA) so a child pointed at
	// SSL_CERT_FILE can still validate any host masqr forwards to, not just
	// masqr's own leaf certs. Falling back to the bare CA is fine when no
	// system bundle is found (in proxy mode the child only ever TLS-handshakes
	// with masqr anyway).
	bundlePath, err := writeCABundle(ca.certPEM)
	if err != nil {
		logger.Printf("forward-proxy: trust bundle unavailable (%v); child SSL_CERT_FILE left unset", err)
		bundlePath = ""
	}

	return newForwardProxy(ca, logger, policy), caPath, bundlePath
}

// systemCABundleFiles are the conventional locations of the OS trust store in
// PEM form, in rough order of prevalence across Linux distributions and BSDs.
var systemCABundleFiles = []string{
	"/etc/ssl/certs/ca-certificates.crt", // Debian/Ubuntu/Alpine
	"/etc/pki/tls/certs/ca-bundle.crt",   // Fedora/RHEL/CentOS
	"/etc/ssl/ca-bundle.pem",             // OpenSUSE
	"/etc/ssl/cert.pem",                  // Alpine/macOS(Homebrew)/BSD
	"/etc/pki/tls/cacert.pem",            // OpenELEC
}

// writeCABundle writes a temp PEM file containing the system trust store (if
// one is found) followed by the masqr CA, returning its path. When no system
// bundle exists the file holds the masqr CA alone.
func writeCABundle(caPEM []byte) (string, error) {
	f, err := os.CreateTemp("", "masqr-ca-bundle-*.pem")
	if err != nil {
		return "", err
	}
	if sys := readFirstFile(systemCABundleFiles); len(sys) > 0 {
		if _, err := f.Write(sys); err != nil {
			_ = f.Close()
			return "", err
		}
		if len(sys) > 0 && sys[len(sys)-1] != '\n' {
			_, _ = f.Write([]byte("\n"))
		}
	}
	if _, err := f.Write(caPEM); err != nil {
		_ = f.Close()
		return "", err
	}
	if err := f.Close(); err != nil {
		return "", err
	}
	return f.Name(), nil
}

func readFirstFile(paths []string) []byte {
	for _, p := range paths {
		if b, err := os.ReadFile(p); err == nil && len(b) > 0 {
			return b
		}
	}
	return nil
}

// childProxyEnv returns the environment additions that point the wrapped child
// at masqr's forward proxy and make it trust the masqr CA. endpoint is masqr's
// own listener (http://127.0.0.1:PORT). Loopback is excluded via NO_PROXY so
// the child's reverse-proxy BASE_URL traffic (also on 127.0.0.1) doesn't loop
// back through the proxy. SSL_CERT_FILE covers Go (and OpenSSL) children;
// NODE_EXTRA_CA_CERTS covers Node/Electron agents (agy/antigravity).
func childProxyEnv(endpoint, caFile, bundleFile string) []string {
	env := []string{
		"HTTP_PROXY=" + endpoint,
		"HTTPS_PROXY=" + endpoint,
		"http_proxy=" + endpoint,
		"https_proxy=" + endpoint,
		"NO_PROXY=127.0.0.1,localhost,::1",
		"no_proxy=127.0.0.1,localhost,::1",
	}
	if bundleFile != "" {
		env = append(env, "SSL_CERT_FILE="+bundleFile)
	}
	if caFile != "" {
		env = append(env, "NODE_EXTRA_CA_CERTS="+caFile)
	}
	return env
}
