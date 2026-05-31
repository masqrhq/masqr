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
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	_ "embed"
	"encoding/pem"
	"errors"
	"fmt"
	"log"
	"math/big"
	"net"
	"net/http"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"time"

	"golang.org/x/sync/errgroup"
)

// resolverShimSrc is the C source of the LD_PRELOAD getaddrinfo interposer
// (see resolver_shim.c). It's embedded — not a prebuilt .so — so the masqr
// binary stays arch-independent and `go build`/`go test` need no toolchain;
// ldPreloadResolver compiles it with `cc` at runtime and falls back to
// /etc/hosts if no compiler is present.
//
//go:embed embedsrc/resolver_shim.c
var resolverShimSrc string

// interceptListenAddr is where the transparent TLS proxy binds. Both redirect
// strategies steer the target hostname here, so it must match the redirect IP.
const interceptListenAddr = "127.0.0.1:443"
const interceptRedirectIP = "127.0.0.1"

// runIntercept is the provider-Intercept counterpart to run()'s plaintext
// reverse-proxy path. It stands up a transparent TLS proxy on
// interceptListenAddr, redirects the provider's hardcoded API host to it
// (LD_PRELOAD shim, or /etc/hosts fallback), and PTY-attaches the child. The
// existing newProxy handler — scan/redact/block and all — is reused verbatim;
// only the transport (pinned to the real upstream IP) and the TLS front differ.
func runIntercept(ctx context.Context, cliPath string, cliArgs []string, grace time.Duration, upstream *url.URL, logger *log.Logger, policy Policy, logPath string) error {
	host := upstream.Hostname()

	// Resolve the real upstream IP up front — before any /etc/hosts redirect
	// could shadow it — and pin it in the proxy transport so forwarding never
	// loops back into our own listener.
	realIP, err := resolveUpstreamIP(ctx, host)
	if err != nil {
		return fmt.Errorf("resolve upstream %s: %w", host, err)
	}

	// After `masqr --macos-setup`, /etc/hosts + a pf rdr already route the host
	// to an unprivileged :8443, so masqr listens there and needs no per-session
	// sudo. Otherwise it binds :443 directly.
	listenAddr := interceptListenAddr
	if runtime.GOOS == "darwin" && macosSetupPresent() {
		listenAddr = interceptUnprivAddr
	}

	cf, err := newInterceptCA(logger)
	if err != nil {
		return fmt.Errorf("intercept CA: %w", err)
	}

	dir, err := os.MkdirTemp("", "masqr-intercept-")
	if err != nil {
		return fmt.Errorf("temp dir: %w", err)
	}
	defer func() { _ = os.RemoveAll(dir) }()

	// The SSL_CERT_FILE trust bundle is a Linux mechanism; macOS trusts the
	// persistent CA via the Keychain instead, so skip it there.
	var bundle string
	if runtime.GOOS != "darwin" {
		if bundle, err = writeTrustBundle(cf.caPEM, dir); err != nil {
			return fmt.Errorf("write trust bundle: %w", err)
		}
	}

	red, err := selectRedirector(host, bundle, dir, logger)
	if err != nil {
		return fmt.Errorf("set up redirect: %w", err)
	}
	defer func() {
		if terr := red.Teardown(); terr != nil {
			logger.Printf("intercept: redirect teardown: %v", terr)
		}
	}()

	ln, err := net.Listen("tcp", listenAddr)
	if err != nil {
		hint := "binding :443 may need 'sudo setcap cap_net_bind_service=+ep' on the masqr binary, or lowering net.ipv4.ip_unprivileged_port_start"
		if runtime.GOOS == "darwin" {
			hint = "on macOS, either run `sudo masqr --macos-setup` once (then no sudo), or run `sudo masqr agy`"
		}
		return fmt.Errorf("listen %s: %w (%s)", listenAddr, err, hint)
	}

	srv := &http.Server{
		Handler:           newProxy(upstream, logger, policy, pinnedTransport(host, realIP)),
		ReadHeaderTimeout: 5 * time.Second,
		TLSConfig: &tls.Config{
			NextProtos:     []string{"http/1.1"}, // agy's Code Assist client is HTTP/1.1
			GetCertificate: cf.getCertificate,
		},
	}

	printBanner(os.Stderr, "https://"+host+" (transparent intercept on "+interceptListenAddr+")", policy.Provider, logPath)

	// Cancel on child exit so the TLS server shuts down and g.Wait returns —
	// mirrors run()'s stop() call on the plaintext path.
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()

	g, ctx := errgroup.WithContext(ctx)
	g.Go(func() error {
		if err := srv.ServeTLS(ln, "", ""); err != nil && !errors.Is(err, http.ErrServerClosed) {
			return err
		}
		return nil
	})
	g.Go(func() error {
		<-ctx.Done()
		shutdownCtx, cancel := context.WithTimeout(context.Background(), grace)
		defer cancel()
		return srv.Shutdown(shutdownCtx)
	})
	g.Go(func() error {
		// Intercept providers carry no base-URL EnvVars; redirection +
		// trust come from redirector.Env() instead. ExtraArgs are still
		// honored for symmetry (agy has none).
		extras := expandExtraArgs(policy.Provider.ExtraArgs, "")
		mergedArgs := append(append([]string{}, extras...), cliArgs...)
		err := runCLI(ctx, cliPath, mergedArgs, policy.Provider.EnvVars, "", red.Env())
		cancel() // child exited → tear down the listener
		return err
	})

	if err := g.Wait(); err != nil && !errors.Is(err, context.Canceled) {
		return err
	}
	return nil
}

func resolveIPv4(ctx context.Context, host string) (string, error) {
	ips, err := net.DefaultResolver.LookupIP(ctx, "ip4", host)
	if err != nil {
		return "", err
	}
	if len(ips) == 0 {
		return "", fmt.Errorf("no IPv4 address for %s", host)
	}
	return ips[0].String(), nil
}

// pinnedTransport forwards to the real upstream by dialing a fixed IP for the
// intercepted host (so a /etc/hosts redirect pointing that host at loopback
// can't loop us back to ourselves), while TLS still validates against the real
// hostname via the system root pool (ServerName is derived by the transport
// from the request URL host, not the dial address).
func pinnedTransport(host, ip string) *http.Transport {
	dialer := &net.Dialer{Timeout: 10 * time.Second, KeepAlive: 30 * time.Second}
	return &http.Transport{
		DialContext: func(ctx context.Context, network, addr string) (net.Conn, error) {
			if h, port, err := net.SplitHostPort(addr); err == nil && h == host {
				addr = net.JoinHostPort(ip, port)
			}
			return dialer.DialContext(ctx, network, addr)
		},
		ForceAttemptHTTP2:     true,
		MaxIdleConns:          100,
		IdleConnTimeout:       90 * time.Second,
		TLSHandshakeTimeout:   10 * time.Second,
		ExpectContinueTimeout: time.Second,
	}
}

// --- on-the-fly CA + per-SNI leaf certs ---

type certFactory struct {
	caCert *x509.Certificate
	caKey  *ecdsa.PrivateKey
	caPEM  []byte
	mu     sync.Mutex
	leaves map[string]*tls.Certificate
}

func newCertFactory() (*certFactory, error) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, err
	}
	tmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "masqr transient intercept CA"},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(24 * time.Hour),
		IsCA:                  true,
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageDigitalSignature,
		BasicConstraintsValid: true,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		return nil, err
	}
	caCert, err := x509.ParseCertificate(der)
	if err != nil {
		return nil, err
	}
	return &certFactory{
		caCert: caCert,
		caKey:  key,
		caPEM:  pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}),
		leaves: map[string]*tls.Certificate{},
	}, nil
}

func (f *certFactory) getCertificate(chi *tls.ClientHelloInfo) (*tls.Certificate, error) {
	host := chi.ServerName
	if host == "" {
		// No SNI: the client reached us at an IP literal (the CLOUD_CODE_URL
		// random-port path — Go omits SNI for IP addresses per RFC 6066). Serve
		// a loopback leaf carrying an IP SAN instead of failing.
		host = interceptRedirectIP
	}
	return f.leafFor(host)
}

func (f *certFactory) leafFor(host string) (*tls.Certificate, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if c, ok := f.leaves[host]; ok {
		return c, nil
	}
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, err
	}
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(time.Now().UnixNano()),
		Subject:      pkix.Name{CommonName: host},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(24 * time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}
	// An IP host (CLOUD_CODE_URL=https://127.0.0.1:<port>) must go in the IP SAN
	// — Go validates IP literals against IPAddresses, not DNSNames.
	if ip := net.ParseIP(host); ip != nil {
		tmpl.IPAddresses = []net.IP{ip}
	} else {
		tmpl.DNSNames = []string{host}
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, f.caCert, &key.PublicKey, f.caKey)
	if err != nil {
		return nil, err
	}
	c := &tls.Certificate{Certificate: [][]byte{der, f.caCert.Raw}, PrivateKey: key}
	f.leaves[host] = c
	return c, nil
}

// systemCABundleFiles mirrors crypto/x509's Linux/BSD search list. The first
// that exists is the host trust store we concatenate our CA onto.
var systemCABundleFiles = []string{
	"/etc/ssl/certs/ca-certificates.crt",                // Debian/Ubuntu/Alpine
	"/etc/pki/tls/certs/ca-bundle.crt",                  // Fedora/RHEL
	"/etc/ssl/ca-bundle.pem",                            // openSUSE
	"/etc/pki/ca-trust/extracted/pem/tls-ca-bundle.pem", // CentOS/RHEL alt
	"/etc/ssl/cert.pem",                                 // macOS/Alpine
}

// writeTrustBundle writes (system roots ++ masqr CA) to <dir>/bundle.pem and
// returns the path. The system roots MUST be included: only the intercepted
// host is redirected, so the child's other TLS calls (OAuth refresh, telemetry)
// still hit real endpoints and must validate against real roots.
func writeTrustBundle(caPEM []byte, dir string) (string, error) {
	var sys []byte
	for _, p := range systemCABundleFiles {
		if b, err := os.ReadFile(p); err == nil && len(b) > 0 {
			sys = b
			break
		}
	}
	path := filepath.Join(dir, "bundle.pem")
	contents := caPEM
	if len(sys) > 0 {
		if len(sys) > 0 && sys[len(sys)-1] != '\n' {
			sys = append(sys, '\n')
		}
		contents = append(append([]byte{}, sys...), caPEM...)
	}
	if err := os.WriteFile(path, contents, 0o644); err != nil {
		return "", err
	}
	return path, nil
}

// --- redirect strategies ---

// Redirector makes the child's lookups of the intercepted host resolve to
// masqr's local listener, and supplies the extra child env (trust bundle, plus
// for LD_PRELOAD the shim wiring). Teardown reverses any system change.
type Redirector interface {
	Env() []string
	Teardown() error
}

// selectRedirector returns an already-set-up Redirector: the no-sudo
// LD_PRELOAD shim on Linux when a C compiler is available, otherwise the
// /etc/hosts fallback. MASQR_INTERCEPT_REDIRECT=hosts|ldpreload forces one.
func selectRedirector(host, bundle, dir string, logger *log.Logger) (Redirector, error) {
	// macOS: no LD_PRELOAD (DYLD insertion is blocked for notarized binaries);
	// redirect via /etc/hosts and rely on the Keychain-trusted persistent CA.
	if runtime.GOOS == "darwin" {
		if macosSetupPresent() {
			logger.Printf("intercept: macOS persistent setup detected — listening on :8443, no per-session sudo")
			return noopRedirector{}, nil
		}
		r := &hostsBind443{host: host}
		if err := r.setup(); err != nil {
			return nil, err
		}
		logger.Printf("intercept: redirecting %s via /etc/hosts (trust via Keychain)", host)
		return &darwinRedirector{inner: r}, nil
	}

	force := os.Getenv("MASQR_INTERCEPT_REDIRECT")
	tryLD := func() (Redirector, error) {
		r := &ldPreloadResolver{host: host, bundle: bundle, dir: dir}
		if err := r.setup(); err != nil {
			return nil, err
		}
		logger.Printf("intercept: redirecting %s via LD_PRELOAD resolver shim (no sudo)", host)
		return r, nil
	}
	tryHosts := func() (Redirector, error) {
		r := &hostsBind443{host: host, bundle: bundle}
		if err := r.setup(); err != nil {
			return nil, err
		}
		logger.Printf("intercept: redirecting %s via /etc/hosts", host)
		return r, nil
	}

	switch force {
	case "hosts":
		return tryHosts()
	case "ldpreload":
		return tryLD()
	}
	if runtime.GOOS == "linux" {
		if r, err := tryLD(); err == nil {
			return r, nil
		} else {
			logger.Printf("intercept: LD_PRELOAD shim unavailable (%v); falling back to /etc/hosts", err)
		}
	}
	return tryHosts()
}

// ldPreloadResolver compiles the embedded shim and points the child at it.
type ldPreloadResolver struct {
	host, bundle, dir string
	shimPath          string
}

func (r *ldPreloadResolver) setup() error {
	cc := "cc"
	if _, err := exec.LookPath(cc); err != nil {
		if _, err2 := exec.LookPath("gcc"); err2 != nil {
			return fmt.Errorf("no C compiler (cc/gcc) for the resolver shim: %w", err)
		}
		cc = "gcc"
	}
	src := filepath.Join(r.dir, "resolver_shim.c")
	if err := os.WriteFile(src, []byte(resolverShimSrc), 0o600); err != nil {
		return err
	}
	r.shimPath = filepath.Join(r.dir, "resolver_shim.so")
	if out, err := exec.Command(cc, "-shared", "-fPIC", "-o", r.shimPath, src, "-ldl").CombinedOutput(); err != nil {
		return fmt.Errorf("compile shim: %w: %s", err, strings.TrimSpace(string(out)))
	}
	return nil
}

func (r *ldPreloadResolver) Env() []string {
	return []string{
		"SSL_CERT_FILE=" + r.bundle,
		"GODEBUG=netdns=cgo", // force the Go child through libc getaddrinfo so the shim sees the lookup
		"LD_PRELOAD=" + r.shimPath,
		"MASQR_REDIRECT_HOST=" + r.host,
		"MASQR_REDIRECT_IP=" + interceptRedirectIP,
	}
}

// Teardown is a no-op: the shim lives in the temp dir runIntercept removes, and
// the env is scoped to the child process tree.
func (r *ldPreloadResolver) Teardown() error { return nil }

// hostsBind443 adds a loopback /etc/hosts entry for the target (via sudo) and
// removes it on teardown. Fallback for non-Linux or no-compiler hosts.
type hostsBind443 struct {
	host, bundle string
	added        bool
}

const hostsMarker = "# masqr-intercept"

func (h *hostsBind443) setup() error {
	if data, err := os.ReadFile("/etc/hosts"); err == nil && strings.Contains(string(data), hostsMarker) {
		return fmt.Errorf("a stale %q line is already in /etc/hosts; remove it and retry", hostsMarker)
	}
	line := interceptRedirectIP + " " + h.host + " " + hostsMarker
	cmd := exec.Command("sudo", "sh", "-c", "printf '%s\\n' "+shellSingleQuote(line)+" >> /etc/hosts")
	cmd.Stdin, cmd.Stderr = os.Stdin, os.Stderr
	if err := cmd.Run(); err != nil {
		return fmt.Errorf("append to /etc/hosts via sudo: %w", err)
	}
	h.added = true
	return nil
}

func (h *hostsBind443) Env() []string { return []string{"SSL_CERT_FILE=" + h.bundle} }

func (h *hostsBind443) Teardown() error {
	if !h.added {
		return nil
	}
	// Remove only masqr's marked line, preserving everything else.
	script := "tmp=$(mktemp) && grep -v " + shellSingleQuote(hostsMarker) + " /etc/hosts > \"$tmp\" && cat \"$tmp\" > /etc/hosts && rm -f \"$tmp\""
	cmd := exec.Command("sudo", "sh", "-c", script)
	cmd.Stderr = os.Stderr
	return cmd.Run()
}

// shellSingleQuote wraps s in single quotes, escaping embedded ones, for safe
// interpolation into the `sudo sh -c` scripts above.
func shellSingleQuote(s string) string {
	return "'" + strings.ReplaceAll(s, "'", `'\''`) + "'"
}
