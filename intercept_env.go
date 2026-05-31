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
	"errors"
	"fmt"
	"log"
	"net"
	"net/http"
	"net/url"
	"os"
	"time"

	"golang.org/x/sync/errgroup"
)

// runInterceptEnv is the no-sudo TLS-intercept path. Unlike runIntercept (which
// redirects the provider's hardcoded hostname to a privileged :443 listener via
// LD_PRELOAD or /etc/hosts), it binds a *random free loopback port* and points
// the child straight at it through an https:// endpoint override env var
// (agy's CLOUD_CODE_URL — the scheme selects the transport, so https:// makes
// the Code Assist client speak TLS to us). masqr terminates that TLS with an
// on-the-fly CA the child trusts via SSL_CERT_FILE, scans/blocks/redacts in the
// shared newProxy handler, then forwards to the pinned real upstream over real
// TLS. No :443, no sudo/setcap, no LD_PRELOAD shim, no /etc/hosts edit.
//
// The endpoint override env var(s) come from the provider profile's EnvVars
// (CLOUD_CODE_URL for antigravity); the only difference from the plaintext path
// is the https:// scheme and the local TLS termination — which also gives masqr
// the decrypted *response* stream, not just the request.
func runInterceptEnv(ctx context.Context, cliPath string, cliArgs []string, grace time.Duration, upstream *url.URL, logger *log.Logger, policy Policy, logPath string) error {
	host := upstream.Hostname()

	// Resolve the real upstream IP and pin it in the forwarding transport so the
	// proxy reaches the genuine backend (TLS still validates against the real
	// hostname via the system roots).
	realIP, err := resolveUpstreamIP(ctx, host)
	if err != nil {
		return fmt.Errorf("resolve upstream %s: %w", host, err)
	}

	cf, err := newCertFactory()
	if err != nil {
		return fmt.Errorf("intercept CA: %w", err)
	}

	dir, err := os.MkdirTemp("", "masqr-intercept-")
	if err != nil {
		return fmt.Errorf("temp dir: %w", err)
	}
	defer func() { _ = os.RemoveAll(dir) }()

	// SSL_CERT_FILE = system roots ++ masqr CA, so the child trusts our leaf for
	// the intercepted endpoint while its other TLS calls (OAuth refresh) still
	// validate against real roots. (Linux/BSD mechanism; Go ignores it on macOS.)
	bundle, err := writeTrustBundle(cf.caPEM, dir)
	if err != nil {
		return fmt.Errorf("write trust bundle: %w", err)
	}

	// Bind a random free loopback port — the whole point of this path.
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		return fmt.Errorf("listen: %w", err)
	}
	endpoint := "https://" + ln.Addr().String()

	envVars := policy.Provider.EnvVars
	if len(envVars) == 0 {
		envVars = []string{"CLOUD_CODE_URL"}
	}

	srv := &http.Server{
		Handler:           newProxy(upstream, logger, policy, pinnedTransport(host, realIP)),
		ReadHeaderTimeout: 5 * time.Second,
		TLSConfig: &tls.Config{
			NextProtos:     []string{"http/1.1"}, // agy's Code Assist client is HTTP/1.1
			GetCertificate: cf.getCertificate,
		},
	}

	printBanner(os.Stderr, endpoint+" (TLS intercept, random port)", policy.Provider, logPath)

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
		// Mirror the plaintext path: substitute {{endpoint}} into the provider's
		// ExtraArgs (codex needs `-c openai_base_url="<endpoint>/v1"` — it ignores
		// the OPENAI_BASE_URL env) and prepend them ahead of the user's args.
		extras := expandExtraArgs(policy.Provider.ExtraArgs, endpoint)
		mergedArgs := append(append([]string{}, extras...), cliArgs...)
		// Export each EnvVars name = our https endpoint, plus the trust bundle.
		extraEnv := []string{"SSL_CERT_FILE=" + bundle}
		err := runCLI(ctx, cliPath, mergedArgs, envVars, endpoint, extraEnv)
		cancel() // child exited → tear down the listener
		return err
	})

	if err := g.Wait(); err != nil && !errors.Is(err, context.Canceled) {
		return err
	}
	return nil
}
