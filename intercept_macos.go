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
	"net/url"
	"os"
	"os/exec"
	"os/user"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"time"
)

// macOS differs from Linux in two ways that shape the intercept path:
//
//  1. Go on darwin ignores SSL_CERT_FILE and verifies against the Keychain, so
//     masqr can't inject trust per-run. The CA must be *persistent* and trusted
//     once by the user (`security add-trusted-cert`).
//  2. DYLD_INSERT_LIBRARIES is blocked for notarized binaries, so the LD_PRELOAD
//     resolver shim doesn't apply — redirect falls back to /etc/hosts.
//
// This file holds the darwin-specific CA persistence and redirector. The
// behaviour is gated by runtime.GOOS at the call sites in intercept.go, so the
// file still compiles (dormant) on other platforms.

const macCAName = "masqr local CA"

// userHomeDir returns the *invoking* user's home — under `sudo masqr agy`,
// os.UserHomeDir would return root's, but the trusted CA and agy's config live
// in the real user's home.
func userHomeDir() string {
	if su := os.Getenv("SUDO_USER"); su != "" {
		if u, err := user.Lookup(su); err == nil {
			return u.HomeDir
		}
	}
	h, _ := os.UserHomeDir()
	return h
}

// newInterceptCA returns the CA the transparent proxy signs leaves with: an
// ephemeral per-run CA on Linux (trust injected via SSL_CERT_FILE), or the
// persistent, Keychain-trusted CA under ~/.masqr on macOS. On first macOS run it
// generates the CA and returns instructions to trust it once.
func newInterceptCA(logger *log.Logger) (*certFactory, error) {
	if runtime.GOOS != "darwin" {
		return newCertFactory()
	}
	caDir := filepath.Join(userHomeDir(), ".masqr")
	certPath := filepath.Join(caDir, "ca.pem")
	keyPath := filepath.Join(caDir, "ca-key.pem")
	if cf, err := loadPersistentCA(certPath, keyPath); err == nil {
		logger.Printf("intercept: using persistent CA %s (trusted via Keychain)", certPath)
		return cf, nil
	}
	if err := os.MkdirAll(caDir, 0o700); err != nil {
		return nil, err
	}
	cf, keyPEM, err := generatePersistentCA()
	if err != nil {
		return nil, err
	}
	if err := os.WriteFile(certPath, cf.caPEM, 0o644); err != nil {
		return nil, err
	}
	if err := os.WriteFile(keyPath, keyPEM, 0o600); err != nil {
		return nil, err
	}
	chownToInvokingUser(caDir, certPath, keyPath)
	return nil, fmt.Errorf("created masqr CA at %s — trust it once (approve the dialog), then re-run:\n"+
		"  sudo security add-trusted-cert -d -r trustRoot -k /Library/Keychains/System.keychain %s",
		certPath, certPath)
}

func loadPersistentCA(certPath, keyPath string) (*certFactory, error) {
	cp, err := os.ReadFile(certPath)
	if err != nil {
		return nil, err
	}
	kp, err := os.ReadFile(keyPath)
	if err != nil {
		return nil, err
	}
	cb, _ := pem.Decode(cp)
	kb, _ := pem.Decode(kp)
	if cb == nil || kb == nil {
		return nil, fmt.Errorf("malformed CA PEM in %s", filepath.Dir(certPath))
	}
	caCert, err := x509.ParseCertificate(cb.Bytes)
	if err != nil {
		return nil, err
	}
	k, err := x509.ParsePKCS8PrivateKey(kb.Bytes)
	if err != nil {
		return nil, err
	}
	eck, ok := k.(*ecdsa.PrivateKey)
	if !ok {
		return nil, fmt.Errorf("CA key is not ECDSA")
	}
	return &certFactory{caCert: caCert, caKey: eck, caPEM: cp, leaves: map[string]*tls.Certificate{}}, nil
}

func generatePersistentCA() (*certFactory, []byte, error) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, nil, err
	}
	tmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(time.Now().Unix()),
		Subject:               pkix.Name{CommonName: macCAName},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().AddDate(10, 0, 0), // persistent: trusted once, reused
		IsCA:                  true,
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageDigitalSignature,
		BasicConstraintsValid: true,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		return nil, nil, err
	}
	caCert, err := x509.ParseCertificate(der)
	if err != nil {
		return nil, nil, err
	}
	keyDER, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		return nil, nil, err
	}
	cf := &certFactory{
		caCert: caCert,
		caKey:  key,
		caPEM:  pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}),
		leaves: map[string]*tls.Certificate{},
	}
	return cf, pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: keyDER}), nil
}

// chownToInvokingUser hands files created under sudo back to the real user.
func chownToInvokingUser(paths ...string) {
	su, sg := os.Getenv("SUDO_UID"), os.Getenv("SUDO_GID")
	if su == "" {
		return
	}
	uid, _ := strconv.Atoi(su)
	gid, _ := strconv.Atoi(sg)
	for _, p := range paths {
		_ = os.Chown(p, uid, gid)
	}
}

// darwinRedirector redirects the target hostname via /etc/hosts (masqr runs
// under sudo on macOS) and relies on the user's one-time Keychain trust. It
// injects no SSL_CERT_FILE — Go ignores it on macOS.
type darwinRedirector struct{ inner *hostsBind443 }

func (d *darwinRedirector) Env() []string   { return nil }
func (d *darwinRedirector) Teardown() error { return d.inner.Teardown() }

// noopRedirector is used on macOS once the persistent setup (--macos-setup) is
// in place: /etc/hosts + the pf rdr already route the host to masqr's :8443
// listener, so there is nothing to do per session and no sudo is needed.
type noopRedirector struct{}

func (noopRedirector) Env() []string   { return nil }
func (noopRedirector) Teardown() error { return nil }

// --- one-time, no-per-session-sudo macOS setup: /etc/hosts + pf rdr :443->:8443 ---

const (
	interceptUnprivAddr = "127.0.0.1:8443"
	pfAnchorName        = "com.masqr"
	pfAnchorFile        = "/etc/pf.anchors/com.masqr"
	pfConfFile          = "/etc/pf.conf"
	pfConfBackup        = "/etc/pf.conf.masqr-backup"
	pfLaunchDaemon      = "/Library/LaunchDaemons/com.masqr.pf.plist"
	hostsFile           = "/etc/hosts"
	pfRedirectRule      = "rdr pass on lo0 inet proto tcp from any to 127.0.0.1 port 443 -> 127.0.0.1 port 8443\n"
)

const pfPlist = `<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0"><dict>
  <key>Label</key><string>com.masqr.pf</string>
  <key>ProgramArguments</key><array>
    <string>/sbin/pfctl</string><string>-ef</string><string>/etc/pf.conf</string>
  </array>
  <key>RunAtLoad</key><true/>
</dict></plist>
`

// macosSetupPresent reports whether `masqr --macos-setup` has installed the
// persistent /etc/hosts redirect (the marker line). When present, runIntercept
// listens on :8443 and skips the per-session hosts edit (no sudo at runtime).
func macosSetupPresent() bool {
	b, err := os.ReadFile(hostsFile)
	return err == nil && bytes.Contains(b, []byte(hostsMarker))
}

// resolveUpstreamIP resolves the real upstream IP. On macOS it queries DNS
// directly (dig @8.8.8.8) to bypass the persistent /etc/hosts entry that points
// the host at loopback — otherwise masqr would forward to itself.
func resolveUpstreamIP(ctx context.Context, host string) (string, error) {
	if runtime.GOOS == "darwin" {
		if ip := digA(ctx, host); ip != "" {
			return ip, nil
		}
	}
	return resolveIPv4(ctx, host)
}

func digA(ctx context.Context, host string) string {
	out, err := exec.CommandContext(ctx, "dig", "+short", "+time=3", "+tries=1", "A", host, "@8.8.8.8").Output()
	if err != nil {
		return ""
	}
	for _, line := range strings.Split(strings.TrimSpace(string(out)), "\n") {
		line = strings.TrimSpace(line)
		if ip := net.ParseIP(line); ip != nil && ip.To4() != nil {
			return line
		}
	}
	return ""
}

func mustHostname(rawURL string) string {
	if u, err := url.Parse(rawURL); err == nil && u.Hostname() != "" {
		return u.Hostname()
	}
	return rawURL
}

// macosSetup performs the one-time privileged install (run with sudo): a
// persistent /etc/hosts redirect, a pf rdr :443->:8443 anchor wired into
// /etc/pf.conf, and a LaunchDaemon that re-enables pf at boot. Idempotent.
func macosSetup() error {
	host := mustHostname(antigravityProfile.Target)
	fmt.Printf("masqr: macOS one-time setup for %s\n", host)

	if err := addHostsLine(host); err != nil {
		return fmt.Errorf("/etc/hosts: %w", err)
	}
	if err := os.WriteFile(pfAnchorFile, []byte(pfRedirectRule), 0o644); err != nil {
		return fmt.Errorf("write %s: %w", pfAnchorFile, err)
	}
	if err := installPFAnchorRefs(); err != nil {
		return fmt.Errorf("/etc/pf.conf: %w", err)
	}
	if err := os.WriteFile(pfLaunchDaemon, []byte(pfPlist), 0o644); err != nil {
		return fmt.Errorf("write LaunchDaemon: %w", err)
	}
	_ = exec.Command("launchctl", "load", "-w", pfLaunchDaemon).Run()
	// Enable + load now so it works without a reboot (pfctl -ef returns nonzero
	// in some states even on success; trust the "enabled"/loaded outcome).
	_ = exec.Command("pfctl", "-ef", pfConfFile).Run()

	caPath := filepath.Join(userHomeDir(), ".masqr", "ca.pem")
	fmt.Println("✓ /etc/hosts + pf rdr :443->:8443 + LaunchDaemon installed.")
	fmt.Println("If you haven't trusted the CA yet, do it once:")
	fmt.Printf("  sudo security add-trusted-cert -d -r trustRoot -k /Library/Keychains/System.keychain %s\n", caPath)
	fmt.Println("Then run WITHOUT sudo:  masqr agy")
	return nil
}

// macosTeardown reverses macosSetup. Best-effort; leaves the CA trust intact.
func macosTeardown() error {
	_ = exec.Command("launchctl", "unload", "-w", pfLaunchDaemon).Run()
	_ = os.Remove(pfLaunchDaemon)

	if b, err := os.ReadFile(pfConfBackup); err == nil {
		_ = os.WriteFile(pfConfFile, b, 0o644)
		_ = os.Remove(pfConfBackup)
	} else {
		stripLines(pfConfFile, pfAnchorName)
	}
	_ = os.Remove(pfAnchorFile)
	_ = exec.Command("pfctl", "-f", pfConfFile).Run()
	stripLines(hostsFile, hostsMarker)
	fmt.Println("✓ masqr macOS setup removed (CA trust left intact — remove via Keychain Access if desired).")
	return nil
}

func addHostsLine(host string) error {
	b, err := os.ReadFile(hostsFile)
	if err != nil {
		return err
	}
	if bytes.Contains(b, []byte(hostsMarker)) {
		return nil // idempotent
	}
	f, err := os.OpenFile(hostsFile, os.O_APPEND|os.O_WRONLY, 0o644)
	if err != nil {
		return err
	}
	defer f.Close()
	_, err = f.WriteString("127.0.0.1 " + host + " " + hostsMarker + "\n")
	return err
}

// installPFAnchorRefs adds the com.masqr rdr-anchor + load-anchor lines to
// /etc/pf.conf (after the com.apple anchors so translation precedes filtering),
// backing up the original and validating with `pfctl -nf` before applying.
func installPFAnchorRefs() error {
	cur, err := os.ReadFile(pfConfFile)
	if err != nil {
		return err
	}
	if bytes.Contains(cur, []byte(pfAnchorName)) {
		return nil // idempotent
	}
	if _, err := os.Stat(pfConfBackup); os.IsNotExist(err) {
		if err := os.WriteFile(pfConfBackup, cur, 0o644); err != nil {
			return err
		}
	}
	var b strings.Builder
	var sawRdr, sawLoad bool
	for _, line := range strings.Split(string(cur), "\n") {
		b.WriteString(line)
		b.WriteByte('\n')
		if strings.HasPrefix(line, `rdr-anchor "com.apple/*"`) {
			b.WriteString(`rdr-anchor "` + pfAnchorName + "\"\n")
			sawRdr = true
		}
		if strings.HasPrefix(line, `load anchor "com.apple"`) {
			b.WriteString(`load anchor "` + pfAnchorName + `" from "` + pfAnchorFile + "\"\n")
			sawLoad = true
		}
	}
	if !sawRdr || !sawLoad {
		return fmt.Errorf("unexpected /etc/pf.conf (missing com.apple anchor markers); not modifying — install manually")
	}
	tmp := pfConfFile + ".masqr-tmp"
	if err := os.WriteFile(tmp, []byte(b.String()), 0o644); err != nil {
		return err
	}
	defer os.Remove(tmp)
	if out, err := exec.Command("pfctl", "-nf", tmp).CombinedOutput(); err != nil {
		return fmt.Errorf("pf.conf validation failed: %v: %s", err, strings.TrimSpace(string(out)))
	}
	return os.WriteFile(pfConfFile, []byte(b.String()), 0o644)
}

// stripLines rewrites path without any line containing marker.
func stripLines(path, marker string) {
	b, err := os.ReadFile(path)
	if err != nil {
		return
	}
	var out strings.Builder
	for _, line := range strings.Split(string(b), "\n") {
		if strings.Contains(line, marker) {
			continue
		}
		out.WriteString(line)
		out.WriteByte('\n')
	}
	_ = os.WriteFile(path, []byte(strings.TrimRight(out.String(), "\n")+"\n"), 0o644)
}
