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
	"errors"
	"fmt"
	"log"
	"net"
	"net/http"
	"net/url"
	"os"
	"os/exec"
	"os/signal"
	"path/filepath"
	"runtime"
	"strings"
	"syscall"
	"time"

	flag "github.com/spf13/pflag"
	"golang.org/x/sync/errgroup"
	"golang.org/x/term"
)

// version is the masqr release, stamped at build time via
// -ldflags="-X main.version=<tag>" (see .github/workflows/release.yml). It stays
// "dev" for local `go build`/`go install` so `masqr --version` is always answerable.
var version = "dev"

func main() {
	addr := flag.StringP("addr", "a", "127.0.0.1:0", "HTTP listen address (use :0 for random port)")
	envVars := flag.StringSliceP("env", "e", nil, "env var(s) to expose the proxy URL to the child (comma-separated or repeated; overrides provider profile)")
	target := flag.StringP("target", "t", "", "upstream API the proxy forwards to (overrides provider profile; also disables provider Routes)")
	logPath := flag.StringP("log", "l", "", "log file path (overrides the per-session default under the cache dir)")
	keywords := flag.StringP("keywords", "k", "", "path to a <keyword>|<TYPE> wordlist for the keyword scanner (overrides MASQR_KEYWORDS / auto-discovery)")
	blockOn := flag.String("block-on", "low", "severity threshold for triggering: critical|high|medium|low (default low → act on any finding)")
	onFinding := flag.String("on-finding", "block", "behavior on a triggering finding: block (return 451, never contact upstream) | redact (rewrite span with __LABEL_N__, restore in response)")
	shutdownGrace := flag.Duration("shutdown-grace", 5*time.Second, "HTTP graceful shutdown timeout")
	showVersion := flag.BoolP("version", "V", false, "print masqr version and exit")

	// Display friendly defaults in --help instead of the literal empty
	// strings — the real defaults come from provider auto-detection.
	flag.Lookup("env").DefValue = "from provider profile (e.g. ANTHROPIC_BASE_URL, GOOGLE_GEMINI_BASE_URL)"
	flag.Lookup("target").DefValue = "from provider profile (e.g. https://api.anthropic.com)"

	flag.Lookup("log").DefValue = "<user-cache-dir>/masqr/masqr-<YYYYMMDD-HHMMSS>.log"

	flag.CommandLine.SetInterspersed(false) // stop parsing at first positional, so child's flags pass through
	flag.Usage = func() {
		fmt.Fprintf(os.Stderr, "masqr %s (%s/%s) — deep prompt inspection for LLM CLIs\n\n", version, runtime.GOOS, runtime.GOARCH)
		fmt.Fprintf(os.Stderr, "usage: %s [flags] <command> [args...]\n\n", os.Args[0])
		fmt.Fprintf(os.Stderr, "examples: %s claude --resume\n", os.Args[0])
		fmt.Fprintf(os.Stderr, "          %s gemini -p 'summarize this'\n", os.Args[0])
		fmt.Fprintf(os.Stderr, "          %s -a :8080 -l /tmp/c.log claude\n\n", os.Args[0])
		fmt.Fprintln(os.Stderr, "flags:")
		flag.PrintDefaults()
		fmt.Fprintf(os.Stderr,
			"\nbuilt-in providers: %s\n"+
				"  detected automatically from the child command name (claude/gemini/codex/openai).\n"+
				"  --target / --env override the detected profile.\n",
			strings.Join(providerNames(), ", "))
	}
	flag.Parse()

	// --version takes no child command; answer and exit before arg checks.
	if *showVersion {
		fmt.Printf("masqr %s %s/%s\n", version, runtime.GOOS, runtime.GOARCH)
		return
	}

	args := flag.Args()
	if len(args) == 0 {
		flag.Usage()
		os.Exit(2)
	}

	if *keywords != "" {
		_ = os.Setenv("MASQR_KEYWORDS", *keywords)
	}

	threshold, err := ParseSeverity(*blockOn)
	if err != nil {
		log.Fatal(err)
	}

	findingMode, err := ParseOnFinding(*onFinding)
	if err != nil {
		log.Fatal(err)
	}

	// Auto-detect provider from the child command basename. Explicit
	// --target / --env always win — even if a matching profile exists, the
	// user's override is respected so corporate proxies / mock endpoints /
	// LiteLLM-style routers keep working. An explicit --target also
	// disables provider Routes (one user-specified host covers everything).
	provider, _ := LookupProvider(args[0])
	if flag.Lookup("target").Changed {
		provider.Target = *target
		provider.Routes = nil
	}
	if flag.Lookup("env").Changed {
		provider.EnvVars = *envVars
	}
	// Final fallbacks for the unrecognised-CLI case where no flags were
	// passed: keep the historical Anthropic defaults so a bare `masqr foo`
	// still has something to forward to.
	if provider.Target == "" {
		provider.Target = "https://api.anthropic.com"
	}
	if len(provider.EnvVars) == 0 && provider.Prepare == nil {
		provider.EnvVars = []string{"ANTHROPIC_BASE_URL"}
	}

	policy := Policy{Threshold: threshold, Provider: provider, OnFinding: findingMode}

	if err := run(args[0], args[1:], *addr, *logPath, *shutdownGrace, policy); err != nil {
		log.Fatal(err)
	}
}

// masqrCacheDir returns masqr's per-user cache root using the OS-native
// location from os.UserCacheDir():
//
//   - Linux:   $XDG_CACHE_HOME/masqr   (else ~/.cache/masqr)
//   - macOS:   ~/Library/Caches/masqr
//   - Windows: %LocalAppData%\masqr
//
// It returns "" when no cache dir is resolvable (rare: no $HOME / %LocalAppData%).
// Both the session log (defaultLogPath) and the bundled OCR runtime (cacheDir)
// hang off this root so they stay together on every platform.
func masqrCacheDir() string {
	base, err := os.UserCacheDir()
	if err != nil || base == "" {
		return ""
	}
	return filepath.Join(base, "masqr")
}

// defaultLogPath returns the per-session log path when -l is not given:
// <masqrCacheDir>/masqr-<YYYYMMDD-HHMMSS>.log, creating the directory on demand.
// If no cache dir is resolvable it falls back to the bare filename in the
// current directory.
func defaultLogPath() string {
	name := fmt.Sprintf("masqr-%s.log", time.Now().Format("20060102-150405"))
	dir := masqrCacheDir()
	if dir == "" {
		return name
	}
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return name
	}
	return filepath.Join(dir, name)
}

func run(cliPath string, cliArgs []string, addr, logPath string, grace time.Duration, policy Policy) error {
	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()

	if logPath == "" {
		logPath = defaultLogPath()
	}

	upstream, err := url.Parse(policy.Provider.Target)
	if err != nil {
		return fmt.Errorf("parse target %q: %w", policy.Provider.Target, err)
	}

	logFile, err := os.OpenFile(logPath, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0o644)
	if err != nil {
		return fmt.Errorf("open log %s: %w", logPath, err)
	}
	defer func() { _ = logFile.Close() }()

	// DEBUG=1 (or DEBUG=/path) opens a second, verbose trace log an agent can
	// read to verify scan coverage, what arrived, what was masked/blocked, and
	// the exact prompt the remote model received.
	closeDebug, err := setupDebugLog(logPath)
	if err != nil {
		return fmt.Errorf("open debug log: %w", err)
	}
	defer closeDebug()

	// Redirect the default logger so internal Printf calls (scanner sources,
	// OCR init) land in the per-session log file instead of stderr — otherwise
	// they bleed onto the banner.
	log.SetOutput(logFile)
	defer log.SetOutput(os.Stderr)
	logger := log.New(logFile, "", log.LstdFlags|log.Lmicroseconds)

	ln, err := net.Listen("tcp", addr)
	if err != nil {
		return fmt.Errorf("listen %s: %w", addr, err)
	}
	endpoint := "http://" + ln.Addr().String()
	printBanner(os.Stderr, endpoint, policy.Provider, logPath)

	srv := &http.Server{
		Handler:           newProxy(upstream, logger, policy, nil),
		ReadHeaderTimeout: 5 * time.Second,
	}

	g, ctx := errgroup.WithContext(ctx)

	g.Go(func() error {
		if err := srv.Serve(ln); err != nil && !errors.Is(err, http.ErrServerClosed) {
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
		extras := expandExtraArgs(policy.Provider.ExtraArgs, endpoint)
		// Inject ExtraArgs before the user's own args so they sit in the
		// `[OPTIONS]` slot every modern CLI uses, ahead of any subcommand
		// or positional prompt the user typed.
		mergedArgs := append(append([]string{}, extras...), cliArgs...)
		// Providers that can't be redirected by an env var (Mistral's vibe)
		// do their setup here and hand back extra env + a cleanup to run on
		// exit. extraEnv is appended after EnvVars so it takes precedence.
		var extraEnv []string
		if policy.Provider.Prepare != nil {
			pe, cleanup, perr := policy.Provider.Prepare(endpoint)
			if perr != nil {
				stop()
				return fmt.Errorf("%s setup: %w", policy.Provider.Name, perr)
			}
			defer cleanup()
			extraEnv = pe
		}
		err := runCLI(ctx, cliPath, mergedArgs, policy.Provider.EnvVars, endpoint, extraEnv)
		stop()
		return err
	})

	if err := g.Wait(); err != nil && !errors.Is(err, context.Canceled) {
		return err
	}
	return nil
}

// expandExtraArgs substitutes the `{{endpoint}}` placeholder in each
// provider-supplied flag with the actual masqr listener URL. Returns a
// fresh slice so the provider's template stays reusable across runs.
func expandExtraArgs(args []string, endpoint string) []string {
	if len(args) == 0 {
		return nil
	}
	out := make([]string, len(args))
	for i, a := range args {
		out[i] = strings.ReplaceAll(a, "{{endpoint}}", endpoint)
	}
	return out
}

func runCLI(ctx context.Context, path string, args, envVars []string, endpoint string, extraEnv []string) error {
	cmd := exec.CommandContext(ctx, path, args...)
	env := os.Environ()
	for _, v := range envVars {
		env = append(env, v+"="+endpoint)
	}
	// extraEnv carries literal KEY=VALUE pairs appended last so they take
	// precedence over any inherited value of the same key.
	env = append(env, extraEnv...)
	cmd.Env = env

	if !term.IsTerminal(int(os.Stdin.Fd())) {
		cmd.Stdin, cmd.Stdout, cmd.Stderr = os.Stdin, os.Stdout, os.Stderr
		return cmd.Run()
	}

	// Interactive path differs per OS: a PTY + SIGWINCH dance on Unix, plain
	// inherited stdio on Windows (no PTY support there).
	return runInteractive(cmd, path)
}
