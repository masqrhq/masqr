//go:build !windows

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
	"io"
	"os"
	"os/exec"
	"os/signal"
	"syscall"

	"github.com/creack/pty"
	"golang.org/x/term"
)

// runInteractive runs the child under a PTY so it sees a real terminal, mirrors
// terminal resizes via SIGWINCH, and puts our stdin into raw mode so keystrokes
// pass through untranslated. Restores terminal state on exit.
func runInteractive(cmd *exec.Cmd, path string) error {
	ptmx, err := pty.Start(cmd)
	if err != nil {
		return fmt.Errorf("start %s: %w", path, err)
	}
	defer func() { _ = ptmx.Close() }()

	resizeCh := make(chan os.Signal, 1)
	signal.Notify(resizeCh, syscall.SIGWINCH)
	defer signal.Stop(resizeCh)
	go func() {
		for range resizeCh {
			_ = pty.InheritSize(os.Stdin, ptmx)
		}
	}()
	resizeCh <- syscall.SIGWINCH

	oldState, err := term.MakeRaw(int(os.Stdin.Fd()))
	if err != nil {
		return fmt.Errorf("raw stdin: %w", err)
	}
	defer func() { _ = term.Restore(int(os.Stdin.Fd()), oldState) }()

	go func() { _, _ = io.Copy(ptmx, os.Stdin) }()
	_, _ = io.Copy(os.Stdout, ptmx)

	return cmd.Wait()
}
