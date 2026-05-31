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
	"os/user"
	"runtime"
	"strconv"
	"syscall"

	"github.com/creack/pty"
	"golang.org/x/term"
)

// dropPrivilegesForChild makes the wrapped CLI run as the invoking user when
// masqr itself was started with sudo (the macOS :443 intercept needs root to
// bind the port, but agy's OAuth token + Keychain live in the user's HOME, not
// root's). Returns env extended with the user's HOME/USER/LOGNAME. No-op unless
// we're root on darwin via sudo.
func dropPrivilegesForChild(cmd *exec.Cmd, env []string) []string {
	if runtime.GOOS == "darwin" && os.Geteuid() == 0 {
		if su := os.Getenv("SUDO_UID"); su != "" {
			uid, _ := strconv.Atoi(su)
			gid, _ := strconv.Atoi(os.Getenv("SUDO_GID"))
			cmd.SysProcAttr = &syscall.SysProcAttr{Credential: &syscall.Credential{Uid: uint32(uid), Gid: uint32(gid)}}
			if u, uerr := user.LookupId(su); uerr == nil {
				env = append(env, "HOME="+u.HomeDir, "USER="+u.Username, "LOGNAME="+u.Username)
			}
		}
	}
	return env
}

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
