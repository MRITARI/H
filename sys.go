package main

import (
	"context"
	"io/fs"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"time"
)

// Platform-neutral helpers. Everything OS specific lives in *_windows.go / *_linux.go.

// run executes a program hidden and returns stdout+stderr (used by fixes).
func run(timeout time.Duration, name string, args ...string) (string, error) {
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()
	cmd := exec.CommandContext(ctx, name, args...)
	hiddenProc(cmd)
	out, err := cmd.CombinedOutput()
	return strings.TrimSpace(string(out)), err
}

// lazy runs an expensive probe once and shares the result between checks.
type lazy struct {
	once sync.Once
	f    func() (string, error)
	v    string
	err  error
}

func (l *lazy) get() (string, error) {
	l.once.Do(func() { l.v, l.err = l.f() })
	return l.v, l.err
}

func lines(s string) []string {
	var out []string
	for _, l := range strings.Split(s, "\n") {
		if l = strings.TrimSpace(l); l != "" {
			out = append(out, l)
		}
	}
	return out
}

func atoi(s string) int {
	n, _ := strconv.Atoi(strings.TrimSpace(s))
	return n
}

type drive struct {
	Root        string
	Free, Total uint64
	Inodes      uint64 // Linux only: total and free inodes (0 when unknown)
	InodesFree  uint64
}

// dirSize adds up file sizes under root for at most budget; complete is false if it ran out of time.
func dirSize(root string, budget time.Duration) (total int64, complete bool) {
	deadline := time.Now().Add(budget)
	complete = true
	_ = filepath.WalkDir(root, func(p string, d fs.DirEntry, err error) error {
		if time.Now().After(deadline) {
			complete = false
			return filepath.SkipAll
		}
		if err != nil || d.IsDir() {
			return nil
		}
		if info, e := d.Info(); e == nil {
			total += info.Size()
		}
		return nil
	})
	return
}

// adminOnly returns a ready-made INFO row when a probe needs elevation, or nil when it can run.
func adminOnly(name string) *Check {
	if isAdmin() {
		return nil
	}
	c := info(name, "needs "+adminWord+" rights to check (press a on the main menu)")
	return &c
}
