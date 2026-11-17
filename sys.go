package main

import (
	"bytes"
	"context"
	"fmt"
	"io/fs"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"

	"golang.org/x/sys/windows"
	"golang.org/x/sys/windows/registry"
)

// ---------- running commands ----------

// run executes a program hidden and returns stdout+stderr (used by fixes).
func run(timeout time.Duration, name string, args ...string) (string, error) {
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()
	cmd := exec.CommandContext(ctx, name, args...)
	hiddenProc(cmd)
	out, err := cmd.CombinedOutput()
	return strings.TrimSpace(string(out)), err
}

// ps runs a PowerShell snippet and returns stdout only. -Command is not
// subject to the script execution policy, so this works on locked-down PCs.
func ps(script string) (string, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 40*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, "powershell.exe", "-NoProfile", "-NonInteractive", "-ExecutionPolicy", "Bypass", "-Command",
		"[Console]::OutputEncoding=[Text.Encoding]::UTF8;$ProgressPreference='SilentlyContinue';"+script)
	hiddenProc(cmd)
	var out bytes.Buffer
	cmd.Stdout = &out
	err := cmd.Run()
	return strings.TrimSpace(out.String()), err
}

// openConsole runs a long command in its own visible console window.
func openConsole(title, command string) error {
	cmd := exec.Command("cmd.exe")
	cmd.SysProcAttr = &syscall.SysProcAttr{CmdLine: fmt.Sprintf(`cmd.exe /c start "%s" cmd /k %s`, title, command)}
	return cmd.Start()
}

func isAdmin() bool { return windows.GetCurrentProcessToken().IsElevated() }

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

// ---------- native probes ----------

type drive struct {
	Root        string
	Free, Total uint64
}

func fixedDrives() []drive {
	mask, _ := windows.GetLogicalDrives()
	var out []drive
	for i := 0; i < 26; i++ {
		if mask&(1<<uint(i)) == 0 {
			continue
		}
		root := string(rune('A'+i)) + `:\`
		p, _ := windows.UTF16PtrFromString(root)
		if windows.GetDriveType(p) != windows.DRIVE_FIXED {
			continue
		}
		var avail, total, free uint64
		if windows.GetDiskFreeSpaceEx(p, &avail, &total, &free) == nil && total > 0 {
			out = append(out, drive{root, free, total})
		}
	}
	return out
}

func regKeyExists(root registry.Key, path string) bool {
	k, err := registry.OpenKey(root, path, registry.QUERY_VALUE)
	if err != nil {
		return false
	}
	k.Close()
	return true
}

func pendingReboot() []string {
	var why []string
	if regKeyExists(registry.LOCAL_MACHINE, `SOFTWARE\Microsoft\Windows\CurrentVersion\Component Based Servicing\RebootPending`) {
		why = append(why, "component servicing")
	}
	if regKeyExists(registry.LOCAL_MACHINE, `SOFTWARE\Microsoft\Windows\CurrentVersion\WindowsUpdate\Auto Update\RebootRequired`) {
		why = append(why, "Windows Update")
	}
	return why
}

var reMs = regexp.MustCompile(`(\d+)\s?ms`)

// pingHost uses ping.exe (works unelevated). Matching on "TTL=" and "NN ms" is locale independent.
func pingHost(host string) (ok bool, avgMs int) {
	out, _ := run(12*time.Second, "ping.exe", "-n", "2", "-w", "1500", host)
	if !strings.Contains(out, "TTL=") {
		return false, 0
	}
	if m := reMs.FindAllStringSubmatch(out, -1); len(m) > 0 {
		avgMs = atoi(m[len(m)-1][1])
	}
	return true, avgMs
}

// ---------- more helpers ----------

// psLines runs a PowerShell snippet and returns its non-empty output lines.
func psLines(script string) ([]string, error) {
	out, err := ps(script)
	return lines(out), err
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

// relaunchAsAdmin starts a new elevated copy of this program (UAC prompt).
func relaunchAsAdmin() error {
	exe, err := os.Executable()
	if err != nil {
		return err
	}
	verb, _ := windows.UTF16PtrFromString("runas")
	file, _ := windows.UTF16PtrFromString(exe)
	return windows.ShellExecute(0, verb, file, nil, nil, windows.SW_NORMAL)
}

// adminOnly returns a ready-made INFO row when a probe needs elevation, or nil when it can run.
func adminOnly(name string) *Check {
	if isAdmin() {
		return nil
	}
	c := info(name, "needs an administrator terminal to check (press a on the main menu)")
	return &c
}
