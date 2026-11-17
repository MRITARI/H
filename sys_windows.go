package main

import (
	"bytes"
	"context"
	"fmt"
	"os"
	"os/exec"
	"regexp"
	"strings"
	"syscall"
	"time"

	tea "github.com/charmbracelet/bubbletea"
	"golang.org/x/sys/windows"
	"golang.org/x/sys/windows/registry"
)

const adminWord = "administrator"

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
			out = append(out, drive{Root: root, Free: free, Total: total})
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

// psLines runs a PowerShell snippet and returns its non-empty output lines.
func psLines(script string) ([]string, error) {
	out, err := ps(script)
	return lines(out), err
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

// elevate restarts H with administrator rights; the elevated copy opens in a new window.
func elevate() (tea.Cmd, error) {
	if err := relaunchAsAdmin(); err != nil {
		return nil, err
	}
	return tea.Quit, nil
}

func sysDriveRoot() string {
	d := os.Getenv("SystemDrive")
	if d == "" {
		d = "C:"
	}
	return d + `\`
}
