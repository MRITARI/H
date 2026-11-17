package main

import (
	"fmt"
	"net"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"syscall"
	"time"

	tea "github.com/charmbracelet/bubbletea"
)

// Linux platform layer: everything that needs a Linux-only API lives here.

const (
	adminWord = "root"
	trashName = "Trash"
	fileMgr   = "file manager"
)

func hiddenProc(*exec.Cmd) {}

func isAdmin() bool { return os.Geteuid() == 0 }

func defaultRoot() string { return "/" }

// fixedDrives lists mounted disk file systems (one entry per device) with free and total bytes.
func fixedDrives() []drive {
	seen := map[string]bool{}
	var out []drive
	for _, m := range parseMounts(readStr("/proc/mounts")) {
		if !realFS[m.FS] || seen[m.Dev] || strings.HasPrefix(m.Dir, "/snap") {
			continue
		}
		var st syscall.Statfs_t
		if syscall.Statfs(m.Dir, &st) != nil || st.Blocks == 0 {
			continue
		}
		seen[m.Dev] = true
		out = append(out, drive{Root: m.Dir, Free: uint64(st.Bavail) * uint64(st.Bsize), Total: uint64(st.Blocks) * uint64(st.Bsize),
			Inodes: uint64(st.Files), InodesFree: uint64(st.Ffree)})
	}
	return out
}

func pendingReboot() []string { return rebootReasons() }

// pingHost uses ping when installed (works unprivileged on modern kernels) and falls back to a TCP connect.
func pingHost(host string) (ok bool, avgMs int) {
	if haveCmd("ping") {
		out, _ := cmdOut(12*time.Second, "ping", "-c", "2", "-W", "2", host)
		if ok, ms := parsePingAvg(out); ok {
			return true, ms
		}
	}
	for _, port := range []string{"443", "53", "80"} {
		t := time.Now()
		if c, err := net.DialTimeout("tcp", net.JoinHostPort(host, port), 2*time.Second); err == nil {
			c.Close()
			return true, int(time.Since(t).Milliseconds())
		}
	}
	return false, 0
}

// elevate re-runs H under sudo in this terminal (password prompt included), then quits the unprivileged copy.
func elevate() (tea.Cmd, error) {
	exe, err := os.Executable()
	if err != nil {
		return nil, err
	}
	sudo, err := exec.LookPath("sudo")
	if err != nil {
		return nil, fmt.Errorf("sudo not found - start H again as root instead")
	}
	c := exec.Command(sudo, append([]string{exe}, os.Args[1:]...)...)
	return tea.ExecProcess(c, func(error) tea.Msg { return tea.QuitMsg{} }), nil
}

// devID identifies the file system of path so the disk scanner can stay on it.
func devID(path string) uint64 {
	var st syscall.Stat_t
	if syscall.Stat(path, &st) != nil {
		return 0
	}
	return uint64(st.Dev)
}

// pseudoDirs are never scanned: virtual file systems report meaningless sizes
// (/proc/kcore looks like 128 TB) and /mnt and /media hold other disks - scan those directly.
var pseudoDirs = map[string]bool{"/proc": true, "/sys": true, "/dev": true, "/run": true, "/mnt": true, "/media": true, "/lost+found": true}

func skipDir(path string, rootDev uint64) bool {
	return pseudoDirs[path]
}

// ---------- delete / reveal ----------

// recycle moves a path to the freedesktop.org Trash (undoable).
func recycle(path string) error {
	if haveCmd("gio") {
		if _, err := run(30*time.Second, "gio", "trash", path); err == nil {
			return nil
		}
	}
	if haveCmd("trash-put") {
		if _, err := run(30*time.Second, "trash-put", path); err == nil {
			return nil
		}
	}
	abs, err := filepath.Abs(path)
	if err != nil {
		return err
	}
	trash := filepath.Join(realHome(), ".local", "share", "Trash")
	if err := os.MkdirAll(filepath.Join(trash, "files"), 0o700); err != nil {
		return err
	}
	if err := os.MkdirAll(filepath.Join(trash, "info"), 0o700); err != nil {
		return err
	}
	name := filepath.Base(abs)
	if _, err := os.Lstat(filepath.Join(trash, "files", name)); err == nil {
		name = fmt.Sprintf("%s.%d", name, time.Now().UnixNano())
	}
	infoTxt := fmt.Sprintf("[Trash Info]\nPath=%s\nDeletionDate=%s\n", (&url.URL{Path: abs}).EscapedPath(), time.Now().Format("2006-01-02T15:04:05"))
	if err := os.Rename(abs, filepath.Join(trash, "files", name)); err != nil {
		return fmt.Errorf("cannot move to the Trash (other disk or no permission) - use p for permanent delete: %v", err)
	}
	_ = os.WriteFile(filepath.Join(trash, "info", name+".trashinfo"), []byte(infoTxt), 0o600)
	return nil
}

func permanentDelete(path string) error { return os.RemoveAll(path) }

// openInExplorer opens the folder that contains path in the desktop file manager (needs a desktop session).
func openInExplorer(path string) {
	dir := path
	if st, err := os.Stat(path); err != nil || !st.IsDir() {
		dir = filepath.Dir(path)
	}
	_ = exec.Command("xdg-open", dir).Start()
}
