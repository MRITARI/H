package main

import "strings"

// Rule-based hints for well-known disposable locations, shown in the tree.
// Paths are lower-cased and normalised to forward slashes before matching, so
// one table serves both Windows and Linux.
var junkRules = []struct{ frag, label string }{
	// Windows
	{"/appdata/local/temp/", "temp"},
	{"/windows/temp/", "temp"},
	{"/windows/softwaredistribution/download/", "update cache"},
	{"/windows/minidump/", "crash dumps"},
	{"/crashdumps/", "crash dumps"},
	{"/$recycle.bin/", "recycle bin"},
	{"/microsoft/windows/inetcache/", "browser cache"},
	{"/windows/logs/", "logs"},
	{"/windows/installer/$patchcache$/", "patch cache"},
	// Linux
	{"/.cache/", "user cache"},
	{"/.local/share/trash/", "trash"},
	{"/var/cache/apt/archives/", "package cache"},
	{"/var/cache/pacman/pkg/", "package cache"},
	{"/var/cache/dnf/", "package cache"},
	{"/var/cache/zypp/", "package cache"},
	{"/var/lib/systemd/coredump/", "crash dumps"},
	{"/var/crash/", "crash dumps"},
	{"/var/tmp/", "temp"},
	{"/tmp/", "temp"},
	{"/var/log/journal/", "journal logs (journalctl --vacuum-size trims them)"},
	{"/.npm/_cacache/", "npm cache"},
	{"/.cargo/registry/cache/", "re-downloadable"},
	{"/.gradle/caches/", "gradle cache"},
	// both
	{"/code cache/", "cache"},
	{"/gpucache/", "cache"},
	{"/cache2/", "cache"},
	{"/npm-cache/", "npm cache"},
	{"/pip/cache/", "pip cache"},
	{"/.nuget/packages/", "re-downloadable"},
	{"/node_modules/", "rebuildable"},
	{"/__pycache__/", "rebuildable"},
}

var neverRules = []struct{ frag, label string }{
	// Windows
	{"/windows/system32/", "OS core"},
	{"/windows/winsxs/", "OS store (use DISM)"},
	{"/program files/", "installed apps"},
	{"/program files (x86)/", "installed apps"},
	{"/programdata/microsoft/", "OS data"},
	// Linux
	{"/usr/", "installed system software"},
	{"/lib/", "system libraries"},
	{"/lib64/", "system libraries"},
	{"/bin/", "system programs"},
	{"/sbin/", "system programs"},
	{"/boot/", "boot files"},
	{"/etc/", "system configuration"},
	{"/var/lib/dpkg/", "package database"},
	{"/var/lib/pacman/", "package database"},
	{"/var/lib/rpm/", "package database"},
	{"/var/lib/flatpak/", "installed apps (use flatpak)"},
	{"/var/lib/snapd/", "installed apps (use snap)"},
	{"/snap/", "installed apps (use snap)"},
}

// anchored rules only match at the start of the path (Linux system directories).
func anchored(frag string) bool {
	for _, pre := range []string{"/usr/", "/lib", "/bin/", "/sbin/", "/boot/", "/etc/", "/var/", "/snap/", "/tmp/"} {
		if strings.HasPrefix(frag, pre) {
			return true
		}
	}
	return false
}

func matches(p, frag string) bool {
	if anchored(frag) {
		return strings.HasPrefix(p, frag)
	}
	return strings.Contains(p, frag)
}

func classify(path string) (kind, label string) {
	p := strings.ToLower(strings.ReplaceAll(path, `\`, "/"))
	if !strings.HasSuffix(p, "/") {
		p += "/"
	}
	for _, r := range junkRules {
		if matches(p, r.frag) {
			return "junk", r.label
		}
	}
	for _, r := range neverRules {
		if matches(p, r.frag) {
			return "keep", r.label
		}
	}
	return "", ""
}

// verdictFor is the authoritative SAFE/CAUTION/KEEP decision. It is rule-based
// on purpose: only known locations and file types are ever called SAFE.
// Anything unrecognised is UNSURE (never SAFE).
func verdictFor(n *Node) (verdict, reason string) {
	if n.Pseudo {
		return "UNSURE", "many small files grouped together; open the folder to see them"
	}
	if k, l := classify(n.Path); k == "junk" {
		return "SAFE", l + " - regenerated automatically"
	} else if k == "keep" {
		return "KEEP", l + " - deleting can break the system or apps"
	}
	name := strings.ToLower(n.Name)
	switch name {
	case "pagefile.sys", "hiberfil.sys", "swapfile.sys":
		return "KEEP", "managed by Windows (shrink via System settings or powercfg, never delete)"
	case "swapfile", "swap.img", "vmlinuz", "initrd.img":
		return "KEEP", "swap or boot file managed by the system (resize swap properly, never just delete)"
	}
	if n.IsDir {
		return "UNSURE", "not recognised - open it and check before deleting"
	}
	ext := extOf(n.Name)
	switch ext {
	case ".tmp", ".dmp", ".etl", ".log", ".chk":
		return "SAFE", "temporary / log / crash data"
	case ".iso", ".img":
		return "CAUTION", "disk image - usually re-downloadable; delete if you no longer need it"
	case ".msi", ".exe":
		return "CAUTION", "installer or program - fine to delete if already installed and re-downloadable"
	case ".zip", ".7z", ".rar", ".tar", ".gz":
		return "CAUTION", "archive - delete only if you have the extracted contents or no longer need it"
	case ".vhd", ".vhdx", ".vmdk", ".vdi":
		return "CAUTION", "virtual machine disk - may hold a whole VM"
	case ".mp4", ".mkv", ".mov", ".avi", ".mp3", ".flac", ".jpg", ".jpeg", ".png", ".heic", ".raw":
		return "CAUTION", "personal media - make sure it is backed up"
	case ".doc", ".docx", ".xls", ".xlsx", ".pdf", ".pptx", ".txt", ".odt":
		return "CAUTION", "personal document"
	case ".bin":
		return "UNSURE", "binary data of unknown purpose"
	case ".sys", ".dll", ".so", ".ko":
		return "KEEP", "system/driver/library file"
	case ".deb", ".rpm", ".appimage", ".pkg", ".run":
		return "CAUTION", "installer or program - fine to delete if already installed and re-downloadable"
	}
	return "UNSURE", "unrecognised file type"
}
