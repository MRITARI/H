package main

import (
	"flag"
	"fmt"
	"os"
	"path/filepath"

	tea "github.com/charmbracelet/bubbletea"
)

func main() {
	flag.Usage = func() {
		fmt.Fprintln(os.Stderr, "usage: H [folder-for-the-disk-scanner]   (default: system drive)")
		flag.PrintDefaults()
	}
	flag.Parse()

	root := os.Getenv("SystemDrive") + `\`
	if root == `\` {
		root = `C:\`
	}
	if flag.NArg() > 0 {
		abs, err := filepath.Abs(flag.Arg(0))
		if err != nil {
			fmt.Fprintln(os.Stderr, err)
			os.Exit(1)
		}
		root = abs
	}
	if st, err := os.Stat(root); err != nil || !st.IsDir() {
		fmt.Fprintf(os.Stderr, "not a directory: %s\n", root)
		os.Exit(1)
	}

	if _, err := tea.NewProgram(newApp(root), tea.WithAltScreen()).Run(); err != nil {
		fmt.Fprintln(os.Stderr, "error:", err)
		os.Exit(1)
	}
}
