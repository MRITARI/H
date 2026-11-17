package main

import (
	"fmt"
	"strings"

	tea "github.com/charmbracelet/bubbletea"
	"github.com/charmbracelet/lipgloss"
)

type screen int

const (
	scMenu screen = iota
	scDisk
	scDiag
	scFixCats
)

type menuItem struct {
	Title, Blurb string
	Disk         bool
	Cats         bool // opens the quick-fix category list
	Build        func() tool
}

var menuItems = []menuItem{
	{Title: "Disk scanner", Blurb: "dirscope: what is using my disk space? safe-to-delete hints", Disk: true},
	{Title: "Network diagnostics", Blurb: "no internet, slow Wi-Fi, DNS problems", Build: netTool},
	{Title: "PC troubleshooter", Blurb: "general health: CPU, memory, disks, crashes, errors", Build: pcTool},
	{Title: "Performance check", Blurb: "why is my PC slow? startup, temp files, load", Build: perfTool},
	{Title: "Windows Update & services", Blurb: "updates failing, stuck or services stopped", Build: updateTool},
	{Title: "Security check", Blurb: "Defender, firewall, UAC, BitLocker, risky settings", Build: securityTool},
	{Title: "Hardware & battery", Blurb: "battery wear, drive health, drivers, BIOS, temperature", Build: hardwareTool},
	{Title: "Printing & peripherals", Blurb: "printers, stuck print jobs, audio, Bluetooth, camera", Build: peripheralsTool},
	{Title: "Quick fixes", Blurb: "common repairs in categories - each asks before running", Cats: true},
}

// app is the top-level model: a menu that opens one screen at a time.
type app struct {
	w, h     int
	tick     int
	cursor   int
	catCur   int
	sc       screen
	fromCats bool // the open diag screen came from the quick-fix category list
	disk     *model
	diag     *diagModel
	scanPath string
	admin    bool
	note     string
}

func newApp(scanPath string) *app { return &app{scanPath: scanPath, admin: isAdmin()} }

func (a *app) Init() tea.Cmd { return tickCmd() }

func (a *app) openDiag(build func() tool, fromCats bool) tea.Cmd {
	a.diag = newDiag(build)
	a.diag.w, a.diag.h = a.w, a.h
	a.sc, a.fromCats = scDiag, fromCats
	return a.diag.Init()
}

func (a *app) openFixCat(i int) tea.Cmd {
	name := fixCats[i].Name
	return a.openDiag(func() tool { return fixesTool(name) }, true)
}

func (a *app) open(i int) tea.Cmd {
	it := menuItems[i]
	switch {
	case it.Disk:
		a.disk = newModel(a.scanPath)
		a.disk.w, a.disk.h = a.w, a.h
		a.sc = scDisk
		return a.disk.Init()
	case it.Cats:
		a.sc, a.catCur = scFixCats, 0
		return nil
	}
	return a.openDiag(it.Build, false)
}

func (a *app) Update(msg tea.Msg) (tea.Model, tea.Cmd) {
	switch msg := msg.(type) {
	case tea.WindowSizeMsg:
		a.w, a.h = msg.Width, msg.Height
		if a.diag != nil {
			a.diag.Update(msg)
		}
		if a.disk != nil {
			a.disk.Update(msg)
		}
	case tickMsg:
		a.tick++
		if a.disk != nil {
			a.disk.Update(msg)
		}
		if a.diag != nil {
			a.diag.Update(msg)
		}
		return a, tickCmd()
	case backMsg:
		a.disk, a.diag = nil, nil
		if a.sc == scDiag && a.fromCats {
			a.sc = scFixCats
		} else {
			a.sc = scMenu
		}
		return a, nil
	case tea.KeyMsg:
		switch a.sc {
		case scDisk:
			_, cmd := a.disk.Update(msg)
			return a, cmd
		case scDiag:
			_, cmd := a.diag.Update(msg)
			return a, cmd
		case scFixCats:
			return a.catKey(msg)
		}
		return a.menuKey(msg)
	}
	// everything else (scan results, check results, fix results) goes to the open screen
	var cmds []tea.Cmd
	if a.disk != nil {
		_, c := a.disk.Update(msg)
		cmds = append(cmds, c)
	}
	if a.diag != nil {
		_, c := a.diag.Update(msg)
		cmds = append(cmds, c)
	}
	return a, tea.Batch(cmds...)
}

// moveCursor handles the keys shared by both list menus.
func moveCursor(s string, cur, n int) int {
	switch s {
	case "up", "k":
		return (cur + n - 1) % n
	case "down", "j":
		return (cur + 1) % n
	}
	return cur
}

func (a *app) menuKey(k tea.KeyMsg) (tea.Model, tea.Cmd) {
	s := k.String()
	a.note = ""
	switch s {
	case "ctrl+c", "q", "esc":
		return a, tea.Quit
	case "up", "k", "down", "j":
		a.cursor = moveCursor(s, a.cursor, len(menuItems))
	case "enter", "right", "l":
		return a, a.open(a.cursor)
	case "a":
		if a.admin {
			a.note = "Already running as administrator."
		} else if err := relaunchAsAdmin(); err != nil {
			a.note = "Could not restart as administrator: " + err.Error()
		} else {
			return a, tea.Quit // the elevated copy opens in a new window
		}
	default:
		if len(s) == 1 && s[0] >= '1' && s[0] <= '9' {
			if i := int(s[0] - '1'); i < len(menuItems) {
				a.cursor = i
				return a, a.open(i)
			}
		}
	}
	return a, nil
}

func (a *app) catKey(k tea.KeyMsg) (tea.Model, tea.Cmd) {
	s := k.String()
	switch s {
	case "ctrl+c":
		return a, tea.Quit
	case "q", "esc", "left", "h", "backspace":
		a.sc = scMenu
	case "up", "k", "down", "j":
		a.catCur = moveCursor(s, a.catCur, len(fixCats))
	case "enter", "right", "l":
		return a, a.openFixCat(a.catCur)
	default:
		if len(s) == 1 && s[0] >= '1' && s[0] <= '9' {
			if i := int(s[0] - '1'); i < len(fixCats) {
				a.catCur = i
				return a, a.openFixCat(i)
			}
		}
	}
	return a, nil
}

func (a *app) View() string {
	if a.w == 0 {
		return "starting…"
	}
	switch a.sc {
	case scDisk:
		return a.disk.View()
	case scDiag:
		return a.diag.View()
	case scFixCats:
		return a.catView()
	}
	return a.menuView()
}

type listRow struct{ Title, Blurb string }

// renderList draws a titled, numbered list menu with a highlighted cursor.
func (a *app) renderList(head []string, rows []listRow, cursor int, help string) string {
	if a.w < 60 || a.h < 16 {
		return "Terminal too small - enlarge the window (min 60x16)."
	}
	inner := a.w - 4
	var out []string
	out = append(out, head...)
	out = append(out, "")
	for i, r := range rows {
		prefix := fmt.Sprintf(" %d  ", i+1)
		title := fit(r.Title, 26)
		blurb := fit0(r.Blurb, max(0, inner-len(prefix)-27))
		if i == cursor {
			out = append(out, sSel.Render(fit(prefix+title+" "+blurb, inner)))
		} else {
			out = append(out, prefix+sBold.Render(title)+" "+sDim.Render(blurb))
		}
	}
	box := panel(strings.Join(out, "\n"), a.w, len(out)+2, true)
	return box + "\n" + sDim.Render(fit(help, a.w))
}

func (a *app) menuView() string {
	who := sDim.Render("standard user - admin repairs are refused; press a to restart as administrator")
	if a.admin {
		who = lipgloss.NewStyle().Foreground(cGreen).Render("administrator - all fixes available")
	}
	if a.note != "" {
		who = lipgloss.NewStyle().Foreground(cYellow).Render(a.note)
	}
	rows := make([]listRow, len(menuItems))
	for i, it := range menuItems {
		rows[i] = listRow{it.Title, it.Blurb}
	}
	head := []string{sTitle.Render("H"), who}
	return a.renderList(head, rows, a.cursor, " ↑↓ move · enter open · 1-9 jump · a run as administrator · q quit")
}

func (a *app) catView() string {
	rows := make([]listRow, len(fixCats))
	for i, c := range fixCats {
		rows[i] = listRow{c.Name, fmt.Sprintf("%d fixes - %s", len(c.IDs), c.Blurb)}
	}
	head := []string{sTitle.Render("Quick fixes"), sDim.Render("pick a category; every fix asks for confirmation first")}
	return a.renderList(head, rows, a.catCur, " ↑↓ move · enter open · 1-9 jump · q back")
}
