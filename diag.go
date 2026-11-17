package main

import (
	"fmt"
	"strings"

	tea "github.com/charmbracelet/bubbletea"
	"github.com/charmbracelet/lipgloss"
)

type (
	checkDoneMsg struct {
		gen, idx int
		c        Check
	}
	fixDoneMsg struct {
		id  string
		out string
		err error
	}
)

type diagState int

const (
	dsBrowse diagState = iota
	dsConfirm
	dsFixing
)

const diagInspectorH = 8

var probeSem = make(chan struct{}, 6)

type diagModel struct {
	build  func() tool // rebuilt on rescan so cached probes are fresh
	t      tool
	gen    int
	res    []*Check
	cursor int
	offset int
	w, h   int
	tick   int
	st     diagState
	status string
}

func newDiag(build func() tool) *diagModel {
	d := &diagModel{build: build}
	d.reset()
	return d
}

func (d *diagModel) reset() {
	d.t = d.build()
	d.gen++
	d.res = make([]*Check, len(d.t.Defs))
	d.cursor, d.offset, d.st, d.status = 0, 0, dsBrowse, ""
}

func (d *diagModel) Init() tea.Cmd {
	var cmds []tea.Cmd
	for i, def := range d.t.Defs {
		i, def, gen := i, def, d.gen
		cmds = append(cmds, func() (msg tea.Msg) {
			probeSem <- struct{}{} // limit concurrent probes (each may start a helper process)
			defer func() { <-probeSem }()
			defer func() { // a crashing probe must not take the whole app down
				if r := recover(); r != nil {
					msg = checkDoneMsg{gen, i, info(def.Name, fmt.Sprint("check failed: ", r))}
				}
			}()
			return checkDoneMsg{gen, i, def.Run()}
		})
	}
	return tea.Batch(cmds...)
}

func (d *diagModel) pending() int {
	n := 0
	for _, r := range d.res {
		if r == nil {
			n++
		}
	}
	return n
}

func (d *diagModel) selected() *Check {
	if d.cursor < 0 || d.cursor >= len(d.res) {
		return nil
	}
	return d.res[d.cursor]
}

func (d *diagModel) Update(msg tea.Msg) (tea.Model, tea.Cmd) {
	switch msg := msg.(type) {
	case tea.WindowSizeMsg:
		d.w, d.h = msg.Width, msg.Height
		d.clamp()
	case tickMsg:
		d.tick++
	case checkDoneMsg:
		if msg.gen == d.gen && msg.idx < len(d.res) {
			c := msg.c
			d.res[msg.idx] = &c
		}
	case fixDoneMsg:
		d.st = dsBrowse
		out := firstLines(msg.out, 3)
		if msg.err != nil {
			d.status = "Fix failed: " + msg.err.Error()
			if out != "" {
				d.status += " | " + out
			}
		} else {
			d.status = "Done. " + out + "  Press r to re-run the checks."
		}
	case tea.KeyMsg:
		return d.onKey(msg)
	}
	return d, nil
}

func firstLines(s string, n int) string {
	l := lines(s)
	if len(l) > n {
		l = l[:n]
	}
	return strings.Join(l, " / ")
}

func (d *diagModel) onKey(k tea.KeyMsg) (tea.Model, tea.Cmd) {
	s := k.String()
	if s == "ctrl+c" {
		return d, tea.Quit
	}
	switch d.st {
	case dsConfirm:
		if s == "y" {
			c := d.selected()
			d.st, d.status = dsFixing, "Running fix..."
			id := c.Fix
			return d, func() tea.Msg {
				out, err := runFix(id)
				return fixDoneMsg{id, out, err}
			}
		}
		d.st, d.status = dsBrowse, "Cancelled"
		return d, nil
	case dsFixing:
		return d, nil
	}
	switch s {
	case "q", "esc":
		return d, func() tea.Msg { return backMsg{} }
	case "up", "k":
		d.cursor--
	case "down", "j":
		d.cursor++
	case "pgup":
		d.cursor -= d.rows()
	case "pgdown":
		d.cursor += d.rows()
	case "home", "g":
		d.cursor = 0
	case "end", "G":
		d.cursor = len(d.res) - 1
	case "r":
		d.reset()
		return d, d.Init()
	case "f", "enter":
		c := d.selected()
		switch {
		case c == nil:
		case c.Fix == "":
			d.status = "No automatic fix for this item - see the explanation below"
		default:
			f := fixes[c.Fix]
			if f.Admin && !isAdmin() {
				d.status = "This fix needs " + adminWord + " rights: go back to the main menu and press a to restart as " + adminWord
			} else {
				d.st, d.status = dsConfirm, ""
			}
		}
	}
	d.clamp()
	return d, nil
}

func (d *diagModel) listH() int { return d.h - 3 - diagInspectorH - 1 }
func (d *diagModel) rows() int  { return max(1, d.listH()-2) }

func (d *diagModel) clamp() {
	if d.cursor >= len(d.res) {
		d.cursor = len(d.res) - 1
	}
	if d.cursor < 0 {
		d.cursor = 0
	}
	rows := d.rows()
	if d.cursor < d.offset {
		d.offset = d.cursor
	}
	if d.cursor >= d.offset+rows {
		d.offset = d.cursor - rows + 1
	}
	if d.offset < 0 {
		d.offset = 0
	}
}

var spinFrames = []string{"⠋", "⠙", "⠹", "⠸", "⠼", "⠴", "⠦", "⠧", "⠇", "⠏"}

func statusColor(s string) lipgloss.Color {
	switch s {
	case "PASS":
		return cGreen
	case "WARN":
		return cYellow
	case "FAIL":
		return cRed
	}
	return cGray
}

func (d *diagModel) View() string {
	if d.w == 0 {
		return "starting…"
	}
	if d.w < 70 || d.h < 18 {
		return "Terminal too small - enlarge the window (min 70x18)."
	}
	return d.header() + "\n" + d.list() + "\n" + d.inspector() + "\n" + d.footer()
}

// header: title, progress and a rule-based summary of what to look at first.
func (d *diagModel) header() string {
	var fails, warns int
	var first *Check
	for _, r := range d.res {
		if r == nil {
			continue
		}
		switch r.Status {
		case "FAIL":
			fails++
			if first == nil || first.Status != "FAIL" {
				first = r
			}
		case "WARN":
			warns++
			if first == nil {
				first = r
			}
		}
	}
	l1 := sTitle.Render(" "+d.t.Title+" ") + sDim.Render(d.t.Blurb)
	if p := d.pending(); p > 0 {
		l1 += "  " + lipgloss.NewStyle().Foreground(cYellow).Render(fmt.Sprintf("%s checking… %d left", spinFrames[d.tick%len(spinFrames)], p))
	}
	var l2 string
	switch {
	case d.pending() == len(d.res):
		l2 = sDim.Render(" running checks…")
	case first != nil:
		col := cYellow
		if fails > 0 {
			col = cRed
		}
		l2 = lipgloss.NewStyle().Foreground(col).Bold(true).Render(fmt.Sprintf(" %d failed, %d warning(s)", fails, warns)) +
			sDim.Render("  start with: ") + first.Name
	case d.pending() == 0:
		l2 = lipgloss.NewStyle().Foreground(cGreen).Bold(true).Render(" All checks look fine")
	default:
		l2 = sDim.Render(" no problems found so far")
	}
	return fit(l1, d.w) + "\n" + lipgloss.NewStyle().MaxWidth(d.w).Render(l2)
}

func (d *diagModel) list() string {
	inner := d.w - 2
	var rows []string
	for i := d.offset; i < len(d.res) && i < d.offset+d.rows(); i++ {
		rows = append(rows, d.row(i, inner))
	}
	return panel(strings.Join(rows, "\n"), d.w, d.listH(), true)
}

func (d *diagModel) row(i, w int) string {
	r := d.res[i]
	sel := i == d.cursor
	if r == nil {
		txt := fit(fmt.Sprintf(" %s  %s", spinFrames[(d.tick+i)%len(spinFrames)], d.t.Defs[i].Name), w)
		if sel {
			return sSel.Render(txt)
		}
		return sDim.Render(txt)
	}
	fixMark := " "
	if r.Fix != "" && (r.Status == "WARN" || r.Status == "FAIL" || strings.HasPrefix(d.t.Title, "Quick fixes")) {
		fixMark = "⚑"
	}
	tag := fmt.Sprintf(" [%-4s] ", r.Status)
	name := fmt.Sprintf("%-28s", fit0(r.Name, 28))
	rest := fit0(r.Detail, max(0, w-len(tag)-30))
	if sel {
		return sSel.Render(fit(tag+name+" "+rest, w-2) + " " + fixMark)
	}
	line := lipgloss.NewStyle().Foreground(statusColor(r.Status)).Render(tag) + name + " " + sDim.Render(rest)
	pad := w - 2 - lipgloss.Width(line)
	if pad < 0 {
		pad = 0
	}
	return line + strings.Repeat(" ", pad) + " " + lipgloss.NewStyle().Foreground(cAccent).Render(fixMark)
}

func (d *diagModel) inspector() string {
	inner := d.w - 4
	c := d.selected()
	if c == nil {
		return panel(sDim.Render("waiting for this check…"), d.w, diagInspectorH, false)
	}
	badge := lipgloss.NewStyle().Foreground(statusColor(c.Status)).Bold(true).Render(c.Status)
	wrap := lipgloss.NewStyle().Width(inner)
	rows := []string{sBold.Render(c.Name) + "  " + badge, wrap.Render(c.Detail)}
	if c.Hint != "" {
		rows = append(rows, wrap.Render("What it means: "+c.Hint))
	}
	if c.Fix != "" {
		f := fixes[c.Fix]
		adm := ""
		if f.Admin {
			adm = " [admin]"
		}
		rows = append(rows, lipgloss.NewStyle().Foreground(cAccent).Render("Fix: "+f.Desc+adm+" ["+f.Risk+"]  (press f)"))
	}
	return panel(strings.Join(rows, "\n"), d.w, diagInspectorH, false)
}

func (d *diagModel) footer() string {
	if d.st == dsConfirm {
		f := fixes[d.selected().Fix]
		return lipgloss.NewStyle().Foreground(cRed).Bold(true).MaxWidth(d.w).Render(
			fmt.Sprintf(" Run: %s ?  [%s]  [y] yes   [any other key] cancel", f.Desc, f.Risk))
	}
	if d.status != "" {
		return lipgloss.NewStyle().Foreground(cGreen).MaxWidth(d.w).Render(" " + d.status)
	}
	return sDim.Render(fit(" ↑↓ move · f run suggested fix · r re-run checks · q back to menu", d.w))
}
