package main

import (
	"fmt"
	"sort"
	"strings"
	"time"

	tea "github.com/charmbracelet/bubbletea"
	"github.com/charmbracelet/lipgloss"
)

type uiState int

const (
	stScanning uiState = iota
	stBrowse
	stConfirm
)

// messages
type (
	tickMsg       time.Time
	scanDoneMsg   struct{ root *Node }
	backMsg       struct{} // leave this screen, return to the menu
	deleteDoneMsg struct {
		done   []*Node
		failed int
		err    error
	}
)

var (
	cDim    = lipgloss.Color("244")
	cAccent = lipgloss.Color("39")
	cGreen  = lipgloss.Color("42")
	cYellow = lipgloss.Color("220")
	cRed    = lipgloss.Color("196")
	cCyan   = lipgloss.Color("51")
	cGray   = lipgloss.Color("246")

	sDir   = lipgloss.NewStyle().Foreground(lipgloss.Color("75")).Bold(true)
	sDim   = lipgloss.NewStyle().Foreground(cDim)
	sSel   = lipgloss.NewStyle().Reverse(true).Bold(true)
	sTitle = lipgloss.NewStyle().Bold(true).Foreground(cAccent)
	sBold  = lipgloss.NewStyle().Bold(true)
)

const inspectorH = 6

type model struct {
	rootPath string
	root     *Node
	cur      *Node
	cursor   int
	offset   int
	w, h     int
	st       uiState
	scanner  *Scanner
	tick     int
	status   string

	marked  map[*Node]bool
	targets []*Node

	extCache map[*Node]string
}

func newModel(root string) *model {
	return &model{rootPath: root, scanner: &Scanner{}, marked: map[*Node]bool{}, extCache: map[*Node]string{}}
}

// ---------- tea plumbing ----------

func tickCmd() tea.Cmd {
	return tea.Tick(120*time.Millisecond, func(t time.Time) tea.Msg { return tickMsg(t) })
}

func scanCmd(path string, s *Scanner) tea.Cmd {
	return func() tea.Msg { return scanDoneMsg{Scan(path, s)} }
}

func (m *model) Init() tea.Cmd { return scanCmd(m.rootPath, m.scanner) }

func (m *model) Update(msg tea.Msg) (tea.Model, tea.Cmd) {
	switch msg := msg.(type) {
	case tea.WindowSizeMsg:
		m.w, m.h = msg.Width, msg.Height
		if m.cur != nil {
			m.clamp()
		}
	case tickMsg:
		m.tick++
	case scanDoneMsg:
		m.root, m.cur, m.cursor, m.offset = msg.root, msg.root, 0, 0
		m.st = stBrowse
		m.status = fmt.Sprintf("Scanned %s in %s files", human(m.root.Size), commas(m.root.Files))
		return m, nil
	case deleteDoneMsg:
		m.st = stBrowse
		var freed int64
		for _, n := range msg.done {
			freed += n.Size
			n.Remove()
			delete(m.marked, n)
		}
		m.extCache = map[*Node]string{}
		m.status = fmt.Sprintf("Deleted %d item(s), freed %s", len(msg.done), human(freed))
		if msg.failed > 0 {
			m.status += fmt.Sprintf(" · %d failed: %v", msg.failed, msg.err)
		}
		m.clamp()
	case tea.KeyMsg:
		return m.onKey(msg)
	}
	return m, nil
}

func (m *model) onKey(k tea.KeyMsg) (tea.Model, tea.Cmd) {
	s := k.String()
	if s == "ctrl+c" {
		return m, tea.Quit
	}
	if m.st == stConfirm {
		switch s {
		case "y":
			return m, m.deleteCmd(m.targets, false)
		case "p":
			return m, m.deleteCmd(m.targets, true)
		default:
			m.st = stBrowse
			m.status = "Delete cancelled"
		}
		return m, nil
	}
	if s == "q" || s == "esc" {
		return m, func() tea.Msg { return backMsg{} }
	}
	if m.st != stBrowse {
		return m, nil
	}
	kids := m.cur.Children
	switch s {
	case "up", "k":
		m.cursor--
	case "down", "j":
		m.cursor++
	case "pgup":
		m.cursor -= m.treeRows()
	case "pgdown":
		m.cursor += m.treeRows()
	case "home", "g":
		m.cursor = 0
	case "end", "G":
		m.cursor = len(kids) - 1
	case "enter", "right", "l":
		if n := m.selected(); n != nil && n.IsDir && len(n.Children) > 0 {
			m.cur, m.cursor, m.offset = n, 0, 0
		}
	case "left", "h", "backspace":
		if m.cur.Parent != nil {
			prev := m.cur
			m.cur = m.cur.Parent
			m.cursor, m.offset = 0, 0
			for i, c := range m.cur.Children {
				if c == prev {
					m.cursor = i
				}
			}
		}
	case " ":
		if n := m.selected(); n != nil && !n.Pseudo {
			if m.marked[n] {
				delete(m.marked, n)
			} else {
				m.marked[n] = true
			}
			m.cursor++
		}
	case "c":
		cnt := 0
		for _, c := range kids {
			if v, _ := verdictFor(c); v == "SAFE" && !c.Pseudo {
				m.marked[c] = true
				cnt++
			}
		}
		if cnt == 0 {
			m.status = "Nothing in this folder is known-safe junk"
		} else {
			m.status = fmt.Sprintf("Marked %d safe item(s) - press d to delete them", cnt)
		}
	case "u":
		m.marked = map[*Node]bool{}
		m.status = "Marks cleared"
	case "d", "delete":
		m.startDelete()
	case "o":
		if n := m.selected(); n != nil && !n.Pseudo {
			openInExplorer(n.Path)
		}
	case "r":
		m.st, m.scanner = stScanning, &Scanner{}
		m.marked = map[*Node]bool{}
		m.extCache = map[*Node]string{}
		return m, scanCmd(m.rootPath, m.scanner)
	}
	m.clamp()
	return m, nil
}

func (m *model) startDelete() {
	targets := m.markedList()
	if len(targets) == 0 {
		if n := m.selected(); n != nil && !n.Pseudo {
			targets = []*Node{n}
		}
	}
	if len(targets) == 0 {
		m.status = "Nothing deletable selected"
		return
	}
	for _, t := range targets {
		if v, r := verdictFor(t); v == "KEEP" {
			m.status = fmt.Sprintf("Protected: %s is a KEEP item (%s)", t.Name, r)
			return
		}
	}
	m.targets, m.st = targets, stConfirm
}

// markedList returns marked nodes still in the tree, biggest first, without
// children whose ancestor is also marked.
func (m *model) markedList() []*Node {
	var out []*Node
	for n := range m.marked {
		skip := false
		for a := n.Parent; a != nil; a = a.Parent {
			if m.marked[a] {
				skip = true
				break
			}
		}
		if !skip {
			out = append(out, n)
		}
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Size > out[j].Size })
	return out
}

func (m *model) selected() *Node {
	if m.cur == nil || m.cursor < 0 || m.cursor >= len(m.cur.Children) {
		return nil
	}
	return m.cur.Children[m.cursor]
}

func (m *model) clamp() {
	n := len(m.cur.Children)
	if m.cursor >= n {
		m.cursor = n - 1
	}
	if m.cursor < 0 {
		m.cursor = 0
	}
	rows := m.treeRows()
	if m.cursor < m.offset {
		m.offset = m.cursor
	}
	if m.cursor >= m.offset+rows {
		m.offset = m.cursor - rows + 1
	}
	if m.offset < 0 {
		m.offset = 0
	}
}

func (m *model) deleteCmd(targets []*Node, permanent bool) tea.Cmd {
	m.status = "Deleting…"
	return func() tea.Msg {
		var res deleteDoneMsg
		for _, n := range targets {
			var err error
			if permanent {
				err = permanentDelete(n.Path)
			} else {
				err = recycle(n.Path)
			}
			if err != nil {
				res.failed++
				res.err = err
			} else {
				res.done = append(res.done, n)
			}
		}
		return res
	}
}

// ---------- view ----------

func (m *model) treeBoxH() int { return m.h - 1 - inspectorH - 1 }
func (m *model) treeRows() int { return max(1, m.treeBoxH()-2-1) }

func (m *model) View() string {
	if m.w == 0 {
		return "starting…"
	}
	if m.w < 70 || m.h < 18 {
		return "Terminal too small - enlarge the window (min 70x18)."
	}
	return m.header() + "\n" + m.treeView() + "\n" + m.inspector() + "\n" + m.footer()
}

func (m *model) header() string {
	left := sTitle.Render(" Dirscope ") + sDim.Render(m.rootPath)
	legend := ""
	if m.w >= 115 {
		legend = lipgloss.NewStyle().Foreground(cGreen).Render("● safe ") +
			lipgloss.NewStyle().Foreground(cYellow).Render("● caution ") +
			lipgloss.NewStyle().Foreground(cRed).Render("● keep ") +
			lipgloss.NewStyle().Foreground(cGray).Render("● unsure  ")
	}
	right := legend
	gap := m.w - lipgloss.Width(left) - lipgloss.Width(right)
	if gap < 1 {
		gap = 1
	}
	return left + strings.Repeat(" ", gap) + right
}

func (m *model) box(content string, h int, accent bool) string { return panel(content, m.w, h, accent) }

// panel draws a rounded box of exactly w x h cells.
func panel(content string, w, h int, accent bool) string {
	bc := cDim
	if accent {
		bc = cAccent
	}
	return lipgloss.NewStyle().Border(lipgloss.RoundedBorder()).BorderForeground(bc).
		Width(w - 2).Height(h - 2).MaxHeight(h).Render(content)
}

func (m *model) treeView() string {
	inner := m.w - 2
	if m.st == stScanning || m.cur == nil {
		frames := []string{"⠋", "⠙", "⠹", "⠸", "⠼", "⠴", "⠦", "⠧", "⠇", "⠏"}
		txt := fmt.Sprintf("%s Scanning %s\n\n%s files · %s", frames[m.tick%len(frames)], m.rootPath,
			commas(m.scanner.Count.Load()), human(m.scanner.Bytes.Load()))
		return m.box(txt, m.treeBoxH(), true)
	}
	var safe int64
	for _, c := range m.cur.Children {
		if v, _ := verdictFor(c); v == "SAFE" {
			safe += c.Size
		}
	}
	sum := fmt.Sprintf("%s  %s", m.cur.Path, human(m.cur.Size))
	if safe > 0 {
		sum += "   ● safe to reclaim here: " + human(safe)
	}
	lines := []string{sTitle.Render(fit(sum, inner))}
	rows := m.treeRows()
	kids := m.cur.Children
	for i := m.offset; i < len(kids) && i < m.offset+rows; i++ {
		lines = append(lines, m.row(kids[i], m.cur.Size, i == m.cursor, inner))
	}
	if len(kids) == 0 {
		lines = append(lines, sDim.Render("(empty)"))
	}
	return m.box(strings.Join(lines, "\n"), m.treeBoxH(), true)
}

func verdictColor(v string) lipgloss.Color {
	switch v {
	case "SAFE":
		return cGreen
	case "CAUTION":
		return cYellow
	case "KEEP":
		return cRed
	}
	return cGray
}

// marker returns the colored marker for a node.
func marker(n *Node) (string, lipgloss.Color) {
	if n.Pseudo {
		return "·", cDim
	}
	if n.IsDir {
		return " ", cDim // folders carry no color flag
	}
	v, _ := verdictFor(n)
	return "●", verdictColor(v)
}

func (m *model) row(n *Node, parentSize int64, sel bool, w int) string {
	const barW, pctW, sizeW = 10, 6, 9
	prefixW := 5 // mark, dir, space, dot, space
	nameW := max(10, w-(prefixW+1+barW+1+pctW+1+sizeW))
	p := pct(n.Size, parentSize)

	name := n.Name
	if n.IsDir {
		name += `\`
	}
	nameR := []rune(name)
	note := ""
	if !n.Pseudo {
		if k, l := classify(n.Path); k != "" {
			note = l
		}
	}
	noteTxt := ""
	if len(nameR) > nameW {
		name = string(nameR[:nameW-1]) + "…"
	} else if room := nameW - len(nameR) - 3; note != "" && room >= 6 {
		noteTxt = "  " + fit0(note, room)
	}
	pad := nameW - len([]rune(name)) - len([]rune(noteTxt))
	if pad < 0 {
		pad = 0
	}

	mk, dirm := " ", " "
	if m.marked[n] {
		mk = "✔"
	}
	if n.IsDir {
		dirm = "▸"
	}
	dot, dc := marker(n)

	fill := int(p/100*barW + 0.5)
	bar := strings.Repeat("█", fill) + strings.Repeat("░", barW-fill)
	tail := fmt.Sprintf(" %*.1f%% %*s", pctW-1, p, sizeW, human(n.Size))

	if sel {
		return sSel.Render(mk + dirm + " " + dot + " " + name + noteTxt + strings.Repeat(" ", pad) + " " + bar + tail)
	}
	ns := lipgloss.NewStyle()
	if n.IsDir {
		ns = sDir
	}
	if n.Pseudo {
		ns = sDim
	}
	if v, _ := verdictFor(n); v == "SAFE" && !n.Pseudo && !n.IsDir {
		ns = lipgloss.NewStyle().Foreground(cGreen)
	}
	bc := cGreen
	if p > 50 {
		bc = cRed
	} else if p > 20 {
		bc = cYellow
	}
	return lipgloss.NewStyle().Foreground(cGreen).Render(mk) + sDim.Render(dirm) + " " +
		lipgloss.NewStyle().Foreground(dc).Render(dot) + " " +
		ns.Render(name) + sDim.Render(noteTxt) + strings.Repeat(" ", pad) + " " +
		lipgloss.NewStyle().Foreground(bc).Render(bar) + tail
}

func (m *model) inspector() string {
	inner := m.w - 4
	n := m.selected()
	if n == nil || m.st == stScanning {
		return m.box("", inspectorH, false)
	}
	v, reason := verdictFor(n)
	badge := lipgloss.NewStyle().Foreground(verdictColor(v)).Bold(true).Render(v)
	if n.IsDir {
		badge = ""
	}
	kind := "file"
	if n.IsDir {
		kind = fmt.Sprintf("folder · %s files", commas(n.Files))
	}
	l1 := sBold.Render(fit0(n.Name, max(10, inner-45))) + sDim.Render(fmt.Sprintf("  %s · %.1f%% of folder · %s   ", human(n.Size), pct(n.Size, m.cur.Size), kind)) + badge
	l2 := "Why:  " + reason
	l4 := ""
	if n.IsDir {
		l4 = "Holds: " + m.extSummary(n)
	} else {
		l4 = "Type:  " + extOf(n.Name)
	}
	l5 := sDim.Render(n.Path)
	rows := []string{l1, l2, l4, l5}
	for i, r := range rows {
		if lipgloss.Width(r) > inner {
			rows[i] = lipgloss.NewStyle().MaxWidth(inner).Render(r)
		}
	}
	return m.box(strings.Join(rows, "\n"), inspectorH, false)
}

func (m *model) extSummary(n *Node) string {
	if s, ok := m.extCache[n]; ok {
		return s
	}
	ext := map[string]int64{}
	n.ExtStats(ext)
	type kv struct {
		k string
		v int64
	}
	var list []kv
	for k, v := range ext {
		if v > 0 {
			list = append(list, kv{k, v})
		}
	}
	sort.Slice(list, func(i, j int) bool { return list[i].v > list[j].v })
	var parts []string
	for i, e := range list {
		if i == 5 {
			break
		}
		parts = append(parts, fmt.Sprintf("%s %s", e.k, human(e.v)))
	}
	s := strings.Join(parts, " · ")
	if s == "" {
		s = "(nothing)"
	}
	m.extCache[n] = s
	return s
}

func (m *model) footer() string {
	if m.st == stConfirm {
		var tot int64
		for _, t := range m.targets {
			tot += t.Size
		}
		what := fit0(m.targets[0].Name, 30)
		if len(m.targets) > 1 {
			what = fmt.Sprintf("%d items", len(m.targets))
		}
		return lipgloss.NewStyle().Foreground(cRed).Bold(true).Render(
			fmt.Sprintf(" Delete %s (%s)?  [y] "+trashName+"   [p] PERMANENT   [any other key] cancel", what, human(tot)))
	}
	help := " ↑↓ move · → open · ← back · space mark · c mark safe · u unmark · d delete · o " + fileMgr + " · r rescan · q quit"
	if mk := m.markedList(); len(mk) > 0 {
		var tot int64
		for _, t := range mk {
			tot += t.Size
		}
		return lipgloss.NewStyle().Foreground(cGreen).Bold(true).Render(fit(fmt.Sprintf(" ✔ %d marked (%s) - press d to delete   ", len(mk), human(tot))+sDim.Render(m.status), m.w))
	}
	if m.status != "" {
		return sDim.Render(fit(" "+m.status, m.w))
	}
	return sDim.Render(fit(help, m.w))
}

// ---------- helpers ----------

func pct(a, b int64) float64 {
	if b <= 0 {
		return 0
	}
	return float64(a) * 100 / float64(b)
}

func fit(s string, w int) string {
	r := []rune(s)
	if len(r) > w {
		if w <= 1 {
			return string(r[:max(w, 0)])
		}
		return string(r[:w-1]) + "…"
	}
	return s + strings.Repeat(" ", w-len(r))
}

func fit0(s string, w int) string { return strings.TrimRight(fit(s, w), " ") }

func commas(n int64) string {
	s := fmt.Sprint(n)
	for i := len(s) - 3; i > 0; i -= 3 {
		s = s[:i] + "," + s[i:]
	}
	return s
}
