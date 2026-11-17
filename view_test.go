package main

import (
	"os"
	"strings"
	"sync"
	"testing"

	"github.com/charmbracelet/lipgloss"
)

func checkFits(t *testing.T, name, out string, w, h int) {
	t.Helper()
	lines := strings.Split(out, "\n")
	if len(lines) > h {
		t.Errorf("%s %dx%d: %d lines > height", name, w, h, len(lines))
	}
	for i, l := range lines {
		if lw := lipgloss.Width(l); lw > w {
			t.Errorf("%s %dx%d line %d width %d > %d: %q", name, w, h, i, lw, w, l)
		}
	}
}

func TestViewFits(t *testing.T) {
	root := os.Getenv("USERPROFILE") + `\Downloads`
	m := newModel(root)
	m.root = Scan(root, m.scanner)
	m.cur, m.st = m.root, stBrowse
	if len(m.cur.Children) > 2 {
		m.marked[m.cur.Children[0]] = true
	}
	for _, sz := range [][2]int{{70, 18}, {100, 30}, {160, 50}} {
		m.w, m.h = sz[0], sz[1]
		m.clamp()
		for _, key := range []string{"", "j", "c"} {
			if key != "" {
				m.cursor++
			}
			checkFits(t, "disk", m.View(), m.w, m.h)
		}
	}
}

func TestDiagViewFits(t *testing.T) {
	long := strings.Repeat("a very long explanation ", 20)
	d := newDiag(func() tool {
		var defs []checkDef
		for i := 0; i < 30; i++ {
			defs = append(defs, checkDef{"check", func() Check {
				return fail("check name that is rather long indeed", long, long, "flushdns")
			}})
		}
		return tool{Title: "Test", Blurb: "blurb", Defs: defs}
	})
	for i, def := range d.t.Defs {
		c := def.Run()
		if i%3 != 0 {
			d.res[i] = &c
		}
	}
	for _, sz := range [][2]int{{70, 18}, {100, 30}, {160, 50}} {
		d.w, d.h = sz[0], sz[1]
		for k := 0; k < 4; k++ {
			d.cursor += 7
			d.clamp()
			checkFits(t, "diag", d.View(), d.w, d.h)
		}
	}
}

func TestMenuAndCategoryFit(t *testing.T) {
	a := newApp(`C:\`)
	for _, sz := range [][2]int{{60, 16}, {100, 30}, {160, 50}} {
		a.w, a.h = sz[0], sz[1]
		a.sc = scMenu
		checkFits(t, "menu", a.View(), a.w, a.h)
		a.sc = scFixCats
		checkFits(t, "categories", a.View(), a.w, a.h)
	}
	if len(menuItems) > 9 || len(fixCats) > 9 {
		t.Errorf("menus support the number keys 1-9 only (menu %d, categories %d)", len(menuItems), len(fixCats))
	}
}

// Every category screen must render at the smallest supported size.
func TestFixCategoryScreens(t *testing.T) {
	for _, c := range fixCats {
		tl := fixesTool(c.Name)
		if len(tl.Defs) != len(c.IDs) {
			t.Errorf("%s: %d defs for %d ids", c.Name, len(tl.Defs), len(c.IDs))
		}
		d := newDiag(func() tool { return fixesTool(c.Name) })
		for i, def := range d.t.Defs {
			ck := def.Run()
			d.res[i] = &ck
		}
		d.w, d.h = 70, 18
		checkFits(t, "fixes "+c.Name, d.View(), d.w, d.h)
	}
}

func TestFixesExist(t *testing.T) {
	seen := map[string]string{}
	for _, c := range fixCats {
		for _, id := range c.IDs {
			if _, ok := fixes[id]; !ok {
				t.Errorf("category %q references unknown fix %q", c.Name, id)
			}
			if prev, dup := seen[id]; dup {
				t.Errorf("fix %q is in both %q and %q", id, prev, c.Name)
			}
			seen[id] = c.Name
		}
	}
	for id, f := range fixes {
		if seen[id] == "" {
			t.Errorf("fix %q is not in any category", id)
		}
		switch f.Risk {
		case "safe", "disruptive", "heavy":
		default:
			t.Errorf("fix %q has invalid risk %q", id, f.Risk)
		}
		if f.Desc == "" || f.Run == nil {
			t.Errorf("fix %q is incomplete", id)
		}
	}
}

// liveTools lists every diagnostic screen.
var liveTools = []func() tool{netTool, pcTool, perfTool, updateTool, securityTool, hardwareTool, peripheralsTool}

// Runs every real check on this PC. Opt in with H_LIVE=1 (takes about a minute).
func TestLiveChecks(t *testing.T) {
	if os.Getenv("H_LIVE") == "" {
		t.Skip("set H_LIVE=1 to run every check on this PC")
	}
	for _, mk := range liveTools {
		tl := mk()
		res := make([]Check, len(tl.Defs))
		var wg sync.WaitGroup
		for i, d := range tl.Defs {
			wg.Add(1)
			go func() {
				defer wg.Done()
				probeSem <- struct{}{}
				defer func() { <-probeSem }()
				res[i] = d.Run()
			}()
		}
		wg.Wait()
		t.Logf("== %s", tl.Title)
		for _, c := range res {
			t.Logf("[%s] %s - %s | fix=%s", c.Status, c.Name, c.Detail, c.Fix)
			switch c.Status {
			case "PASS", "WARN", "FAIL", "INFO":
			default:
				t.Errorf("%s: invalid status %q", c.Name, c.Status)
			}
			if c.Fix != "" {
				if _, ok := fixes[c.Fix]; !ok {
					t.Errorf("%s: unknown fix %q", c.Name, c.Fix)
				}
			}
			if (c.Status == "WARN" || c.Status == "FAIL") && c.Hint == "" {
				t.Errorf("%s: %s without an explanation", c.Name, c.Status)
			}
		}
	}
}
