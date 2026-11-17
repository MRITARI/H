package main

import (
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"sort"
	"strings"
	"sync"
	"sync/atomic"
)

// bigFile is the size above which a file gets its own node in the tree.
// Smaller files are folded into one "small files" pseudo node per directory,
// which keeps memory bounded on drives with millions of files.
const bigFile = 1 << 20

type Node struct {
	Name, Path string
	Size       int64
	Files      int64
	IsDir      bool
	Pseudo     bool // aggregate of small files; cannot be selected for deletion
	Denied     bool // directory could not be read
	Children   []*Node
	Parent     *Node
	Ext        map[string]int64 // direct files only (dirs)
}

type Scanner struct {
	Count atomic.Int64
	Bytes atomic.Int64
	sem   chan struct{}
}

func Scan(root string, s *Scanner) *Node {
	n := &Node{Name: root, Path: root, IsDir: true}
	s.sem = make(chan struct{}, runtime.NumCPU()*4)
	s.scanDir(n)
	return n
}

func (s *Scanner) scanDir(n *Node) {
	entries, err := os.ReadDir(n.Path)
	if err != nil {
		n.Denied = true
		return
	}
	n.Ext = map[string]int64{}
	var wg sync.WaitGroup
	var small, smallCnt int64
	var dirs []*Node

	for _, e := range entries {
		if e.Type()&(os.ModeSymlink|os.ModeIrregular) != 0 {
			continue // symlinks / junctions / reparse points: avoid loops & double counting
		}
		if e.IsDir() {
			c := &Node{Name: e.Name(), Path: filepath.Join(n.Path, e.Name()), IsDir: true, Parent: n}
			n.Children = append(n.Children, c)
			dirs = append(dirs, c)
			select {
			case s.sem <- struct{}{}:
				wg.Add(1)
				go func() {
					defer wg.Done()
					defer func() { <-s.sem }()
					s.scanDir(c)
				}()
			default:
				s.scanDir(c)
			}
			continue
		}
		info, err := e.Info()
		if err != nil {
			continue
		}
		sz := info.Size()
		s.Count.Add(1)
		s.Bytes.Add(sz)
		n.Size += sz
		n.Files++
		n.Ext[extOf(e.Name())] += sz
		if sz >= bigFile {
			n.Children = append(n.Children, &Node{Name: e.Name(), Path: filepath.Join(n.Path, e.Name()), Size: sz, Files: 1, Parent: n})
		} else {
			small += sz
			smallCnt++
		}
	}
	wg.Wait()
	for _, c := range dirs {
		n.Size += c.Size
		n.Files += c.Files
	}
	if smallCnt > 0 {
		n.Children = append(n.Children, &Node{
			Name: fmt.Sprintf("‹%d small files›", smallCnt), Size: small, Files: smallCnt, Pseudo: true, Parent: n,
		})
	}
	sortChildren(n)
}

func sortChildren(n *Node) {
	sort.Slice(n.Children, func(i, j int) bool { return n.Children[i].Size > n.Children[j].Size })
}

func extOf(name string) string {
	e := strings.ToLower(filepath.Ext(name))
	if e == "" {
		return "(none)"
	}
	return e
}

// Remove detaches n from the tree and fixes up ancestor totals.
func (n *Node) Remove() {
	p := n.Parent
	if p == nil {
		return
	}
	for i, c := range p.Children {
		if c == n {
			p.Children = append(p.Children[:i], p.Children[i+1:]...)
			break
		}
	}
	if !n.IsDir && p.Ext != nil {
		p.Ext[extOf(n.Name)] -= n.Size
	}
	for a := p; a != nil; a = a.Parent {
		a.Size -= n.Size
		a.Files -= n.Files
	}
}

// ExtStats aggregates size per extension across the subtree.
func (n *Node) ExtStats(into map[string]int64) {
	if !n.IsDir {
		into[extOf(n.Name)] += n.Size
		return
	}
	for k, v := range n.Ext {
		into[k] += v
	}
	for _, c := range n.Children {
		if c.IsDir {
			c.ExtStats(into)
		}
	}
}

func human(b int64) string {
	const u = 1024.0
	f := float64(b)
	switch {
	case f >= u*u*u*u:
		return fmt.Sprintf("%.2f TB", f/(u*u*u*u))
	case f >= u*u*u:
		return fmt.Sprintf("%.1f GB", f/(u*u*u))
	case f >= u*u:
		return fmt.Sprintf("%.1f MB", f/(u*u))
	case f >= u:
		return fmt.Sprintf("%.1f KB", f/u)
	}
	return fmt.Sprintf("%d B", b)
}
