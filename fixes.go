package main

import (
	"fmt"
	"os/exec"
	"strings"
	"time"
)

// A fix is a fixed, reviewed action. Checks only ever reference a fix by id,
// and nothing runs until the user presses y.
//
// Risk tells the user what to expect before they confirm:
//
//	safe       - opens a tool or changes nothing important
//	disruptive - brief disconnect, service restart or settings change; easy to undo
//	heavy      - long-running, needs a restart, or permanently deletes data
type fix struct {
	Desc  string
	Admin bool
	Risk  string
	Run   func() (string, error)
}

type fixCat struct {
	Name, Blurb string
	IDs         []string
}

func runFixCmd(timeout time.Duration, name string, args ...string) func() (string, error) {
	return func() (string, error) { return run(timeout, name, args...) }
}

func openFix(msg, name string, args ...string) func() (string, error) {
	return func() (string, error) { return msg, exec.Command(name, args...).Start() }
}

// fixCatOf returns the category name a fix belongs to.
func fixCatOf(id string) string {
	for _, c := range fixCats {
		for _, x := range c.IDs {
			if x == id {
				return c.Name
			}
		}
	}
	return ""
}

// runFix executes a fix by id, refusing admin fixes in a normal terminal.
func runFix(id string) (string, error) {
	f, ok := fixes[id]
	if !ok {
		return "", fmt.Errorf("unknown fix %q", id)
	}
	if f.Admin && !isAdmin() {
		return "", fmt.Errorf("needs %s rights - press a on the main menu to restart as %s", adminWord, adminWord)
	}
	out, err := f.Run()
	return strings.TrimSpace(out), err
}
