package main

import "fmt"

// Check is one real measurement. Status is PASS, WARN, FAIL or INFO.
// Hint explains what a non-passing result means; Fix is an id from fixes.go.
type Check struct {
	Name, Status, Detail, Hint, Fix string
}

type checkDef struct {
	Name string
	Run  func() Check
}

type tool struct {
	Title string
	Blurb string
	Defs  []checkDef
}

func pass(name, detail string) Check { return Check{Name: name, Status: "PASS", Detail: detail} }
func info(name, detail string) Check { return Check{Name: name, Status: "INFO", Detail: detail} }
func warn(name, detail, hint, fix string) Check {
	return Check{name, "WARN", detail, hint, fix}
}
func fail(name, detail, hint, fix string) Check {
	return Check{name, "FAIL", detail, hint, fix}
}

// probeErr turns an unavailable probe into an INFO row instead of a false verdict.
func probeErr(name string, err error) Check {
	return info(name, fmt.Sprintf("could not be checked (%v)", err))
}

func gb(b uint64) string { return fmt.Sprintf("%.1f GB", float64(b)/(1<<30)) }

// fixesTool lists the fixes of one category so any of them can be run on demand.
func fixesTool(cat string) tool {
	var defs []checkDef
	var blurb string
	for _, c := range fixCats {
		if c.Name != cat {
			continue
		}
		blurb = c.Blurb
		for _, id := range c.IDs {
			id := id
			defs = append(defs, checkDef{fixes[id].Desc, func() Check {
				f := fixes[id]
				detail := "[" + f.Risk + "] runs without admin rights"
				if f.Admin {
					detail = "[" + f.Risk + "] needs administrator rights"
				}
				return Check{Name: f.Desc, Status: "INFO", Detail: detail, Hint: "Press f to run this fix; you will be asked to confirm first.", Fix: id}
			}})
		}
	}
	return tool{Title: "Quick fixes: " + cat, Blurb: blurb, Defs: defs}
}
