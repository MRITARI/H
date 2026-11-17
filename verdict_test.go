package main

import "testing"

func TestVerdicts(t *testing.T) {
	cases := []struct {
		path, name string
		dir        bool
		want       string
	}{
		{`C:\Users\a\Downloads\x.iso`, "x.iso", false, "CAUTION"},
		{`C:\Users\a\AppData\Local\Temp\foo.dat`, "foo.dat", false, "SAFE"},
		{`C:\Windows\System32\drivers`, "drivers", true, "KEEP"},
		{`C:\pagefile.sys`, "pagefile.sys", false, "KEEP"},
		{`C:\Users\a\thing.xyz`, "thing.xyz", false, "UNSURE"},
		{`C:\Users\a\x\node_modules`, "node_modules", true, "SAFE"},
	}
	for _, c := range cases {
		if v, _ := verdictFor(&Node{Name: c.name, Path: c.path, IsDir: c.dir}); v != c.want {
			t.Errorf("%s: got %s want %s", c.path, v, c.want)
		}
	}
}
