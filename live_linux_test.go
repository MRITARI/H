package main

import "os"

// liveTools lists every diagnostic screen.
var liveTools = []func() tool{netToolLx, pcToolLx, perfToolLx, updateToolLx, securityToolLx, hardwareToolLx, peripheralsToolLx}

func testScanRoot() string { return os.TempDir() }
