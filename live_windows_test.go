package main

import "os"

// liveTools lists every diagnostic screen.
var liveTools = []func() tool{netTool, pcTool, perfTool, updateTool, securityTool, hardwareTool, peripheralsTool}

func testScanRoot() string { return os.Getenv("USERPROFILE") + `\Downloads` }
