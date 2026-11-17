package main

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
