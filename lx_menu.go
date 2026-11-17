package main

// linuxMenuItems is the Linux main menu (menu_linux.go selects it; no build tag so tests can render it anywhere).
var linuxMenuItems = []menuItem{
	{Title: "Disk scanner", Blurb: "dirscope: what is using my disk space? safe-to-delete hints", Disk: true},
	{Title: "Network diagnostics", Blurb: "no internet, slow Wi-Fi, DNS problems", Build: netToolLx},
	{Title: "System troubleshooter", Blurb: "general health: CPU, memory, disks, failed services, errors", Build: pcToolLx},
	{Title: "Performance check", Blurb: "why is my PC slow? load, pressure, caches, startup", Build: perfToolLx},
	{Title: "Updates & packages", Blurb: "broken or stuck package manager, pending updates, reboots", Build: updateToolLx},
	{Title: "Security check", Blurb: "firewall, SSH, SELinux/AppArmor, encryption, open ports", Build: securityToolLx},
	{Title: "Hardware & battery", Blurb: "battery wear, drive health, temperatures, firmware", Build: hardwareToolLx},
	{Title: "Printing & peripherals", Blurb: "CUPS printers, audio, Bluetooth, camera, input", Build: peripheralsToolLx},
	{Title: "Quick fixes", Blurb: "common repairs in categories - each asks before running", Cats: true},
}
