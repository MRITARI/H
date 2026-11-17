package main

import (
	"fmt"
	"strings"

	"golang.org/x/sys/windows/registry"
)

// ---------- Security ----------

func securityTool() tool {
	def := &lazy{f: func() (string, error) {
		return ps(`try { $s=Get-MpComputerStatus -ErrorAction Stop; "$($s.AntivirusEnabled)|$($s.RealTimeProtectionEnabled)|$($s.AntivirusSignatureAge)|$($s.QuickScanAge)" } catch { 'ERR' }; exit 0`)
	}}
	defender := func(name string, f func(p []string) Check) checkDef {
		return checkDef{name, func() Check {
			out, _ := def.get()
			p := strings.Split(strings.TrimSpace(out), "|")
			if len(p) < 4 {
				return info(name, "Microsoft Defender is not the active antivirus (another product may be installed)")
			}
			return f(p)
		}}
	}
	defs := []checkDef{
		defender("Defender real-time protection", func(p []string) Check {
			if p[0] != "True" || p[1] != "True" {
				return warn("Defender real-time protection", "real-time protection is off",
					"Files are not scanned as they are opened. If you use another antivirus this is expected; otherwise turn it on in Windows Security.", "open-windows-security")
			}
			return pass("Defender real-time protection", "on")
		}),
		defender("Defender definitions", func(p []string) Check {
			age := atoi(p[2])
			txt := fmt.Sprintf("%d day(s) old", age)
			if age > 7 {
				return warn("Defender definitions", txt, "Out-of-date virus definitions miss new threats. Update them now.", "update-defender-signatures")
			}
			return pass("Defender definitions", txt)
		}),
		defender("Last quick scan", func(p []string) Check {
			age := atoi(p[3])
			if age > 100000 {
				return warn("Last quick scan", "never run", "No Defender scan has run on this PC. A quick scan takes a few minutes.", "defender-quick-scan")
			}
			txt := fmt.Sprintf("%d day(s) ago", age)
			if age > 14 {
				return warn("Last quick scan", txt, "It has been a while since the last scan. Run a quick scan.", "defender-quick-scan")
			}
			return pass("Last quick scan", txt)
		}),
		psCheck("Firewall profiles", `Get-NetFirewallProfile | ForEach-Object { "$($_.Name)|$($_.Enabled)" }`, func(l []string) Check {
			var off []string
			for _, x := range l {
				if p := strings.Split(x, "|"); len(p) == 2 && p[1] != "True" {
					off = append(off, p[0])
				}
			}
			if len(l) == 0 {
				return info("Firewall profiles", "could not be read")
			}
			if len(off) > 0 {
				return warn("Firewall profiles", "off for: "+strings.Join(off, ", "), "The firewall is off for some network types, leaving this PC open to the network. Turn it back on unless another firewall manages it.", "enable-firewall")
			}
			return pass("Firewall profiles", "on for Domain, Private and Public")
		}),
		{"User Account Control", func() Check {
			if v, ok := regDWORD(registry.LOCAL_MACHINE, `SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System`, "EnableLUA"); ok && v == 0 {
				return fail("User Account Control", "UAC is turned off", "Without UAC every program runs with full rights. Turn it on in Control Panel > User Accounts and restart.", "open-windows-security")
			}
			return pass("User Account Control", "on")
		}},
		{"SMBv1", func() Check {
			if v, ok := regDWORD(registry.LOCAL_MACHINE, `SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters`, "SMB1"); ok && v == 1 {
				return warn("SMBv1", "the old SMBv1 file-sharing protocol is enabled", "SMBv1 is obsolete and was used by ransomware worms. Disable it in Windows Features unless an old device needs it.", "")
			}
			return pass("SMBv1", "not enabled")
		}},
		{"Remote Desktop", func() Check {
			if v, ok := regDWORD(registry.LOCAL_MACHINE, `SYSTEM\CurrentControlSet\Control\Terminal Server`, "fDenyTSConnections"); ok && v == 0 {
				return warn("Remote Desktop", "incoming Remote Desktop connections are allowed", "Fine if you use it. If not, turn it off in Settings > System > Remote Desktop to reduce attack surface.", "")
			}
			return pass("Remote Desktop", "disabled")
		}},
		{"Automatic sign-in", func() Check {
			if v, ok := regString(registry.LOCAL_MACHINE, `SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon`, "AutoAdminLogon"); ok && v == "1" {
				return warn("Automatic sign-in", "Windows signs in without a password", "Anyone who powers on this PC gets in. Fine for a kiosk, risky for a normal PC.", "")
			}
			return pass("Automatic sign-in", "off")
		}},
		psCheck("Local administrators", `Get-LocalGroupMember -SID S-1-5-32-544 -ErrorAction SilentlyContinue | ForEach-Object { $_.Name }`, func(l []string) Check {
			if len(l) == 0 {
				return info("Local administrators", "could not be listed")
			}
			txt := fmt.Sprintf("%d: %s", len(l), strings.Join(l, ", "))
			if len(l) > 6 {
				return warn("Local administrators", txt, "Many accounts have full control. Remove administrator rights from accounts that do not need them.", "")
			}
			return pass("Local administrators", txt)
		}),
		{"BitLocker drive encryption", func() Check {
			if c := adminOnly("BitLocker drive encryption"); c != nil {
				return *c
			}
			l, _ := psLines(`Get-BitLockerVolume -ErrorAction SilentlyContinue | ForEach-Object { "$($_.MountPoint)|$($_.ProtectionStatus)" }; exit 0`)
			var off []string
			for _, x := range l {
				if p := strings.Split(x, "|"); len(p) == 2 && p[1] != "On" {
					off = append(off, p[0])
				}
			}
			switch {
			case len(l) == 0:
				return info("BitLocker drive encryption", "not available on this edition of Windows")
			case len(off) > 0:
				return warn("BitLocker drive encryption", "protection off on "+strings.Join(off, ", "), "Unencrypted drives expose their data if the PC is lost or stolen. Turn on BitLocker or Device Encryption on laptops.", "open-windows-security")
			}
			return pass("BitLocker drive encryption", "protection on")
		}},
		{"Secure Boot & TPM", func() Check {
			if c := adminOnly("Secure Boot & TPM"); c != nil {
				return *c
			}
			l, _ := psLines(`$sb='ERR'; try { $sb=Confirm-SecureBootUEFI } catch {}; $t=Get-Tpm -ErrorAction SilentlyContinue; "$sb|$($t.TpmPresent)|$($t.TpmReady)"; exit 0`)
			p := strings.Split(strings.Join(l, ""), "|")
			if len(p) != 3 {
				return info("Secure Boot & TPM", "could not be read")
			}
			txt := fmt.Sprintf("Secure Boot %s, TPM present %s, ready %s", p[0], p[1], p[2])
			if p[0] != "True" || p[1] != "True" {
				return warn("Secure Boot & TPM", txt, "Windows 11 and BitLocker expect Secure Boot and a TPM. Enable them in the BIOS/UEFI if the hardware supports it.", "open-msinfo")
			}
			return pass("Secure Boot & TPM", txt)
		}},
	}
	return tool{Title: "Security check", Blurb: "Defender, firewall, UAC, encryption, risky settings", Defs: defs}
}

// ---------- Hardware & battery ----------

func hardwareTool() tool {
	bat := &lazy{f: func() (string, error) {
		return ps(`$b = Get-CimInstance Win32_Battery | Select-Object -First 1; if (-not $b) { 'NONE' } else { "$($b.EstimatedChargeRemaining)|$($b.BatteryStatus)" }; exit 0`)
	}}
	defs := []checkDef{
		{"Battery charge", func() Check {
			out, _ := bat.get()
			p := strings.Split(strings.TrimSpace(out), "|")
			if len(p) != 2 {
				return info("Battery charge", "no battery (desktop PC)")
			}
			pct, status := atoi(p[0]), atoi(p[1])
			state := "on battery"
			if status == 2 || status >= 6 {
				state = "plugged in"
			}
			txt := fmt.Sprintf("%d%%, %s", pct, state)
			if pct < 20 && state == "on battery" {
				return warn("Battery charge", txt, "The battery is low. Plug in the charger.", "")
			}
			return pass("Battery charge", txt)
		}},
		{"Battery health", func() Check {
			if out, _ := bat.get(); strings.TrimSpace(out) == "NONE" {
				return info("Battery health", "no battery (desktop PC)")
			}
			l, _ := psLines(`$f=(Get-CimInstance -Namespace root\wmi -ClassName BatteryFullChargedCapacity -ErrorAction SilentlyContinue | Select-Object -First 1).FullChargedCapacity; ` +
				`$d=(Get-CimInstance -Namespace root\wmi -ClassName BatteryStaticData -ErrorAction SilentlyContinue | Select-Object -First 1).DesignedCapacity; "$f|$d"; exit 0`)
			p := strings.Split(strings.Join(l, ""), "|")
			if len(p) != 2 || atoi(p[1]) == 0 || atoi(p[0]) == 0 {
				return info("Battery health", "capacity data not available on this PC")
			}
			pct := 100 * atoi(p[0]) / atoi(p[1])
			txt := fmt.Sprintf("%d%% of original capacity (%d of %d mWh)", pct, atoi(p[0]), atoi(p[1]))
			switch {
			case pct < 50:
				return fail("Battery health", txt, "The battery has lost half its capacity and should be replaced.", "battery-report")
			case pct < 75:
				return warn("Battery health", txt, "The battery is worn. Runtime will be noticeably shorter; consider replacing it. The report shows the history.", "battery-report")
			}
			return pass("Battery health", txt)
		}},
		psCheck("Drive failure prediction", `Get-CimInstance -Namespace root\wmi -ClassName MSStorageDriver_FailurePredictStatus -ErrorAction SilentlyContinue | ForEach-Object { $_.PredictFailure }`,
			func(l []string) Check {
				if len(l) == 0 {
					return info("Drive failure prediction", "not reported by this drive (or needs an administrator terminal)")
				}
				for _, x := range l {
					if x == "True" {
						return fail("Drive failure prediction", "a drive predicts it will fail", "The drive's own SMART monitoring expects a failure. Back up everything now and replace the drive.", "open-diskmgmt")
					}
				}
				return pass("Drive failure prediction", "no failure predicted")
			}),
		psCheck("Drive wear & temperature", `Get-PhysicalDisk | ForEach-Object { $r = $_ | Get-StorageReliabilityCounter -ErrorAction SilentlyContinue; "$($_.FriendlyName)|$($r.Wear)|$($r.Temperature)|$($r.ReadErrorsTotal)|$($r.WriteErrorsTotal)" }`,
			func(l []string) Check {
				var notes, issues []string
				for _, x := range l {
					p := strings.Split(x, "|")
					if len(p) != 5 {
						continue
					}
					if p[1] != "" && atoi(p[1]) >= 80 {
						issues = append(issues, fmt.Sprintf("%s is %s%% worn", p[0], p[1]))
					}
					if p[2] != "" && atoi(p[2]) >= 60 {
						issues = append(issues, fmt.Sprintf("%s runs hot (%s C)", p[0], p[2]))
					}
					if atoi(p[3])+atoi(p[4]) > 0 {
						issues = append(issues, fmt.Sprintf("%s has read/write errors", p[0]))
					}
					if p[2] != "" {
						notes = append(notes, fmt.Sprintf("%s %s C", p[0], p[2]))
					}
				}
				if len(issues) > 0 {
					return warn("Drive wear & temperature", strings.Join(issues, "; "), "Heavy wear, heat or errors shorten a drive's life. Back up important data and plan a replacement.", "open-diskmgmt")
				}
				if len(notes) == 0 {
					return info("Drive wear & temperature", "not reported by this drive (or needs an administrator terminal)")
				}
				return pass("Drive wear & temperature", strings.Join(notes, ", "))
			}),
		psCheck("CPU temperature", `Get-CimInstance -Namespace root\wmi -ClassName MSAcpi_ThermalZoneTemperature -ErrorAction SilentlyContinue | ForEach-Object { [math]::Round($_.CurrentTemperature/10-273.15) }`,
			func(l []string) Check {
				if len(l) == 0 {
					return info("CPU temperature", "this PC does not expose it to Windows (or needs an administrator terminal)")
				}
				t := atoi(l[0])
				if t >= 90 {
					return warn("CPU temperature", fmt.Sprintf("%d C", t), "Very hot. Clean the fans and vents, check the thermal paste and make sure the PC has airflow.", "open-resmon")
				}
				return pass("CPU temperature", fmt.Sprintf("%d C", t))
			}),
		psCheck("Memory modules", `Get-CimInstance Win32_PhysicalMemory | ForEach-Object { "$([int]($_.Capacity/1GB)) GB @ $($_.ConfiguredClockSpeed) MHz" }`,
			func(l []string) Check {
				if len(l) == 0 {
					return info("Memory modules", "not reported")
				}
				return info("Memory modules", fmt.Sprintf("%d module(s): %s", len(l), strings.Join(l, ", ")))
			}),
		psCheck("Graphics driver age", `Get-CimInstance Win32_VideoController | ForEach-Object { if ($_.DriverDate) { "$($_.Name)|$($_.DriverDate.ToString('yyyy-MM-dd'))" } }`,
			func(l []string) Check {
				var old, all []string
				for _, x := range l {
					if p := strings.Split(x, "|"); len(p) == 2 {
						if age, ok := ageDays(p[1]); ok {
							all = append(all, fmt.Sprintf("%s (%s)", p[0], p[1]))
							if age > 730 {
								old = append(old, p[0])
							}
						}
					}
				}
				if len(all) == 0 {
					return info("Graphics driver age", "not reported")
				}
				if len(old) > 0 {
					return warn("Graphics driver age", strings.Join(all, ", "), "The graphics driver is over two years old. Newer drivers fix crashes, glitches and game problems.", "open-devmgmt")
				}
				return pass("Graphics driver age", strings.Join(all, ", "))
			}),
		psCheck("BIOS / firmware age", `(Get-CimInstance Win32_BIOS).ReleaseDate.ToString('yyyy-MM-dd')`,
			func(l []string) Check {
				d := strings.Join(l, "")
				age, ok := ageDays(d)
				if !ok {
					return info("BIOS / firmware age", "not reported")
				}
				txt := fmt.Sprintf("%s (%.1f years old)", d, float64(age)/365)
				if age > 365*5 {
					return warn("BIOS / firmware age", txt, "Old firmware misses stability and security fixes. Check the PC maker's support page for a BIOS update.", "open-msinfo")
				}
				return pass("BIOS / firmware age", txt)
			}),
		psCheck("USB device errors", `Get-PnpDevice -Class USB -Status ERROR -ErrorAction SilentlyContinue | ForEach-Object { $_.FriendlyName }`,
			func(l []string) Check {
				if len(l) == 0 {
					return pass("USB device errors", "none")
				}
				return warn("USB device errors", strings.Join(l, ", "), "A USB device or hub reports a driver error. Replug it, try another port, or reinstall its driver.", "open-devmgmt")
			}),
	}
	return tool{Title: "Hardware & battery", Blurb: "battery wear, drive health, drivers, BIOS, temperature", Defs: defs}
}

// ---------- Printing & peripherals ----------

func peripheralsTool() tool {
	svcState := func(name, svc, hint, fixID string, disabledOnly bool) checkDef {
		return psCheck(name, fmt.Sprintf(`Get-Service %s -ErrorAction SilentlyContinue | ForEach-Object { "$($_.Name)|$($_.Status)|$($_.StartType)" }`, svc),
			func(l []string) Check {
				var bad []string
				for _, x := range l {
					p := strings.Split(x, "|")
					if len(p) != 3 {
						continue
					}
					if p[2] == "Disabled" || (!disabledOnly && p[1] != "Running") {
						bad = append(bad, fmt.Sprintf("%s (%s, %s)", p[0], p[1], p[2]))
					}
				}
				if len(l) == 0 {
					return info(name, "service not present on this PC")
				}
				if len(bad) > 0 {
					return warn(name, strings.Join(bad, ", "), hint, fixID)
				}
				return pass(name, "running")
			})
	}
	defs := []checkDef{
		svcState("Print spooler", "Spooler", "Nothing can print while the spooler is stopped. Restart it.", "restart-spooler", false),
		psCheck("Printers & print queue", `Get-Printer -ErrorAction SilentlyContinue | ForEach-Object { $j=(Get-PrintJob -PrinterName $_.Name -ErrorAction SilentlyContinue | Measure-Object).Count; "$($_.Name)|$j|$($_.PrinterStatus)" }`,
			func(l []string) Check {
				if len(l) == 0 {
					return info("Printers & print queue", "no printers installed (or the spooler is stopped)")
				}
				var stuck, odd []string
				for _, x := range l {
					p := strings.Split(x, "|")
					if len(p) != 3 {
						continue
					}
					if atoi(p[1]) > 0 {
						stuck = append(stuck, fmt.Sprintf("%s has %s job(s)", p[0], p[1]))
					}
					if p[2] != "Normal" && p[2] != "Idle" && p[2] != "Printing" {
						odd = append(odd, fmt.Sprintf("%s is %s", p[0], p[2]))
					}
				}
				switch {
				case len(odd) > 0:
					return warn("Printers & print queue", strings.Join(odd, "; "), "A printer reports a problem: offline, paper jam, out of paper or an error. Check the printer itself first.", "open-printers-settings")
				case len(stuck) > 0:
					return warn("Printers & print queue", strings.Join(stuck, "; "), "Jobs are waiting in the queue. If they do not print, clearing the queue usually fixes it (for shared network printers the queue lives on the print server, so this only clears local jobs).", "clear-print-queue")
				}
				return pass("Printers & print queue", fmt.Sprintf("%d printer(s), no stuck jobs", len(l)))
			}),
		psCheck("Default printer", `(Get-CimInstance Win32_Printer | Where-Object Default).Name`,
			func(l []string) Check {
				if len(l) == 0 {
					return info("Default printer", "none set")
				}
				return info("Default printer", strings.Join(l, ", "))
			}),
		svcState("Audio services", "audiosrv,AudioEndpointBuilder", "Without these services there is no sound. Restart them.", "restart-audio", false),
		psCheck("Audio output devices", `(Get-PnpDevice -Class AudioEndpoint -Status OK -ErrorAction SilentlyContinue | Measure-Object).Count`,
			func(l []string) Check {
				n := atoi(strings.Join(l, ""))
				if n == 0 {
					return warn("Audio output devices", "no active audio devices", "Windows sees no speakers or microphone. Check the cable or headset, then restart the audio services.", "restart-audio")
				}
				return pass("Audio output devices", fmt.Sprintf("%d active endpoint(s)", n))
			}),
		svcState("Bluetooth service", "bthserv", "The Bluetooth service is disabled, so Bluetooth devices cannot connect. Set it to Manual in Services.", "open-services", true),
		psCheck("Camera", `Get-PnpDevice -Class Camera,Image -ErrorAction SilentlyContinue | ForEach-Object { "$($_.FriendlyName)|$($_.Status)" }`,
			func(l []string) Check {
				if len(l) == 0 {
					return info("Camera", "no camera found")
				}
				var bad []string
				for _, x := range l {
					if p := strings.Split(x, "|"); len(p) == 2 && p[1] != "OK" {
						bad = append(bad, p[0]+" ("+p[1]+")")
					}
				}
				if len(bad) > 0 {
					return warn("Camera", strings.Join(bad, ", "), "The camera has a driver problem or is disabled. Check Device Manager and the camera privacy switch.", "open-devmgmt")
				}
				return pass("Camera", fmt.Sprintf("%d camera(s) working", len(l)))
			}),
		psCheck("Keyboard & mouse", `Get-PnpDevice -Class Keyboard,Mouse -Status ERROR -ErrorAction SilentlyContinue | ForEach-Object { $_.FriendlyName }`,
			func(l []string) Check {
				if len(l) == 0 {
					return pass("Keyboard & mouse", "no driver errors")
				}
				return warn("Keyboard & mouse", strings.Join(l, ", "), "An input device has a driver error. Replug it or reinstall the driver in Device Manager.", "open-devmgmt")
			}),
	}
	return tool{Title: "Printing & peripherals", Blurb: "printers, audio, Bluetooth, camera, input devices", Defs: defs}
}
