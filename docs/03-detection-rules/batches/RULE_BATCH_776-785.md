# CARTHAGO — R776–R785 independent workbook-derived source candidates

**SOURCE CANDIDATE — UNVERIFIED. xUnit authored; 0 tests, 0 builds, 0 CI, 0 replays, 0 holdouts.**

Ten independent process-attributed, typed-network-only shapes selected from the canonical 2,500-rule workbook after excluding endpoint-only telemetry claims and prior rule families. The original analytics require richer endpoint or data-access evidence. These candidates deliberately make NO claim of file reads, commands, exfiltration, C2, authenticated identity, transfer completion or compromise.

| Carthago | Original workbook | Independent observable shape | Threshold |
|---|---|---|---|
| R776 | R1296 | Windows PowerShell HTTP POST burst to text-storage host; process powershell.exe, http shape, port 80, pastebin.com | 5 in 20s |
| R777 | R1304 | Windows git HTTP POST burst to code-repository host; process git.exe, http shape, port 80, github.com | 5 in 20s |
| R778 | R1330 | Windows Excel TLS/443 burst to cloud-storage host; process excel.exe, tls shape, port 443, drive.google.com | 5 in 30s |
| R779 | R1361 | Windows 7-Zip uncommon-port TLS payload burst; process 7z.exe, tls shape, port 8443, updates.example.net | 5 in 30s |
| R780 | R1373 | Windows PowerShell TCP/21 payload burst; process powershell.exe, tcp shape, port 21, no host claim | 6 in 20s |
| R781 | R1166 | ESXi hostd TLS/443 burst to text-storage host; process hostd, tls shape, port 443, pastebin.com | 5 in 30s |
| R782 | R1436 | Linux tar TLS/443 burst to cloud-storage host; process tar, tls shape, port 443, drive.google.com | 5 in 30s |
| R783 | R1541 | Linux rsync TCP/21 payload burst; process rsync, tcp shape, port 21, no host claim | 6 in 20s |
| R784 | R1816 | macOS osascript HTTP POST burst to text-storage host; process osascript, http shape, port 80, paste.ee | 5 in 20s |
| R785 | R1987 | macOS launchd fixed-size TLS/443 egress cadence; process launchd, cadence shape, port 443, api.example.net | 4 in 100s |

All ten classes own independent state windows and cooldowns. Shared helpers are restricted to typed packet/process validation. Source-only xUnit coverage includes positive/negative, contradictions, replay, reverse-time, expiry, cooldown recovery, privacy, nonconvergence, Candidate/Shadow and registry uniqueness. Process attribution is local best-effort enrichment, not remote endpoint identity. HTTPS SNI is hostname evidence, not proof of HTTP POST or data upload. TCP/21 packets are port observations, not decoded FTP commands.

Canonical workbook: `file_00000000402c81f4bb16133abf63e951`; library file `libfile_3dce02a91bac8191a6896c8e24e04839`.

**Next unallocated ID: R786.** SOURCE CANDIDATE — UNVERIFIED.
