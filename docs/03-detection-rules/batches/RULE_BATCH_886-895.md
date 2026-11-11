# CARTHAGO — R886–R895 observable research candidates

**SOURCE CANDIDATE — UNVERIFIED.** Work directly on `feature/carthago-reliability-hardening`. Ten isolated `Candidate`/`Shadow` rules, confidence floor 80%, bounded in-memory windows, 10-minute alert cooldown. Source tests authored first; **0 builds, tests, CI jobs, runtime replays or precision gates executed**. No promotion, convergence, behavior changes to existing rules, authenticated principal inference or unsupported host-log substitution.

| New ID | Workbook origin | Typed network predicate | Important unsupported evidence |
| --- | --- | --- | --- |
| R886 | R1513 | Public SSH/22 SYN to private host then same private host sends SMB/445 SYN to another private peer in 60s | SSH login, sudo, interactive shell, lateral success |
| R887 | R1287 | `code`/`idea64`-attributed TLS/443 on tunnel-like SNI to two distinct public IPs within 45s | Extension installation, IDE tunnel activation, server/developer role |
| R888 | R1644 | `hostd`/`vpxa`-attributed TLS/443 to two public peers with same SNI within 45s | ESXi asset trust, approved vCenter/updater baseline, C2 |
| R889 | R1649 | Four `hostd`/`vpxa` TLS/8443 packets of similar size to same public peer at 5–20s spacing in 65s | Junk data, ciphertext contents, malware beacon identity |
| R890 | R1891 | `rundll32`-attributed TLS/9443 to two public peers sharing one SNI in 45s | DLL image load, process ancestry, unusualness against fleet baseline |
| R891 | R1743 | Public VNC/5900 SYN and subsequent same-source-port client TCP payload within 40s | VNC login, session takeover, interactive actions |
| R892 | R1208 | Private broadcast-address UDP/9 of 102 payload bytes then same source SYNs to private TCP/3389 in 45s | True magic packet, target MAC, host wake, firewall activation |
| R893 | R2704 | `powershell` DNS A query then same process/source TLS/443 to public peer with matching SNI in 60s | DNS answer, ICS Windows role, forbidden peer, malicious script |
| R894 | R2720 | Same public source SSH/22 SYN then `/api/login` HTTP POST to same private host within 60s | Linux/ICS host type, authentication, user identity, success |
| R895 | R2632 | Same private source SYNs to same private service on TCP/502 then TCP/44818 within 45s | Transient/new device identity, asset enrollment, unauthorized OT contact |

## Research/telemetry boundary

Original workbook entries are typically broader, requiring syslog, auditd, Windows Event Log, ESXi guest logs, verified device inventory, access decisions or vendor allowlists. CARTHAGO does **not** claim that a packet-only projection implements that complete analytic. Each rule detects only the specific telemetry it can actually observe, explicitly states the unobserved portions, and remains disabled for production alerting by Shadow mode. Do not infer a malicious action from a shadow match.

Previously registered related shapes were screened: R706 port-knocking, R755 VNC→script egress, R756 ESXi repository TLS, R858 hostd TLS/9443 burst, R862 rundll32 DNS TXT→TLS, R870 hostd HTTP polling, R878 SSH same-flow payload, R883 VMX TLS fanout, R885 CGI→bash TLS, and R871 Modbus four-device walk. R886–R895 have separate per-rule predicates, sources, windows and cooldowns; no shared correlation state, no merged detection. This is candidate source, not a uniqueness or recall guarantee.

Unsupported variations deliberately skipped: host-audit-confirmed SSH privilege escalation, IDE extension file installation, reliable vCenter allowlist policy, VNC session hijacking, content-based junk-data decoding, WOL magic bytes, actual DHCP asset onboarding and OT device enrollment. No fabricated producer, direct source code execution or configuration change is claimed.

## Source tests (not run)

`Carthago.Tests/R886R895ObservableCandidateBatchTests.cs` contains per-rule typed positive cases, benign near misses, missing IP and contradictory transport fields, duplicate packet IDs, reverse UTC and expired windows, independent state, cooldown and recovery, raw `Info` exclusion, peer and SNI precision tests, cadence minimum spacing, and exact Candidate/Shadow unique registration check. **Compilation and pass/fail status are unknown.**

## Owner-workbook source attribution

- R886 / R1513 — https://attack.mitre.org/detectionstrategies/DET0269#AN0751
- R887 / R1287 — https://attack.mitre.org/detectionstrategies/DET0561#AN1548
- R888 / R1644 — https://attack.mitre.org/detectionstrategies/DET0273#AN0762
- R889 / R1649 — https://attack.mitre.org/detectionstrategies/DET0011#AN0033
- R890 / R1891 — https://attack.mitre.org/detectionstrategies/DET0273#AN0759
- R891 / R1743 — https://attack.mitre.org/detectionstrategies/DET0354#AN1006
- R892 / R1208 — https://attack.mitre.org/detectionstrategies/DET0524#AN1448
- R893 / R2704 — https://attack.mitre.org/detectionstrategies/DET0799#AN2281
- R894 / R2720 — https://attack.mitre.org/detectionstrategies/DET0796#AN2256
- R895 / R2632 — https://attack.mitre.org/detectionstrategies/DET0744#AN1877

Next unallocated rule ID: **R896**, subject to a fresh live-branch inspection.
