# CARTHAGO — R736–R745 independent workbook-derived source candidates

**SOURCE CANDIDATE — UNVERIFIED. xUnit authored; 0 tests, 0 builds, 0 replay runs.**

## Admission and duplicate-screen basis

Direct work on `feature/carthago-reliability-hardening`. The live branch ended at R735 before this batch was authored. Candidate selection used only the owner-provided `CARTHAGO_R586-R3085_2500_UNIFIED_PRIORITY_RULE_RESEARCH_AND_TESTS(1).xlsx`; no fresh online research was used.

Several higher-ranked unused workbook rows were deliberately skipped because their core evidence requires file-read audit, credentials, endpoint crash/resource telemetry, asset inventory, configuration logs, or protocol semantics Carthago does not currently produce. Close live counterparts were also excluded: generic miner egress (R647), VNC listener exposure (R648), IDE dev-tunnel TLS (R662), repeated HTTP chunk uploads (R254), generic FTP upload (R248), and existing metadata rules.

Every new ID remains an independent class/predicate/state/test/documentation unit. Shared `Research736Evidence` contains only field validation, host/process classification and bounded state primitives.

| Carthago | Workbook / rank | Observable predicate | Important non-overlap / limitation |
|---|---:|---|---|
| R736 | R1510 / 225 | Linux transfer-tool process + four substantial TLS/443 payload observations to one public peer | R718 is PowerShell/Office→cloud storage; R726 is ESXi management-process TLS. R736 requires a Linux transfer-tool basename and makes no file-read/upload/exfiltration claim. |
| R737 | R1436 / 211 | curl/wget/Python + four large parsed cleartext HTTP POST/PUT packet observations | Does not parse encrypted HTTPS body and does not become R248 FTP or R254 repeated small chunks. Packet lengths are not delivered upload bytes. |
| R738 | R1548 / 395 | Linux transfer tool + three similarly sized raw outbound TCP payloads at regular 20–70s intervals | Scheduler/cron evidence is unavailable. The rule is cadence-specific and does not match isolated rsync/scp/rclone traffic. |
| R739 | R1425 / 627 | curl/wget/Python + 12 parsed HTTP GET/POST requests to one public peer in 10s | R731/R732 are SYN/UDP packet bursts. R739 requires parser-backed HTTP requests and never asserts backend CPU/memory exhaustion or DoS impact. |
| R740 | R1963 / 968 | osascript/Office/Preview + four large cleartext HTTP POST/PUT packet observations | macOS-characteristic process predicate. File access, HTTP response and delivered transfer are unavailable. |
| R741 | R1739 / 1394 | hostd/vpxa/vmx + TLS SNI to paste/Gist-style dead-drop service | R635 uses Windows system utilities; R733 uses macOS processes. R741 is hypervisor-management attribution only and does not observe retrieved C2 data. |
| R742 | R1750 / 1396 | BusyBox/curl/wget + three similarly sized TLS payloads at 9–31s cadence | Excludes dead-drop, cloud-storage, code-repository and public-IP-discovery host families. Shell origin and C2 content remain unknown. |
| R743 | R1647 / 1268 | hostd/vpxa/vmx + fixed-size raw TCP cadence on an uncommon public port | Distinct from R726 TLS/443 volume. No encoding, command line, lookup table, tunnel or C2 content is observable. |
| R744 | R1632 / 1386 | hostd/vpxa/vmx TCP SYNs to three distinct public proxy/tunnel-port peers in 60s | Only proxy-port fanout is established. No forwarding, relay chaining, authenticated proxy use or multi-hop path is inferred. |
| R745 | R2591 / 1517 | hping3/hping/nping + SYNs to four distinct public targets in 10s | R732 is generic Linux same-peer burst. R745 requires exact stress-tool attribution and distinct-target fanout; spoofing and DoS impact are unknown. |

## Evidence boundaries

- Process names are best-effort local tuple enrichment, not authenticated endpoint process events.
- R736 uses four unique TLS payload observations and a 5,000 observed-packet-byte threshold within two minutes. These are packet observations, not TCP unique bytes.
- R737/R740 require parser-coherent cleartext HTTP POST/PUT, each packet carrying at least 900 bytes of L4 data. Four observations and at least 5,000 observed packet bytes are required. No request-body reassembly is claimed.
- R738 requires three unique raw TCP payload observations with 20–70 second intervals, similar packet sizes and a total window no longer than three minutes.
- R739 requires twelve unique parser-backed GET/POST observations within ten seconds from the same process/peer context.
- R741 uses only TLS SNI and hypervisor-management process attribution.
- R742 requires three unique similar-size TLS observations at 9–31 second intervals and excludes neighboring service families before cadence state is updated.
- R743 requires raw TCP, an uncommon destination port, hypervisor-management process attribution and three fixed-size observations at 9–31 second intervals.
- R744/R745 use distinct-target state with duplicate-ID, reverse-time and expiry protections.
- All ten rules use independent ten-minute cooldown state and fixed structured evidence labels. Raw `Info`, URI queries, payloads, credentials and command lines are not emitted by these rule-specific evidence items.

## Authored xUnit source — not executed

`Carthago.Tests/R736R745AdvancedAccuracyBatchTests.cs` contains:

- positive real-life-shaped samples for all ten rules;
- independent benign near misses;
- missing local process attribution and contradictory transport failures;
- duplicate packet ID, reverse-time and expired-window checks;
- 12-request HTTP burst using sub-second monotonic timestamps;
- cooldown suppression and recovery for every rule;
- raw-info/query privacy assertions;
- explicit non-convergence checks against generic FTP, isolated transfer, dead-drop/common-host, TLS-volume and generic Linux flood families;
- Candidate / Shadow profile checks and full registry uniqueness.

**0 tests executed — 0 builds — 0 CI — 0 packet captures — 0 replays — 0 holdouts.**

## Workbook source references

- R736 ← R1510 (rank 225): https://attack.mitre.org/detectionstrategies/DET0512#AN1414
- R737 ← R1436 (rank 211): https://attack.mitre.org/detectionstrategies/DET0548#AN1512
- R738 ← R1548 (rank 395): https://attack.mitre.org/detectionstrategies/DET0399#AN1119
- R739 ← R1425 (rank 627): https://attack.mitre.org/detectionstrategies/DET0415#AN1166
- R740 ← R1963 (rank 968): https://attack.mitre.org/detectionstrategies/DET0149#AN0425
- R741 ← R1739 (rank 1394): https://attack.mitre.org/detectionstrategies/DET0058#AN0161
- R742 ← R1750 (rank 1396): https://attack.mitre.org/detectionstrategies/DET0027#AN0078
- R743 ← R1647 (rank 1268): https://attack.mitre.org/detectionstrategies/DET0326#AN0930
- R744 ← R1632 (rank 1386): https://attack.mitre.org/detectionstrategies/DET0325#AN0925
- R745 ← R2591 (rank 1517): https://attack.mitre.org/detectionstrategies/DET0518#AN1435

After successful atomic publication, the next contiguous source-candidate block is **R746–R755**, subject to a fresh live-branch and registry check before allocation.
