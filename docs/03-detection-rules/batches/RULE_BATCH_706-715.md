# CARTHAGO — R706–R715 independent workbook-derived source candidates

**SOURCE CANDIDATE — UNVERIFIED. xUnit authored; 0 tests, 0 builds, 0 replay runs.**

## Live-branch admission basis

Work is directly on `feature/carthago-reliability-hardening`, rebased against live HEAD `f08d7b609f001432481aa3ac1ee1fb5961c6ec36`. The live registry contained **705 registered rules / 705 unique IDs**, ending at R705, so R706–R715 were available. Research comes from the owner-provided `CARTHAGO_R586-R3085_2500_UNIFIED_PRIORITY_RULE_RESEARCH_AND_TESTS(1).xlsx`; no new external research was needed for candidate selection.

Every rule remains a separate Candidate / Shadow detector. Shared code is limited to typed evidence hygiene and bounded per-instance correlation state. No endpoint command line, file write, authentication result, successful connection, exploit result, device role, approved-workstation list, payload body, or transfer completion is invented.

| Carthago | Workbook / rank | Narrow observable behavior | Non-overlap / limitation |
|---|---|---|---|
| R706 | R1445 / 10 | Public source sends SYNs to exactly three distinct high ports on one private host, then an admin-service SYN within 60 s | Distinct from R676, which requires an ordered unicast/broadcast/network-address pattern at one port. No closed-port result, firewall change, listener activation or successful session is observed. |
| R707 | R2606 / 244 | Two distinct private UDP/67 responders target the same private UDP/68 client within 10 s | R462 is a generic single-event rogue-offer candidate; R707 requires two distinct responder source addresses. DHCP OFFER/ACK type, DNS/gateway options and authorization are not parsed. |
| R708 | R2799 / 265 | Public client requests TFTP/69 on a private host and receives an ephemeral-port reply to its original client port | Inbound direction only. No firmware-update mode, target role, file name, transfer result or approved-engineering-source context is known. |
| R709 | R2810 / 269 | Public-to-private cleartext HTTP GET/POST on a management-style port with URI length >1024 | Uses only the workbook's oversized-request branch; traversal matching remains with R086. Asset type, exploit string, vulnerable application and exploit success are unknown. |
| R710 | R1114 / 602 | One private host sends UDP/11211 traffic to three distinct public peers within 60 s | Distinct from R242 NTP amplification and R439 Memcached enumeration. No spoofed source, Memcached command, reflection ratio, victim or DoS impact is observed. |
| R711 | R1811 / 2069 | Same Plink/PuTTY PID contacts public SSH then a different private admin-service peer | Exact process identity plus two-leg sequence; not the generic one-flow R263 proxy signal. No forwarding flags, authentication, encapsulation or established tunnel is visible. |
| R712 | R2049 / 1887 | Same Socat PID receives public high-port SYN then contacts a different private admin-service peer | Distinct from R674's PowerShell/Rundll32/Netsh public-egress sequence. No bind/connect syscall, relay payload or successful forwarding is observed. |
| R713 | R2306 / 2131 | Same Netcat/Ncat PID sends public uncommon-high-port SYN then raw TCP payload on the same tuple | Sigma source is command-line based; Carthago does not see `-e`/`-c` or shell execution. This is explicitly not a confirmed reverse shell. |
| R714 | R1727 / 1905 | Same Netcat/Ncat PID sends SYNs to four distinct ports on one private peer within 30 s | Distinct from R680's different-process multi-host fanout. Container context, service responses and discovery intent are unknown. |
| R715 | R1246 / 142 | Private client requests public TFTP/69 and receives an ephemeral-port reply to its original client port | Opposite direction from R708. File/configuration identity, upload direction, transfer completion and exfiltration are not observed. |

## Evidence and state boundaries

- R706 uses a 60-second instance-owned sequence keyed by public source and private target. Exactly three distinct high-port knocks are required before the final admin-port SYN; duplicate IDs, reverse time and stale sequences cannot advance state.
- R707 uses a 10-second distinct-source window and requires two unique DHCP-server-port responder addresses for one private client. It deliberately does not parse or claim DHCP message type.
- R708 and R715 use separate rule-owned 30-second TFTP request/reply correlation. The reply must return to the original high client port; direction is part of each rule's identity.
- R709 stores no URI in event evidence. It accepts only coherent cleartext HTTP metadata and management-style destination ports; raw query content is not emitted.
- R710 requires three distinct public UDP/11211 peers in 60 seconds. A single Memcached contact or repeated packets to one peer cannot satisfy it.
- R711/R712 preserve exact Plink/PuTTY versus Socat identities and use separate per-rule two-leg windows.
- R713 requires a Netcat/Ncat SYN followed by non-HTTP/non-TLS/non-DNS raw TCP payload on the exact same tuple and PID.
- R714 requires four distinct destination ports on one private peer; changing hosts does not satisfy the rule.
- Every rule owns its cooldown instance. New evidence contains only workbook identifier, generic matched-condition label and an outcome-scope label.

## xUnit source — authored, not executed

`Carthago.Tests/R706R715AdvancedAccuracyBatchTests.cs` covers all ten candidates with:

- positive real-life-shaped sequences;
- benign near misses;
- missing required telemetry;
- contradictory TCP/UDP fields;
- duplicate packet IDs and reverse/stale time for correlated rules;
- correlation-window expiry;
- per-rule cooldown suppression and recovery;
- raw Info/URI privacy checks;
- Candidate / Shadow registration and full registry ID uniqueness;
- explicit non-convergence checks for TFTP direction, Plink vs Socat identity, and Netcat external vs internal shapes.

**Zero tests, builds, CI, packet captures, replay runs or holdouts were executed.**

## Workbook source URLs

- R706 ← R1445 (rank 10): https://attack.mitre.org/detectionstrategies/DET0524#AN1449
- R707 ← R2606 (rank 244): https://attack.mitre.org/detectionstrategies/DET0468#AN1290
- R708 ← R2799 (rank 265): https://attack.mitre.org/detectionstrategies/DET0802#AN2179
- R709 ← R2810 (rank 269): https://attack.mitre.org/detectionstrategies/DET0740#AN2235
- R710 ← R1114 (rank 602): https://attack.mitre.org/detectionstrategies/DET0408#AN1143
- R711 ← R1811 (rank 2069): https://attack.mitre.org/detectionstrategies/DET0538#AN1483
- R712 ← R2049 (rank 1887): https://attack.mitre.org/detectionstrategies/DET0538#AN1484
- R713 ← R2306 (rank 2131): https://github.com/SigmaHQ/sigma/blob/ccbb0369507f796db0b0ae6854c8a2be471b9d84/rules/linux/process_creation/proc_creation_lnx_netcat_reverse_shell.yml
- R714 ← R1727 (rank 1905): https://attack.mitre.org/detectionstrategies/DET0376#AN1060
- R715 ← R1246 (rank 142): https://attack.mitre.org/detectionstrategies/DET0149#AN0427

After successful publication, the next contiguous candidate block is **R716–R725**, subject to re-fetching the live branch before allocation.
