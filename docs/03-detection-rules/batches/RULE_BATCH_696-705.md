# CARTHAGO — R696–R705 independent workbook-derived source candidates

**SOURCE CANDIDATE — UNVERIFIED. xUnit authored; 0 tests, 0 builds, 0 replay runs.**

## Provenance and anti-duplicate scope

Direct work on `feature/carthago-reliability-hardening`, after R695. Candidate research comes from the owner-supplied `CARTHAGO_R586-R3085_2500_UNIFIED_PRIORITY_RULE_RESEARCH_AND_TESTS(1).xlsx`. No new web research was performed. Original workbook IDs are preserved separately from the Carthago registry IDs.

| Carthago | Workbook / rank | Narrow observable behavior | Existing overlap and distinction |
|---|---|---|---|
| R696 | R2103 / 1579 | Bitsadmin-associated contact to selected file-sharing service | R686 requires Bitsadmin to a direct IP; this rule instead requires a bounded file-sharing host family. Command-line transfer switches, output path and completed download are not observed. |
| R697 | R2292 / 2125 | Certutil-associated contact to selected file-sharing service | R687 is Certutil direct-IP HTTP and R633 is Certutil service-port egress; this is exact file-sharing host contact. Certutil URL-cache/verify flags and any downloaded file are not observable. |
| R698 | R2305 / 2130 | PowerShell-associated contact to selected file-sharing service | R657 requires a Pastebin API POST; this rule requires GET/TLS host contact to the bounded sharing-provider family. PowerShell download APIs, script contents, local file writes and transfer success are not visible. |
| R699 | R2315 / 2136 | Office process cleartext HTTP GET for executable or script-like path | R690 is Curl-specific; this requires an Office process/PID and a suspicious extension on a public HTTP GET. Office command-line URL invocation and saved-file destination are unavailable; a GET path is not proof of download. |
| R700 | R2415 / 1167 | Rundll32-associated external WebDAV request | R174 is inbound WebDAV abuse and R692 is Outlook-specific; this requires private-to-public WebDAV plus Rundll32 PID/name. DavSetCookie command line, parent process, code launch and CVE exploitation are not observed. |
| R701 | R2506 / 1758 | Net.exe-associated external WebDAV request | R700 is Rundll32-specific; this rule preserves the separate Net/Net1 utility identity for external DAV traffic. The `net use` command line and successful mount result are not observable from the packet record. |
| R702 | R2767 / 254 | Known application protocol classified on an incompatible OT service port | R683 is specifically HTTP POST on Modbus/502. This excludes 502 and checks parsed protocol mismatch on 102, 44818 or 4840. Protocol classification mismatch is not proof of an intercepting hook, asset compromise, malformed response or unauthorized tool. |
| R703 | R2043 / 1070 | Script-like process emits repeated raw UDP payloads to one public high-port peer | R670 handles timed ICMP; existing process-egress rules are TCP-oriented. This rule is UDP-only, process-attributed and repeated. Five UDP datagrams do not prove non-application C2, exfiltration, payload semantics or server receipt. |
| R704 | R1793 / 1056 | Unattributed private host receives internal high-port SYN then initiates admin-service SYN to another private host | R680 requires an unusual attributed process fanout; this rule explicitly requires missing process attribution and an ordered relay-shaped pair. Two SYN packets do not prove a proxy, C2 relay, ESXi shell tool, accepted connection or forwarded payload. |
| R705 | R1783 / 1054 | Unattributed private host receives public high-port SYN then initiates SYN to a different public peer | R674 requires the same attributed process; this candidate explicitly requires no PID/name and correlates at host level only. Host-level SYN correlation does not establish netcat/socat, reverse tunnel, traffic bridging or successful connections. |

## Evidence boundaries

- R696–R698 reuse the bounded file-sharing host classifier already introduced for R689, but preserve **separate process identities**: Bitsadmin, Certutil, PowerShell. They require best-effort PID/name and either cleartext GET or TLS SNI contact to a selected provider root. They do not prove a download, upload, command-line switch or local file write.
- R699 requires an Office process/PID plus a cleartext outbound GET whose path ends in a selected executable/script-like extension. This is intentionally narrower than the source command-line rule and is not a file-delivery claim.
- R700 and R701 require private→public, parser-validated WebDAV methods and exact Rundll32 versus Net/Net1 process attribution. Existing R174 is inbound; R692 is Outlook-specific. No successful mount, DavSetCookie action or code execution is asserted.
- R702 requires a *known parser classification* that conflicts with an OT service port: destination 102 not S7Comm, 44818 not EtherNet/IP, or 4840 not OPC UA. Port 502 is deliberately excluded because R683 owns HTTP-on-Modbus/502. The event is a protocol-classification mismatch only; it cannot establish a hooked device, malformed response or attacker.
- R703 uses five same-process UDP observations to one public peer/high port within two minutes, with no DNS/HTTP/TLS/application classification and bounded per-packet payload lengths. This is distinct from R670 ICMP timing and TCP process-egress rules. It does not prove C2 or exfiltration.
- R704 and R705 **explicitly require missing process attribution**. R704 correlates a private inbound high-port SYN to a relay candidate followed by that host initiating a SYN to a *different private peer* on a constrained admin/data-service port. R705 correlates a public inbound high-port SYN followed by that private host initiating a SYN to a *different public peer*. This keeps them separate from R674/R680/R681, whose predicates require process identity. Two SYNs never prove relay forwarding or connection success.

All ten are Candidate maturity and Shadow mode. Every rule retains its own cooldown instance. The UDP burst uses the existing bounded timed window; relay state is capped at 512 keys and 30 seconds per pair. No raw URI/payload, credential, username or process path is emitted in new evidence.

## xUnit source — authored, not executed

`Carthago.Tests/R696R705AdvancedAccuracyBatchTests.cs` defines positive and benign-negative cases, exact process identities, provider suffix boundaries, Office extension paths, WebDAV methods, OT protocol normal/mismatch controls, UDP threshold and common-port exclusions, internal/public relay peer differences, explicit no-process gates, replay/cooldown and registry uniqueness. **Zero tests or builds executed.**

## Workbook source URLs

- R696 ← R2103 (rank 1579): https://github.com/SigmaHQ/sigma/blob/ccbb0369507f796db0b0ae6854c8a2be471b9d84/rules/windows/process_creation/proc_creation_win_bitsadmin_download_file_sharing_domains.yml
- R697 ← R2292 (rank 2125): https://github.com/SigmaHQ/sigma/blob/ccbb0369507f796db0b0ae6854c8a2be471b9d84/rules/windows/process_creation/proc_creation_win_certutil_download_file_sharing_domains.yml
- R698 ← R2305 (rank 2130): https://github.com/SigmaHQ/sigma/blob/ccbb0369507f796db0b0ae6854c8a2be471b9d84/rules/windows/process_creation/proc_creation_win_powershell_download_susp_file_sharing_domains.yml
- R699 ← R2315 (rank 2136): https://github.com/SigmaHQ/sigma/blob/ccbb0369507f796db0b0ae6854c8a2be471b9d84/rules/windows/process_creation/proc_creation_win_office_arbitrary_cli_download.yml
- R700 ← R2415 (rank 1167): https://github.com/SigmaHQ/sigma/blob/ccbb0369507f796db0b0ae6854c8a2be471b9d84/rules/windows/process_creation/proc_creation_win_rundll32_webdav_client_susp_execution.yml
- R701 ← R2506 (rank 1758): https://github.com/SigmaHQ/sigma/blob/ccbb0369507f796db0b0ae6854c8a2be471b9d84/rules/windows/process_creation/proc_creation_win_net_use_mount_internet_share.yml
- R702 ← R2767 (rank 254): https://attack.mitre.org/detectionstrategies/DET0722#AN2286
- R703 ← R2043 (rank 1070): https://attack.mitre.org/detectionstrategies/DET0457#AN1254
- R704 ← R1793 (rank 1056): https://attack.mitre.org/detectionstrategies/DET0075#AN0207
- R705 ← R1783 (rank 1054): https://attack.mitre.org/detectionstrategies/DET0445#AN1232

After successful publication, the next contiguous candidate block is **R706–R715**. Preserve frozen holdouts, UI automation and all validated rule confidence floors.
