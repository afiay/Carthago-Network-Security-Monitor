# CARTHAGO — R826–R835 independent process, request and DNS/TLS candidates

**SOURCE CANDIDATE — UNVERIFIED. 0 tests, 0 builds, 0 CI, 0 replay and 0 holdouts executed.**

Canonical original owner workbook: `CARTHAGO_R586-R3085_2500_UNIFIED_PRIORITY_RULE_RESEARCH_AND_TESTS(1).xlsx` (Library `libfile_3dce02a91bac8191a6896c8e24e04839`). CARTHAGO IDs are **new allocations**, not the source workbook IDs. Every candidate is its own C# class, state and rule identity, **Candidate / Shadow**, with an 80 confidence floor.

| New ID | Workbook ID | Independently observable candidate shape | Explicit evidence limitation |
|---|---|---|---|
| R826 | R2237 | Notepad SYNs to two external peers | Process-attributed SYN only; no injection evidence |
| R827 | R2924 | finger.exe TCP/79 SYN fanout | Process packet, not executable launch or remote query result |
| R828 | R3057 | wget public direct-IP `.tar` HTTP GET | HTTP, not original HTTPS with certificate-bypass CLI flag |
| R829 | R3063 | `.zip` TLD executable HTTP GET | Request, not MOTW stream / file creation |
| R830 | R3076 | Two distinct executable GETs at one public direct IP | Request patterns, not downloaded files or Zone.Identifier |
| R831 | R3078 | MpCmdRun public-IP archive HTTP GET | Request, not DownloadFile command-line flag or file write |
| R832 | R3083 | CertOC public-IP HTTP GET | Request, not -GetCACAPS flag or CA response |
| R833 | R1970 | Word template GET → PowerShell different-peer TLS | Source-IP sequence, no Office child-process ancestry |
| R834 | R2000 | Script-host DGA-like DNS burst → TLS payload | Heuristic label-shape evidence, no algorithm or NXDOMAIN verdict |
| R835 | R2069 | mshta HTA GET → rundll32 different-peer TLS | Source-IP sequence, no infection stage or C2 validation |

## Admission, rejected work and safety boundaries

Original workbook predicates are principally based on trusted Windows/macOS/Linux endpoint telemetry, CLI parameters, NTFS streams, code execution, file writes, SaaS/OT authorization or vendor event logs. None are silently synthesized from network traffic. Where a subset of the original behavior is visible, the rule description and event explicitly qualify the packet-only observation. **No claims** are made about compromised hosts, exfiltration, completed downloads, executed payloads, or confirmed C2.

- Already registered or semantically duplicated research was screened and rejected: workbook R1258 (R757), R2274 (R599), R2312 (R607), R2855 (R766), R2941 (R620), R2960 (R609), R2963 (R634), R2974 (R598), R3009 (R593), R3036 (R692), R3041 (R605), R3048 (R613), R3053 (R595). No original workbook ID used for this batch was previously assigned as a source ID.
- The typed process identifier is local packet/tuple attribution, **not** a trusted child-process event or cryptographic identity.
- For two-process chains (R833/R835), shared local IP and 60-second ordering do **not** establish parentage. For R834, long digit-mixed DNS names are *heuristic candidate signals*, not a validated domain generation algorithm or fast-flux proof.
- Stateless packet hygiene uses existing TCP/DNS/HTTP guards. Per-rule bounded distinct/correlation windows and cooldown instances do not combine alert state between rules.
- Direct-IP comparisons require the parsed cleartext `HttpHost` to be the canonical public destination IPv4 address; TLS encryption is never interpreted as HTTP GET or a file path.
- Source-only evidence contains static workbook identifiers, static matched-condition tags, and unknown-outcome markers; no user-supplied `Info`, raw URI, DNS qname, username, hostname, payload, secret or certificate bytes are copied into custom evidence fields. Framework-normalized endpoint fields may still appear.
- No rule is promoted; promotion requires producer provenance, positive/benign replay, precision/recall, performance and holdout review. The owner specifically requested xUnit **source**, not execution.

## Authored xUnit source (not executed)

`Carthago.Tests/R826R835ObservableCandidateBatchTests.cs` covers typed positives, near-misses, contradictory flags, missing endpoints, duplicate IDs, reversed timestamps, expired correlation, cooldown recovery, raw-Info exclusion, neighboring-rule independence, source-preserved browser/process distinctions, and registry uniqueness/Candidate/Shadow profiles. **These assertions have not been compiled or run.**

## Source links from owner workbook

- R826 / workbook R2237: https://github.com/SigmaHQ/sigma/blob/ccbb0369507f796db0b0ae6854c8a2be471b9d84/rules/windows/network_connection/net_connection_win_notepad.yml
- R827 / workbook R2924: https://github.com/SigmaHQ/sigma/blob/ccbb0369507f796db0b0ae6854c8a2be471b9d84/rules/windows/process_creation/proc_creation_win_finger_execution.yml
- R828 / workbook R3057: https://github.com/SigmaHQ/sigma/blob/ccbb0369507f796db0b0ae6854c8a2be471b9d84/rules-emerging-threats/2023/TA/UNC4841-Barracuda-ESG-Zero-Day-Exploitation/proc_creation_lnx_apt_unc4841_wget_download_tar_files_direct_ip.yml
- R829 / workbook R3063: https://github.com/SigmaHQ/sigma/blob/ccbb0369507f796db0b0ae6854c8a2be471b9d84/rules/windows/create_stream_hash/create_stream_hash_zip_tld_download.yml
- R830 / workbook R3076: https://github.com/SigmaHQ/sigma/blob/ccbb0369507f796db0b0ae6854c8a2be471b9d84/rules/windows/create_stream_hash/create_stream_hash_susp_ip_domains.yml
- R831 / workbook R3078: https://github.com/SigmaHQ/sigma/blob/ccbb0369507f796db0b0ae6854c8a2be471b9d84/rules/windows/process_creation/proc_creation_win_mpcmdrun_download_arbitrary_file.yml
- R832 / workbook R3083: https://github.com/SigmaHQ/sigma/blob/ccbb0369507f796db0b0ae6854c8a2be471b9d84/rules/windows/process_creation/proc_creation_win_certoc_download_direct_ip.yml
- R833 / workbook R1970: https://attack.mitre.org/detectionstrategies/DET0566#AN1564
- R834 / workbook R2000: https://attack.mitre.org/detectionstrategies/DET0419#AN1178
- R835 / workbook R2069: https://attack.mitre.org/detectionstrategies/DET0228#AN0637

**Next unallocated CARTHAGO ID: R836. SOURCE CANDIDATE — UNVERIFIED.**

