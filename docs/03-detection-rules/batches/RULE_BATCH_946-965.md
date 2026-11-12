# CARTHAGO — R946–R965 observable research candidates

**SOURCE CANDIDATE — UNVERIFIED.** Twenty separate Candidate/Shadow rules, test source authored first; no new build, test, CI or runtime replay executed. Owner-supplied local checkpoint: at d01ad78 R926–R945 105/105 passing, 0 failed/skipped; at 0d2d7ef R896–R925 171/171 passing. These are 276 prior unit-test results across two checkpoints, not a new combined run.

## Workbook source and observable boundary

Exact original workbook rows in `CARTHAGO_R586-R3085_2500_UNIFIED_PRIORITY_RULE_RESEARCH_AND_TESTS(1).xlsx`, Ranked 2500 rules sheet. Source title and URL retained. New IDs are separate from original workbook projected IDs. The full source analytics are **not implemented**: the narrow network projections below require existing typed packet data; boot, firmware, logon, process lineage, execution, OT role/approval, command arguments and compromise remain unsupported unless explicitly observable. Some utility-attribution patterns may be rare or unobservable in production; unit fixtures are not producer verification.

| New ID | Original row | Original research title | Network projection |
|---|---|---|---|
| R946 | R1130 | T1542.005 Pre-OS Boot: TFTP Boot — Network Devices (AN1603) | Private UDP/69 request-shaped record followed by reverse private UDP data from an ephemeral source port to the original client port within 45s. Boot configuration, TFTP opcode, file name, firmware and transfer outcome are unknown. |
| R947 | R1138 | T1542.004 Pre-OS Boot: ROMMONkit — Network Devices (AN0497) | Private TCP/22 SYN to a host followed by that host sending public UDP/69 data. This is a port-based management/transfer sequence, not ROMMON modification, firmware upgrade, reboot or authenticated SSH. |
| R948 | R1172 | T1542 Pre-OS Boot — Network Devices (AN0777) | Private parsed FTP STOR request followed by same-source same-destination TCP/22 SYN. File name, upload completion, SCP, firmware role, boot configuration and authorization are unknown. |
| R949 | R1185 | T1542.001 Pre-OS Boot: System Firmware — Network Devices (AN0276) | Private parsed FTP STOR then same-source same-destination UDP/69 data. Transfer contents, TFTP opcode, firmware identity, device role and modification outcome are unknown. |
| R950 | R1328 | Network Logon Script Abuse via Multi-Event Correlation on Windows — Windows (AN1034) | Same private PowerShell PID retrieves a .ps1 path over private HTTP then issues a parsed SMB2 WRITE to the same private peer. GPO, logon script setting, file contents, user logon and execution are unknown. |
| R951 | R1828 | Detecting Electron Application Abuse for Proxy Execution — Windows (AN0071) | Same local Teams PID sends public TLS/443 with visible SNI then public TCP/445 SYN to a different or same peer. Electron argument abuse, child process, app-resource change and execution are unknown. |
| R952 | R1800 | Detecting PowerShell Execution via SyncAppvPublishingServer.vbs Proxy Abuse — Windows (AN1220) | Wscript PID retrieves a public .vbs path then sends public TLS/443 data. SyncAppvPublishingServer invocation, embedded PowerShell, script content and execution are unknown. |
| R953 | R1830 | Detection of Script-Based Proxy Execution via Signed Microsoft Utilities — Windows (AN1288) | Same private cscript PID retrieves a .js path from a private peer then TCP/135 SYN to that peer. Signature status, script arguments, child process, RPC execution and authorization are unknown. |
| R954 | R1492 | Web Shell Detection via Server Behavior and File Execution Chains — Linux (AN1109) | Public HTTP GET for a .php path on a private host followed by Bash-attributed TCP/4444 SYN from that host to a public peer. Webshell creation, process ancestry, command execution and C2 are unknown. |
| R955 | R1399 | Web Shell Detection via Server Behavior and File Execution Chains — Windows (AN1108) | Public HTTP POST to a private .aspx endpoint followed by w3wp-attributed TCP/5985 SYN from that host to a public peer. File creation, child shells, authenticated WinRM, execution and compromise are unknown. |
| R956 | R2074 | Remote System Enumeration Behavior — Windows (AN1583) | Same net/net1 PID sends TCP/135 then TCP/389 SYN to one private peer. Enumeration command, returned system/user data and authorization are unknown. |
| R957 | R2681 | Detection of Remote System Information Discovery — Windows (AN1919) | Same WMIC PID sends private TCP/135 then TCP/445 SYN to one peer. WMI query, returned system information, authenticated session, OT role and authorization are unknown. |
| R958 | R2672 | Behavioral Detection of Internet Connection Discovery — ESXi (AN1018) | Same curl PID sends public HTTP GET to exact connectivitycheck.gstatic.com /generate_204 followed by private TCP/902 SYN. ESXi identity, shell command, service identity and authorized connectivity check are unknown. |
| R959 | R2752 | Behavioral Detection of Internet Connection Discovery — Windows (AN1015) | Same PowerShell PID contacts public TCP/53 then sends TLS/443 data to the same public peer. Test-NetConnection, DNS query, connectivity test intent and authorization are unknown. |
| R960 | R2812 | Behavioral Detection of Command and Scripting Abuse in ICS — Network Devices (AN2084) | Same private ssh/plink PID and private peer sends four TCP/22 data records of 512–4096 bytes at 5–20 second intervals. ICS role, approved management baseline, decoded SSH command and authorization are unknown. |
| R961 | R1635 | Network Boundary Bridging — Network Devices (AN0015) | Public TCP/3128 SYN to a private host followed by that host sending TCP/502 SYN to a private peer in a different /24. Proxy relay, VLAN policy, device role, authentication and control action are unknown. |
| R962 | R2843 | Detection Strategy for Dynamic Resolution using Fast Flux DNS — Linux (AN1332) | Local curl/python-attributed public UDP A queries each followed by reverse-tuple low-TTL public A response for the same name; three distinct response addresses within 45s. DNS transaction IDs, authoritative control, Linux platform and malicious fast flux are unknown. |
| R963 | R2948 | Potential Exploitation of CVE-2024-3094 - Suspicious SSH Child Process | Public SSH TCP/22 SYN to a private host then sshd-attributed public TLS/443 from that host. XZ backdoor, SSH child process, authentication and command execution are unknown. |
| R964 | R1912 | Behavioral Detection Strategy for Exfiltration Over Symmetric Encrypted Non-C2 Protocol — macOS (AN1391) | Same OpenSSL PID sends TLS data to public TCP/8443 then TCP/443 at the same peer. File encryption, symmetric key use, content, operating system and exfiltration are unknown. |
| R965 | R2596 | Detection Strategy for T1547.010 – Port Monitor DLL Persistence via spoolsv.exe (Windows) — Windows (AN0580) | Same spoolsv PID retrieves public DLL-suffix HTTP path then TCP/445 SYN to same public peer. Print-monitor registry write, DLL load, AddMonitor call and persistence are unknown. |

## Duplicate screening and limits

The expansion cursor was screened for all twenty origin IDs; relevant registry entries reviewed. R946 private/private TFTP request-shaped exchange differs from R708 public/private and R715 private/public; no TFTP opcode decoded. R947 private SSH then outbound public TFTP differs from R792 ESXi FTP/TFTP and R881 public FTP/private TFTP. R948/R949 private parsed STOR then SSH or UDP/69 differ from R554 SMB-to-FTP and R663 public STOR/APPE. R950 private same-peer PS1 GET then SMB WRITE differs from R920 public PS1 GET/TLS and R903 SMB/WinRM. R951 Teams TLS then SMB differs from R890 rundll32 TLS peer pair. R952 wscript VBS GET then TLS differs from R817 script GET then different shell and R927 cscript scriptlet. R953 cscript private JS GET then RPC differs from R927 public SCT. R954 PHP GET then bash TCP/4444 differs from R885 CGI POST/bash TLS and R839 traversal/worker TLS. R955 ASPX POST then w3wp WinRM differs from R923 outbound ASPX POST. R956 net RPC/LDAP differs from R898 SMB peer fanout and R901 nltest LDAP/GC. R957 WMIC RPC/SMB differs from R720 public XSL GET. R958 curl connectivity GET then private TCP/902 differs from R724 public IP-discovery service. R959 PowerShell TCP/53 SYN then TLS/443 differs from R677 TLS on port 53 and R893 DNS query then TLS SNI. R960 SSH-port payload cadence differs from R913 hostd public SSH-port burst and R761 public RMM cadence. R961 public proxy ingress then cross-/24 private TCP/502 differs from R941 SOCKS leg and R800 reverse-direction SCADA then HTTP. R962 correlates CLI-attributed DNS A questions with three reverse-tuple distinct low-TTL answers, unlike R876 private resolver response churn then SYN and R844 public response churn without question attribution. R963 public SSH then sshd public TLS differs from R775 macOS sshd SYN-ACK followed by different user tool and R859 SSH ingress/esxcli TLS. R964 OpenSSL TLS/8443 then same-peer TLS/443 differs from R812 UDP payload burst and R748 uncommon-port crypto payload burst. R965 spoolsv DLL GET then public SMB differs from R926 odbcconf DLL GET and R906 rundll32 SMB.

Targeted comparison is not exhaustive equivalence proof. Host-only correlations do not prove a shared session or causality. R946/R947/R949 use UDP/69 shapes, not a TFTP parser; R948/R949 use typed FTP STOR, R950 typed SMB2 WRITE. R962 requires matching client/resolver/port/qname but DNS transaction ID is not available; each query/reply pair has a 45s window and response churn uses a separate 45s window. R960 cadence 65s; other correlations 45s; existing bounded state and ten-minute cooldown. Raw Info, payload, credentials and raw HTTP headers not copied into event evidence. DNS query redaction uses existing helper.

## Tests

`Carthago.Tests/R946R965ObservableCandidateBatchTests.cs` — 100 theory cases plus six facts, positive, missing/contradictory evidence, wrong final port, duplicate/reverse/expired UTC, cooldown, independent state, PID/host/tuple isolation, typed parser labels, DNS distinct answers and query matching, cadence, HTTP resource/scope and registry maturity. **Not executed.** No production promotion.

## Exact workbook source references

- R946 / R1130: https://attack.mitre.org/detectionstrategies/DET0582#AN1603
- R947 / R1138: https://attack.mitre.org/detectionstrategies/DET0175#AN0497
- R948 / R1172: https://attack.mitre.org/detectionstrategies/DET0278#AN0777
- R949 / R1185: https://attack.mitre.org/detectionstrategies/DET0099#AN0276
- R950 / R1328: https://attack.mitre.org/detectionstrategies/DET0367#AN1034
- R951 / R1828: https://attack.mitre.org/detectionstrategies/DET0025#AN0071
- R952 / R1800: https://attack.mitre.org/detectionstrategies/DET0440#AN1220
- R953 / R1830: https://attack.mitre.org/detectionstrategies/DET0466#AN1288
- R954 / R1492: https://attack.mitre.org/detectionstrategies/DET0394#AN1109
- R955 / R1399: https://attack.mitre.org/detectionstrategies/DET0394#AN1108
- R956 / R2074: https://attack.mitre.org/detectionstrategies/DET0574#AN1583
- R957 / R2681: https://attack.mitre.org/detectionstrategies/DET0787#AN1919
- R958 / R2672: https://attack.mitre.org/detectionstrategies/DET0357#AN1018
- R959 / R2752: https://attack.mitre.org/detectionstrategies/DET0357#AN1015
- R960 / R2812: https://attack.mitre.org/detectionstrategies/DET0928#AN2084
- R961 / R1635: https://attack.mitre.org/detectionstrategies/DET0006#AN0015
- R962 / R2843: https://attack.mitre.org/detectionstrategies/DET0485#AN1332
- R963 / R2948: https://github.com/SigmaHQ/sigma/blob/ccbb0369507f796db0b0ae6854c8a2be471b9d84/rules-emerging-threats/2024/Exploits/CVE-2024-3094/proc_creation_lnx_exploit_cve_2024_3094_sshd_child_process.yml
- R964 / R1912: https://attack.mitre.org/detectionstrategies/DET0503#AN1391
- R965 / R2596: https://attack.mitre.org/detectionstrategies/DET0204#AN0580

Next unallocated ID: **R966**, subject to live branch inspection.
