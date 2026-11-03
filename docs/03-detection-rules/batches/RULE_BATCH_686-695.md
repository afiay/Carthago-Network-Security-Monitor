# CARTHAGO — R686–R695 independent workbook-derived source candidates

**SOURCE CANDIDATE — UNVERIFIED. xUnit authored; 0 tests, 0 builds and 0 packet replays executed.**

## Branch and provenance

Directly extends `feature/carthago-reliability-hardening` after R685. Candidate research is taken from the owner-provided `CARTHAGO_R586-R3085_2500_UNIFIED_PRIORITY_RULE_RESEARCH_AND_TESTS(1).xlsx`; no new web research was performed. Original workbook IDs remain research identities while R686–R695 are new sequential Carthago IDs.

| Carthago | Workbook / rank | Narrow observable rule | Non-overlap / evidence boundary |
| --- | --- | --- | --- |
| R686 | R2365 / 1678 | Bitsadmin-associated cleartext HTTP GET to direct public IP | R093 is PowerShell-specific download cradle; this requires exact Bitsadmin process attribution and an HTTP Host IP equal to destination. The original Sigma command-line transfer flags and local output path are unavailable; an HTTP GET is not proof of file download or execution. |
| R687 | R2337 / 2153 | Certutil-associated cleartext HTTP GET to direct public IP | R633 sees Certutil on a limited service-port set without HTTP semantics; this requires parser-labeled cleartext GET and direct-IP host equality. Certutil URL-cache/verify flags and filesystem destination are not observable; no completed download is inferred. |
| R688 | R2874 / 2200 | Wget-associated cleartext HTTP GET to direct public IP | R212 covers curl/wget script-to-shell context; this requires Wget process attribution and IP-literal destination, without shell execution. The original suspicious local output-path condition is unavailable; observed request does not establish saved content. |
| R689 | R2284 / 2121 | Curl-associated contact to selected file-sharing service host | R111 requires posting/upload context and R657 requires Pastebin API POST; this is a curl-specific GET/TLS contact signal, with no upload predicate. The source rule requires command-line download/output flags and suspicious extension; SNI/HTTP host contact alone does not prove a file download. |
| R690 | R3060 / 2271 | Curl-associated cleartext HTTP GET for suspicious file extension | R689 keys on file-sharing host families; this requires a parser-observed URI whose path ends in a selected executable/script-like extension. Curl output-file arguments and local filesystem destination are unavailable; request path does not prove content was received or written. |
| R691 | R2300 / 1660 | Private SMB listener SYN-ACK response to a public client | R351 requires parser-attributed NTLM and R026 observes SMB/RPC internet traffic; this specifically requires server-to-public-client TCP SYN-ACK from source port 445. The original Event 4624 successful logon is not available. SYN-ACK proves only a TCP listener response, not SMB authentication or successful login. |
| R692 | R3036 / 790 | Outlook-associated external WebDAV request or SMB SYN attempt | R174 detects inbound WebDAV abuse and R665 Explorer WebDAV→SMB sequence; this requires Outlook process/PID and external resource traffic. The original registry-access evidence is unavailable. Network activity does not prove CVE-2023-23397 exploitation, NTLM disclosure, or credential capture. |
| R693 | R2098 / 1575 | SnippingTool-associated external SMB SYN or cleartext HTTP GET | R692 is Outlook-specific and R665 Explorer-specific; this rule requires SnippingTool process attribution and an external remote-resource attempt. The ms-screensketch URI handler and filePath command-line value are not observed. Do not claim CVE exploitation, SSRF or NTLM leakage. |
| R694 | R2543 / 2177 | NPS npc.exe process associated with external TCP egress | R263's proxy-process list excludes npc.exe; this candidate is exact-process external TCP evidence for the NPS client binary. No NPS command line, vkey/password, server mode, proxy handshake or actual traffic forwarding is observed. |
| R695 | R2867 / 2196 | IOX iox.exe process associated with external TCP egress | R263's existing proxy-process list excludes iox.exe; this candidate preserves the distinct IOX tool identity. No fwd/proxy command-line mode, listener role, SOCKS semantics, tunnel establishment or forwarded bytes are observed. |

## Detection contracts

- R686–R688 require private→public, parser-labeled cleartext HTTP GET, a positive best-effort local PID/name, and an IP-literal HTTP Host equal to the packet destination. They preserve Bitsadmin, Certutil and Wget as separate source identities. The source Sigma command-line flags, local output path and process-creation provenance are unavailable, so these events **do not mean a file was downloaded**.
- R689 requires `curl.exe/curl` and either cleartext GET or TLS SNI for a bounded list of file-sharing provider domains from the original source. It does not require or infer upload/download semantics. R690 is independent: cleartext GET by Curl where the URI path ends in a selected executable/script-like extension, regardless of provider.
- R691 converts the source successful SMB-logon research into the only packet fact Carthago can independently support here: a private TCP/445 listener emitted SYN-ACK to a public client. It **does not** claim Event 4624, SMB authentication or a completed login.
- R692 requires an attributed Outlook process plus either a WebDAV method parsed by existing `NetworkBatch171175Evidence.DavHttp` or an external TCP SYN to SMB/445. The source CVE rule is based on Windows registry-object access; that signal is absent, so no CVE-2023-23397 or NTLM credential-loss claim is made.
- R693 similarly requires `SnippingTool.exe` plus an external SMB SYN or parser-labeled cleartext HTTP GET. Carthago does not observe the `ms-screensketch:filePath` command line, so it cannot establish CVE-2026-33829 exploitation, SSRF or NTLM hash leakage.
- R694 and R695 require exact `npc.exe` or `iox.exe`, positive PID and private→public TCP flow. Existing R263 does not contain these process names. These are *named proxy-capable process egress* candidates, not evidence of actual NPS/IOX mode, proxy authentication, listener creation or forwarded traffic.

All ten rules are **Candidate / Shadow**, with separate rule classes, separate predicates, separate ten-minute cooldown instances and no convergence. The shared helper only validates IP/process/host evidence. Imported `TrafficRecord` process fields remain mutable and must not be promoted to trusted process provenance without live producer validation.

## Authored xUnit — not executed

`Carthago.Tests/R686R695AdvancedAccuracyBatchTests.cs` covers positive and benign process/host/method cases, private/public boundaries, missing PID, exact file-sharing suffix handling, extension paths, SMB SYN versus SYN-ACK, Outlook WebDAV and SMB alternatives, SnippingTool resource attempts, proxy-tool process identity, replay/out-of-order/cooldown and registry Candidate/Shadow invariants. No test execution or PASS claim.

## Existing workbook sources

- R686 ← R2365, rank 1678: https://github.com/SigmaHQ/sigma/blob/ccbb0369507f796db0b0ae6854c8a2be471b9d84/rules/windows/process_creation/proc_creation_win_bitsadmin_download_direct_ip.yml
- R687 ← R2337, rank 2153: https://github.com/SigmaHQ/sigma/blob/ccbb0369507f796db0b0ae6854c8a2be471b9d84/rules/windows/process_creation/proc_creation_win_certutil_download_direct_ip.yml
- R688 ← R2874, rank 2200: https://github.com/SigmaHQ/sigma/blob/ccbb0369507f796db0b0ae6854c8a2be471b9d84/rules/windows/process_creation/proc_creation_win_wget_download_susp_locations.yml
- R689 ← R2284, rank 2121: https://github.com/SigmaHQ/sigma/blob/ccbb0369507f796db0b0ae6854c8a2be471b9d84/rules/windows/process_creation/proc_creation_win_curl_download_susp_file_sharing_domains.yml
- R690 ← R3060, rank 2271: https://github.com/SigmaHQ/sigma/blob/ccbb0369507f796db0b0ae6854c8a2be471b9d84/rules/windows/process_creation/proc_creation_win_curl_susp_download.yml
- R691 ← R2300, rank 1660: https://github.com/SigmaHQ/sigma/blob/ccbb0369507f796db0b0ae6854c8a2be471b9d84/rules/windows/builtin/security/account_management/win_security_successful_external_remote_smb_login.yml
- R692 ← R3036, rank 790: https://github.com/SigmaHQ/sigma/blob/ccbb0369507f796db0b0ae6854c8a2be471b9d84/rules-emerging-threats/2023/Exploits/CVE-2023-23397/win_security_exploit_cve_2023_23397_outlook_remote_file_query.yml
- R693 ← R2098, rank 1575: https://github.com/SigmaHQ/sigma/blob/ccbb0369507f796db0b0ae6854c8a2be471b9d84/rules-emerging-threats/2026/Exploits/CVE-2026-33829/proc_creation_win_exploit_cve_2026_33829.yml
- R694 ← R2543, rank 2177: https://github.com/SigmaHQ/sigma/blob/ccbb0369507f796db0b0ae6854c8a2be471b9d84/rules/windows/process_creation/proc_creation_win_pua_nps.yml
- R695 ← R2867, rank 2196: https://github.com/SigmaHQ/sigma/blob/ccbb0369507f796db0b0ae6854c8a2be471b9d84/rules/windows/process_creation/proc_creation_win_pua_iox.yml

Next unallocated source candidate block after successful publication: **R696–R705**. Frozen holdouts, UI automation and existing validated confidence floors remain unchanged.
