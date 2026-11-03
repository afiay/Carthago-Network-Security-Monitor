# CARTHAGO — R626–R635 independent workbook-derived candidate detectors

**SOURCE CANDIDATE — UNVERIFIED. 0 builds, 0 xUnit tests, 0 replays executed.**

## Provenance and branch

Work on `feature/carthago-reliability-hardening` exclusively, extending the live contiguous registry R001–R625. Source inventory: `CARTHAGO_R586-R3085_2500_UNIFIED_PRIORITY_RULE_RESEARCH_AND_TESTS(1).xlsx`. No new web research. Preserve original workbook IDs as research provenance. Ten independent C# classes, predicates and instance-owned cooldowns; **no convergence**.

## Ten-rule matrix

| Carthago ID | Workbook ID / rank | Independent predicate | Closest existing rule / non-overlap | Evidence limits |
| --- | --- | --- | --- | --- |
| R626 | R2094 / 1077 | WordPress wp2shell plugin HTTP access | R087 generic webshell upload; here a particular wp2shell plugin access request, not a proved webshell installation | Parsed cleartext HTTP request; no HTTP status or server-side exploit confirmation |
| R627 | R2286 / 1659 | WebLogic keystore webshell-like URI request | R087 webshell upload; here direct WebLogic keystore path request without upload inference | Parsed cleartext HTTP request; no HTTP status or server-side exploit confirmation |
| R628 | R3031 / 1845 | Exchange ProxyToken RulesEditor NewObject request | R319 generic ECP probe, R616 ECP SetObject Reset; this matches a separate RulesEditor NewObject request | Parsed cleartext HTTP request; no HTTP status or server-side exploit confirmation |
| R629 | R2475 / 1741 | Hybrid Connection Manager DNS lookup to Azure Service Bus | R620 LocaltoNet domain alone; here an exact local process + DNS query conjunction, benign Azure connector likely | DNS QNAME with best-effort local PID/name; no authenticated process or successful connection |
| R630 | R2215 / 1626 | PowerShell client outbound WinRM to public IP | R074 WinRM sweep and R027 generic admin egress; here attributed PowerShell client on WinRM port to public IP | Best-effort process-to-flow attribution; not a trusted endpoint process event |
| R631 | R2221 / 1629 | Unusual command interpreter outbound RDP | R073 RDP lateral burst and R124 ingress exposure; this is specific unusual local process to a public RDP endpoint | Best-effort process-to-flow attribution; not a trusted endpoint process event |
| R632 | R2238 / 1638 | Svchost RDP loopback flow candidate | R518 generic reverse SSH tunnel; this only observes the characteristic local loopback 3389 source-flow shape | Loopback frame capture reachability uncertain; no SSH tunnel proof |
| R633 | R2958 / 2241 | Certutil external TCP request to unusual service | R266 first-seen process egress; this matches exact certutil basename and specific four ports regardless of first seen | Best-effort process-to-flow attribution; not a trusted endpoint process event |
| R634 | R2963 / 2243 | Windows script host external TCP other than HTTP/DNS | R268 already matches script interpreter HTTP/DNS; this only matches non-HTTP/non-DNS external TCP | Best-effort process-to-flow attribution; not a trusted endpoint process event |
| R635 | R2350 / 1420 | Nonbrowser Windows system host to public dead-drop service | R104 first-time cloud uploads, R110 service API egress; this requires a local nonbrowser process plus TLS SNI to a particular public service, no dead-drop attribution | Best-effort process-to-flow attribution; not a trusted endpoint process event |

## Evidence and implementation boundaries

- R626–R628: existing `WebSignatureRequestEvidence.TryGet` ensures coherent cleartext HTTP, method, URI, endpoints, non-TLS, bounded sizes. R626 requires the exact WordPress `wp2shell_` plugin path plus query; R627 requires WebLogic `/config/keystore/` with a `.js*` suffix; R628 requires POST and Exchange RulesEditor `InboxRules.svc/NewObject`. No response-status, installation or exploitation inference.
- R629: `DnsSignatureRequestEvidence.TryGetQuery` plus best-effort `ProcessId/ProcessName` association. This may match normal Azure Hybrid Connection Manager operation; Shadow/Low by default, not a malicious finding. The exact DNS producer does **not** independently attest process origin.
- R630–R631 and R633–R635 use `NetworkBatch266270Evidence.ProcessEgress`, already scoped to private→public typed TCP flows, plus independent process/port/domain conjunction. R630 requires PowerShell on WinRM egress; R631 requires an explicit command-execution process and public RDP port; R633 requires certutil on the four workbook ports; R634 excludes HTTP/DNS-related common service ports to avoid R268; R635 requires a nonbrowser system process with TLS and selected historical dead-drop-capable SNI hosts.
- R632 requires `svchost.exe`, TCP source port 3389 and exact loopback peers. This is **only a local loopback RDP-shape candidate**, not proof of SSH tunnel. Loopback capture may be unavailable depending on interface. No positives asserted for a path not observed by the live capture producer.
- Cross-rule classes are **not merged**. `ProcessSignatureEvidence` is only field hygiene. Every rule has its own Shadow profile and independent `WebSignatureCooldown`: 10-minute per source+destination cooldown and 1,024-key upper bound.
- Structured evidence uses only fixed signature tags, fixed matched-condition labels and `*_unknown` outcomes. No unredacted URL, DNS query, request credential, payload, Windows username or original process path. Input `TrafficRecord.ProcessName` is best-effort/mutable and requires dedicated provenance validation before promotion.

## Authored xUnit scenario matrix (unexecuted)

`Carthago.Tests/R626R635AdvancedAccuracyBatchTests.cs` covers positive request/flow/query, independent benign negatives, wrong method/port, missing process ID/name, internal versus public endpoints, UDP/TCP contradiction, DNS response/false suffix, malformed Info-only HTTP, duplicate record IDs, out-of-order timestamps, cooldown, fixed/redacted evidence, process-loopback limits, and registry uniqueness. Source-only test authoring **does not establish passing tests**.

## Sources from existing workbook, not newly researched

- R626 ← R2094, workbook rank 1077: [SigmaHQ source](https://github.com/SigmaHQ/sigma/blob/ccbb0369507f796db0b0ae6854c8a2be471b9d84/rules-emerging-threats/2026/Exploits/CVE-2026-63030/web_exploit_cve_2026_63030_webshell_plugin_access.yml)
- R627 ← R2286, workbook rank 1659: [SigmaHQ source](https://github.com/SigmaHQ/sigma/blob/ccbb0369507f796db0b0ae6854c8a2be471b9d84/rules-emerging-threats/2018/Exploits/CVE-2018-2894/web_cve_2018_2894_weblogic_exploit.yml)
- R628 ← R3031, workbook rank 1845: [SigmaHQ source](https://github.com/SigmaHQ/sigma/blob/ccbb0369507f796db0b0ae6854c8a2be471b9d84/rules-emerging-threats/2021/Exploits/CVE-2021-33766/web_cve_2021_33766_msexchange_proxytoken.yml)
- R629 ← R2475, workbook rank 1741: [SigmaHQ source](https://github.com/SigmaHQ/sigma/blob/ccbb0369507f796db0b0ae6854c8a2be471b9d84/rules/windows/dns_query/dns_query_win_hybridconnectionmgr_servicebus.yml)
- R630 ← R2215, workbook rank 1626: [SigmaHQ source](https://github.com/SigmaHQ/sigma/blob/ccbb0369507f796db0b0ae6854c8a2be471b9d84/rules/windows/network_connection/net_connection_win_susp_remote_powershell_session.yml)
- R631 ← R2221, workbook rank 1629: [SigmaHQ source](https://github.com/SigmaHQ/sigma/blob/ccbb0369507f796db0b0ae6854c8a2be471b9d84/rules/windows/network_connection/net_connection_win_rdp_outbound_over_non_standard_tools.yml)
- R632 ← R2238, workbook rank 1638: [SigmaHQ source](https://github.com/SigmaHQ/sigma/blob/ccbb0369507f796db0b0ae6854c8a2be471b9d84/rules/windows/network_connection/net_connection_win_rdp_reverse_tunnel.yml)
- R633 ← R2958, workbook rank 2241: [SigmaHQ source](https://github.com/SigmaHQ/sigma/blob/ccbb0369507f796db0b0ae6854c8a2be471b9d84/rules/windows/network_connection/net_connection_win_certutil_initiated_connection.yml)
- R634 ← R2963, workbook rank 2243: [SigmaHQ source](https://github.com/SigmaHQ/sigma/blob/ccbb0369507f796db0b0ae6854c8a2be471b9d84/rules/windows/network_connection/net_connection_win_wscript_cscript_outbound_connection.yml)
- R635 ← R2350, workbook rank 1420: [SigmaHQ source](https://github.com/SigmaHQ/sigma/blob/ccbb0369507f796db0b0ae6854c8a2be471b9d84/rules/windows/network_connection/net_connection_win_domain_dead_drop_resolvers.yml)

## Verification / next GA

Pending: actual build, named xUnit suite, trustworthy Windows process-to-packet correlation, request-field live reachability, and loopback capture representability. All withheld until owner explicitly authorizes tests. Do not modify frozen holdouts, design automation or main branch. Next unallocated IDs: R636–R645.
