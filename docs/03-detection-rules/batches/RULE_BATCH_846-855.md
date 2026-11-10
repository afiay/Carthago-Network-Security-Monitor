# CARTHAGO — R846–R855 independent observable source candidates

**SOURCE CANDIDATE — UNVERIFIED. No tests, builds, CI, replay or holdout work executed.**

Original owner research workbook: CARTHAGO_R586-R3085_2500_UNIFIED_PRIORITY_RULE_RESEARCH_AND_TESTS(1).xlsx. Allocated CARTHAGO IDs are independent of workbook IDs. All ten classes have separate identities and independent state where needed. All remain **Candidate / Shadow** with the **80% confidence floor**.

| New ID | Workbook ID | Concrete typed packet/process predicate | Explicit limitation |
|---|---|---|---|
| R846 | R2904 | Locally attributed dialer.exe initiates public TCP/443 SYN | No injection, credential theft, C2 or completed connection |
| R847 | R2956 | Locally attributed addinutil.exe initiates public TCP/8443 SYN | Best-effort process attribution; no execution outcome |
| R848 | R2979 | Locally attributed legacy eqnedt32.exe initiates public TCP/80 SYN | No malicious document, CVE exploitation or connection completion |
| R849 | R1574 | Four Python-sourced TCP/4444 payloads to one public peer in 30s, spaced 2–6s and within 64 bytes of size | Cadence is not proof of staging, file chunking, exfiltration or C2 |
| R850 | R1116 | Public SYN to private OpenSLP/427 then that host's internal SSH/22 SYN inside 60s | No ESXi identity, OpenSLP exploit, hostd crash or authenticated SSH |
| R851 | R1562 | Public SSH/22 ingress SYN then bash/sh public TCP/8443 SYN from same private host | No accepted SSH login, shell lineage or command execution |
| R852 | R1204 | Five PowerShell TCP/443 payloads (at least 10,000 aggregate packet-payload bytes) to content.dropboxapi.com SNI in 30s | No decrypted upload, cloud account, result or exfiltration verdict |
| R853 | R2702 | One internal TCP/1883 source/collector endpoint pair appears with two canonical Ethernet source MACs inside 60s | No enrolled identity, MQTT payload inspection, measurement divergence or spoofing confirmed |
| R854 | R1333 | Same PowerShell PID has public TCP/8443 SYNs with Wi-Fi and Cellular network-type labels within 90s | Untrusted labels; no physical interface change or exfiltration proof |
| R855 | R1222 | Five hostd/vpxa-attributed cleartext HTTP POST packets to /api/* at one public TCP/8080 peer in 20s | No verified ESXi role, policy violation, transferred file or security outcome |

## Admission and scope

- Source ID screening excluded previously assigned workbook origins and reused rule classes. These are adapted **observable subsets** of originals, not full detection strategies. Existing rules keep their behavior unchanged. There is no convergence, shared alert state or promotion.
- Missing, contradictory or malformed packet fields fail closed. Correlation windows are per-rule and bounded with monotonic UTC timestamps, packet-ID protection, expiry and cooldown. R846–R848 are one-packet predicates; other rules use independent cadence, count, distinct or two-stage helpers.
- Process names and network-type labels are not authenticated endpoint events. Source MAC changes can result from legitimate network transitions, routing or sensor topology changes; no operator authorization or enrolled baseline is present.
- Payload sizes are packet samples, not confirmed application-transfer sizes. TLS SNI is metadata, not decrypted content. Incoming SYNs do not prove successful login or exploitation.
- Custom detection evidence contains only static workbook IDs, matched-condition tags and unknown-outcome labels. No raw Info, URI, MAC, payload, secret, username or hostname is copied to custom evidence.
- Promotion requires positive/benign replay, runtime producer checks, performance and holdout review; none were performed.

## Authored xUnit source — not executed

Carthago.Tests/R846R855ObservableCandidateBatchTests.cs covers ten positive fixtures, benign near misses, contradictory TCP/UDP and missing-IP checks, repeated packet IDs, expired first stages, cooldown recovery, raw-Info exclusion, cadence irregularity, malformed MAC, rule independence and registry Candidate/Shadow assertions. **Compilation and test results remain unknown.**

## Direct references from owner workbook

- R846 / workbook R2904: https://github.com/SigmaHQ/sigma/blob/ccbb0369507f796db0b0ae6854c8a2be471b9d84/rules/windows/network_connection/net_connection_win_dialer_initiated_connection.yml
- R847 / workbook R2956: https://github.com/SigmaHQ/sigma/blob/ccbb0369507f796db0b0ae6854c8a2be471b9d84/rules/windows/network_connection/net_connection_win_addinutil_initiated.yml
- R848 / workbook R2979: https://github.com/SigmaHQ/sigma/blob/ccbb0369507f796db0b0ae6854c8a2be471b9d84/rules/windows/network_connection/net_connection_win_eqnedt.yml
- R849 / workbook R1574: https://attack.mitre.org/detectionstrategies/DET0213#AN0597
- R850 / workbook R1116: https://attack.mitre.org/detectionstrategies/DET0118#AN0329
- R851 / workbook R1562: https://attack.mitre.org/detectionstrategies/DET0596#AN1638
- R852 / workbook R1204: https://attack.mitre.org/detectionstrategies/DET0548#AN1511
- R853 / workbook R2702: https://attack.mitre.org/detectionstrategies/DET0746#AN2215
- R854 / workbook R1333: https://attack.mitre.org/detectionstrategies/DET0077#AN0212
- R855 / workbook R1222: https://attack.mitre.org/detectionstrategies/DET0131#AN0371

**Next available CARTHAGO ID: R856. SOURCE CANDIDATE — UNVERIFIED.**
