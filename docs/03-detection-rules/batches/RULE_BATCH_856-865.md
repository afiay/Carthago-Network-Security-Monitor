# CARTHAGO — R856–R865 independent observable source candidates

**SOURCE CANDIDATE — UNVERIFIED. No tests, builds, CI, replay or holdouts executed.**

Owner workbook: CARTHAGO_R586-R3085_2500_UNIFIED_PRIORITY_RULE_RESEARCH_AND_TESTS(1).xlsx. Each research source is adapted only to observable typed packet data and optional local process attribution. All ten classes preserve **Candidate / Shadow**, a **minimum confidence of 80**, independent per-rule state and ten-minute cooldown. Existing detection rules remain unchanged.

| CARTHAGO ID | Workbook origin | Positive packet/process shape | Explicitly unobservable or unproven |
|---|---|---|---|
| R856 | R2865 | frpc-attributed public TCP/7000 SYN then >=512B payload to same peer in 30s | No FRP command line, reverse relay configuration or connection completion |
| R857 | R2691 | awk-attributed public TLS/8443 payload of 720–820B | No awk script, decoded bytes, OT role or process intent |
| R858 | R1169 | Five hostd-attributed TLS/9443 large packets totaling >=9000B to one public peer in 30s | No ESXi identity, encrypted contents or completed exfiltration |
| R859 | R1265 | Public-to-private SSH/22 SYN then same host's esxcli-attributed public TLS/8443 packet in 60s | No successful login, ESXi host role, command execution or causal attribution |
| R860 | R1263 | Three regsvr32-attributed UDP/1194 payload packets to three public IPs in 60s | No DLL invocation, child process, external upload or exfiltration |
| R861 | R1398 | Thunderbird-attributed HTTP/80 GET whose URI contains .zip then bash-attributed public TLS/8443 to different peer in 60s | No attachment open, parent/child lineage, downloaded file or execution |
| R862 | R1338 | Same rundll32-attributed PID sends public UDP/53 DNS TXT query then TLS/443 packet with SNI exactly matching that query in 60s | No TXT response content, DNS tunneling, executed code or C2 |
| R863 | R1519 | Five rsync-attributed public TCP/873 payload packets totaling >=10000B to same peer in 30s | No file-read, replication success, protected data or exfiltration |
| R864 | R1140 | Three docker-proxy-attributed public TCP/1080 SYNs to three public IPs within 60s | No container provenance, installed proxy or proxyjacking |
| R865 | R2952 | curl-attributed HTTP/80 GET ending in .cmd followed by cmd-attributed public TCP/8443 SYN to a different IP within 60s | No batch execution, process ancestry, download success or malicious verdict |

## Evidence, admission and independence

- Reviewed used workbook origins, existing rule classes and live IDs before selection; no duplicate workbook origin among this ten-rule batch. Similar tool names in older rules implement different packet/port/correlation predicates, not converged alerts.
- Missing IPv4 peers, invalid transport markers, contradictory TCP/UDP flags, invalid typed HTTP/DNS/TLS, repeated packet IDs, reverse UTC order, expired stage windows and incorrect destinations must fail closed. Correlation remains in bounded, individual rule instances.
- Local process name and PID are opportunistic enrichment, not verified process start or command-line evidence. Public network packets cannot establish execution, host roles, credential use, authorization, malware identity, transfer completion or encrypted TLS content.
- Evidence returned to the UI is static: workbook identifier, the matched predicate name and an explicit unknown-outcome label. No raw Info, downloaded URI, host name, SNI, DNS question, payload, command, token or source credentials are promoted into event evidence.
- R857 is a one-packet candidate; R858/R863 use bounded unique-packet counts and aggregate sizes; R860/R864 count distinct peers; other candidates correlate two typed legs, with same-peer or different-peer requirements as documented.
- Before promotion, require runtime producers, benign samples, packet replay, latency and performance budgets, precision controls and holdout evaluation. None were run during this source-only batch.

## Authored tests — not executed

Carthago.Tests/R856R865ObservableCandidateBatchTests.cs covers ten source-specific positive cases, negative near misses, invalid/missing peers, contradictory protocol flags, duplicate IDs, expired stages, cooldown and recovery, independent rule predicates, exact DNS TXT/SNI coupling, same-peer frpc correlation, no raw Info in event evidence and unique Candidate/Shadow registry entries. **Compilation and test results are unknown.**

## Direct research references from owner workbook

- R856 / R2865: https://github.com/SigmaHQ/sigma/blob/ccbb0369507f796db0b0ae6854c8a2be471b9d84/rules/windows/process_creation/proc_creation_win_pua_frp.yml
- R857 / R2691: https://attack.mitre.org/detectionstrategies/DET0793#AN2152
- R858 / R1169: https://attack.mitre.org/detectionstrategies/DET0512#AN1416
- R859 / R1265: https://attack.mitre.org/detectionstrategies/DET0596#AN1640
- R860 / R1263: https://attack.mitre.org/detectionstrategies/DET0028#AN0080
- R861 / R1398: https://attack.mitre.org/detectionstrategies/DET0115#AN0321
- R862 / R1338: https://attack.mitre.org/detectionstrategies/DET0348#AN0988
- R863 / R1519: https://attack.mitre.org/detectionstrategies/DET0348#AN0989
- R864 / R1140: https://attack.mitre.org/detectionstrategies/DET0028#AN0083
- R865 / R2952: https://github.com/SigmaHQ/sigma/blob/ccbb0369507f796db0b0ae6854c8a2be471b9d84/rules/windows/process_creation/proc_creation_win_cmd_curl_download_exec_combo.yml

**Next candidate ID: R866. SOURCE CANDIDATE — UNVERIFIED.**
