# CARTHAGO — R876–R885 observable research candidates

**SOURCE CANDIDATE — UNVERIFIED. xUnit source authored before implementation; 0 tests, builds, CI, replays or holdouts executed.**

Research input: owner workbook `CARTHAGO_R586-R3085_2500_UNIFIED_PRIORITY_RULE_RESEARCH_AND_TESTS(1).xlsx`. These are deliberately narrower wire-observable subsets of research that often expects endpoint command lines, asset baselines, authenticated principals, Docker API responses, process ancestry or decoded OT payloads. They are **not** implementation or validation of those complete source analytics. The 10 rules are independent Candidate/Shadow detectors, `MinimumConfidence=80`, bounded per-rule windows and per-instance 10-minute cooldown. Existing rule predicates remain unchanged.

| CARTHAGO ID | Owner-workbook origin | Observable positive shape | Missing / unproven evidence |
|---|---|---|---|
| R876 | R2785 | Same private DNS resolver sends three distinct public IPv4 A answers for one name at TTL ≤30s to one client; client SYN to the most recent answer within 90s | Endpoint process lineage, malicious fast-flux ownership, trusted baseline; distinct from R844's answer churn alone and R837's conflicting resolver path |
| R877 | R2802 | Same private client sends typed HTTP/2375 POST `/containers/create` and later `/containers/{id}/start` to one daemon within 60s | Docker response, image attributes, container ID linkage, successful start, authorization |
| R878 | R2698 | Public SYN then application-sized TCP data to same private SSH/22 peer and source port within 40s | SSH login success, remote identity, protected OT role, legitimate VPN policy |
| R879 | R2804 | Public Telnet/23 SYN then same private host's busybox-attributed public TLS/8443 packet within 60s | Telnet command, service login, process spawn, causality |
| R880 | R1390 | Public HTTP/80 GET to `/cgi-bin/.%2e/` then same client/server POST to `/admin/upload` within 45s | 5xx/WAF block, server file write, spawned process, vulnerability exploitation |
| R881 | R2813 | Public FTP/21 SYN inbound then same private host UDP/69 traffic to another private device within 60s | FTP/TFTP opcodes, filename, completed transfer, engineering-workstation approval |
| R882 | R1831 | esxcli-attributed public script-path HTTP GET then busybox-attributed HTTP check-in POST from same host to a *different* public IP within 60s | ESXi identity, script execution, parent/child relationship, C2 |
| R883 | R1834 | vmware-vmx-attributed TLS/8443 packets to three distinct public peers under one SNI in 90s | Guest identity, operational approval, decrypted content, C2 |
| R884 | R2809 | git-attributed HTTP GET requests for four distinct `.git/objects/` URIs on same private host in 60s | SaaS identity, repo ACL, confidential contents, meaningful exfiltration volume |
| R885 | R2694 | Public CGI diagnostic POST then same private host's bash-attributed public TLS/8443 connection to a different peer within 60s | Linux shell spawn, process ancestry, successful exploit or C2 |

## Evidence boundaries and independence

- Selected ten original research IDs not already referenced in expansion sources, and screened related rule classes for behavior overlap. R876 adds latest-answer client SYN to low-TTL same-resolver churn; R877 detects write-action API request order rather than R821's Docker listing requests; R878 does not infer SSH login or the east-west sequence of R807; R880 is a typed suspicious-request pair rather than R825's image upload/served GET or R839's web-worker egress.
- Every sequence uses coherent typed IPv4, transport flags, packet ID, unique state, strictly increasing UTC and bounded correlation windows. Mixed protocol, missing peer, raw `Info`-only evidence, duplicate packet IDs, reverse timestamps, expired stages and incorrect peers fail closed. No rule shares an alert or temporal aggregation state with another rule.
- Returned evidence contains only the original workbook ID, static matched-condition label, and unknown-outcome marker. No URI, DNS answer, SNI, user identity, payload, command or credential is copied into event evidence.
- Known false-positive sources: CDN DNS changes, maintenance and legitimate SSH/Telnet sessions, Docker administration, web application testing, firmware transfers, hypervisor service checks and normal Git clone/fetch operations. Candidate/Shadow status is required until trusted source producers, benign controls, parser tests, live packet capture, performance and holdout replay results exist.

## Tests authored but not executed

`Carthago.Tests/R876R885ObservableCandidateBatchTests.cs` defines ten source-specific positives, benign near misses, missing/contradictory transport, duplicate IDs, reverse UTC and expired first observations, cooldown recovery, no raw Info exposure, cross-rule independence, exact latest-DNS-answer SYN matching, distinct ESXi second public peer, and unique Candidate/Shadow registrations. **Compilation and pass/fail status are unknown**.

## Owner-workbook original research URLs

- R876 / R2785 — https://attack.mitre.org/detectionstrategies/DET0485#AN1331
- R877 / R2802 — https://attack.mitre.org/detectionstrategies/DET0249#AN0693
- R878 / R2698 — https://attack.mitre.org/detectionstrategies/DET0803#AN2257
- R879 / R2804 — https://attack.mitre.org/detectionstrategies/DET0928#AN2085
- R880 / R1390 — https://attack.mitre.org/detectionstrategies/DET0080#AN0220
- R881 / R2813 — https://attack.mitre.org/detectionstrategies/DET0745#AN2229
- R882 / R1831 — https://attack.mitre.org/detectionstrategies/DET0228#AN0640
- R883 / R1834 — https://attack.mitre.org/detectionstrategies/DET0425#AN1192
- R884 / R2809 — https://attack.mitre.org/detectionstrategies/DET0263#AN0732
- R885 / R2694 — https://attack.mitre.org/detectionstrategies/DET0767#AN2141

**Next source candidate ID: R886. SOURCE CANDIDATE — UNVERIFIED.**
