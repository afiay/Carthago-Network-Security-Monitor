# CARTHAGO — R816–R825 independent network source candidates

**SOURCE CANDIDATE — UNVERIFIED.** Authored xUnit source, **0 tests, 0 builds, 0 CI, 0 replay and 0 holdouts executed**.

Canonical owner workbook: `CARTHAGO_R586-R3085_2500_UNIFIED_PRIORITY_RULE_RESEARCH_AND_TESTS(1).xlsx` (Library `libfile_3dce02a91bac8191a6896c8e24e04839`). Original workbook IDs and newly allocated CARTHAGO IDs are separate. These ten candidate implementations are independently instantiated and remain in **Candidate / Shadow** with confidence floor **80**.

| New rule | Original workbook | Distinct typed packet/process predicate |
|---|---|---|
| R816 | R2838 | curl GET /rest/api/content/* against Confluence-labeled cleartext HTTP host; four distinct paths in 60 s |
| R817 | R1475 | curl/wget cleartext GET of .sh/.bash followed by bash/sh TLS/8443 payload to another public peer in 90 s |
| R818 | R1355 | code/code.exe TLS/443 to marketplace.visualstudio.com then same PID TCP/8443 SYN to another public peer |
| R819 | R1676 | public HTTP/80 GET /api/config/export to private host then UDP/69 egress from that host to public peer |
| R820 | R1619 | Safari cleartext GET of .js resource then osascript TLS/8443 payload to another public peer |
| R821 | R2836 | docker/docker.exe HTTP/2375 GET /containers/json then GET /images/json on same private daemon |
| R822 | R2841 | docker/docker.exe HTTP/2375 POST /build then same PID public TCP/443 SYN |
| R823 | R2849 | dscl process TCP/389 SYN then TCP/636 SYN to same private directory host |
| R824 | R2857 | ping process sends three ICMPv4 Echo Requests to distinct public destination IPs in 30 s |
| R825 | R1553 | public client POST /upload/<image>.png|jpg then GET /uploads/<same-image> to same private HTTP server |

## Admission and exclusion

The workbook often proposes trusted endpoint, SaaS, cloud, Docker daemon, directory or application records not produced by `TrafficRecord`. The implementation is deliberately a **narrow packet/process observation**, not an implementation of an entire MITRE analytic. Each rule uses coherent transport fields, a local process only when present, a bounded UTC correlation window, packet-ID provenance, per-rule state and ten-minute cooldown. The two-stage rules have no required HTTP+TLS combination on a single packet; their metadata allows both observation stages through the runtime selector.

Original candidates requiring unavailable authentication, actor identity, file writes, cloud audit, firmware integrity or success status were excluded. The earlier S3 list semantic indicator (R214) and Docker build-context upload signature (R306) were screened; this batch selects different *multi-event* shapes and does not recreate their single-packet predicates. R819 and R825 are separate HTTP/UDP and upload→matching served-path sequences; R817 and R820 use different initial processes/resource types. No predicates were converged.

- **R816 / workbook R2838:** No Confluence SaaS audit/logon, privileged identity or confirmed page read.
- **R817 / workbook R1475:** No downloaded script bytes, filesystem write, child process relationship or script execution.
- **R818 / workbook R1355:** No extension installation, tunnel setup, process lineage or TCP handshake success.
- **R819 / workbook R1676:** No authentication, configuration dump content or TFTP protocol/message classification.
- **R820 / workbook R1619:** No browser child-process event, exploit, script lineage or compromise.
- **R821 / workbook R2836:** No Docker daemon authentication, API result or actual container inventory.
- **R822 / workbook R2841:** No successful image build, deployment event, Dockerfile or outbound transfer success.
- **R823 / workbook R2849:** No domain user enumeration or authenticated LDAP operation.
- **R824 / workbook R2857:** No observed ICMP replies, macOS evidence or authorization context.
- **R825 / workbook R1553:** No server file write, modified page content, upload result or actual defacement.

Potential benign positives include Confluence exports, software maintenance, IDE extension marketplaces, network configuration backups, browser automation, Docker inventory/builds, directory maintenance, diagnostics and image uploads. The source-only event evidence adds only the original workbook ID, static matching-condition tag, and unknown-outcome marker. No free-form `Info`, payload, token, credentials, raw URI or hostname are copied into custom evidence strings. Framework evidence may still include ordinary endpoint/host context for analyst use; it is not claimed to be fully redacted.

The xUnit source covers positives, negative near-misses, contradictory/missing typed fields, duplicate IDs, reversed UTC time, expired windows, cooldown recovery, raw `Info` exclusion, neighboring-rule independence and registry uniqueness/Candidate/Shadow profile. Tests **not executed at the owner's request**, so no compile, replay, false-positive or detection-quality status is asserted.

## Owner workbook MITRE source references

- R816 / workbook R2838: https://attack.mitre.org/detectionstrategies/DET0358#AN1019
- R817 / workbook R1475: https://attack.mitre.org/detectionstrategies/DET0349#AN0993
- R818 / workbook R1355: https://attack.mitre.org/detectionstrategies/DET0561#AN1549
- R819 / workbook R1676: https://attack.mitre.org/detectionstrategies/DET0233#AN0647
- R820 / workbook R1619: https://attack.mitre.org/detectionstrategies/DET0176#AN0500
- R821 / workbook R2836: https://attack.mitre.org/detectionstrategies/DET0490#AN1352
- R822 / workbook R2841: https://attack.mitre.org/detectionstrategies/DET0459#AN1261
- R823 / workbook R2849: https://attack.mitre.org/detectionstrategies/DET0129#AN0365
- R824 / workbook R2857: https://attack.mitre.org/detectionstrategies/DET0357#AN1017
- R825 / workbook R1553: https://attack.mitre.org/detectionstrategies/DET0590#AN1623

**Next unallocated CARTHAGO rule ID: R826. SOURCE CANDIDATE — UNVERIFIED.**
