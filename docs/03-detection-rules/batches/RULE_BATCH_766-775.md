# CARTHAGO — R766–R775 independent workbook-derived source candidates

**SOURCE CANDIDATE — UNVERIFIED. xUnit authored; 0 tests, 0 builds, 0 replay runs.**

## Admission basis

Direct work on `feature/carthago-reliability-hardening`. At the start of this rerun the live branch was `72b34f3e6af09ca4783fe904f377eacbdb29cdda` with **765 registered rules / 765 unique IDs**, ending at R765.

The canonical research workbook was read from the user's persistent ChatGPT Library:

- file_id: `file_00000000402c81f4bb16133abf63e951`
- library_file_id: `libfile_3dce02a91bac8191a6896c8e24e04839`
- filename: `CARTHAGO_R586-R3085_2500_UNIFIED_PRIORITY_RULE_RESEARCH_AND_TESTS(1).xlsx`

No replacement workbook was created and no broad web re-research was performed.

Exact or renamed duplicates were rejected before authoring. In particular, workbook candidates for ScreenConnect SetupWizard, ReGeorg, SolarWinds Orion auth bypass, WebLogic JNDI, Confluence upload traversal, Grafana traversal and Rejetto HFS already had specialized live counterparts (R587, R601, R602, R603, R605, R595 and R590 respectively).

Every rule below remains a separate ID/class/predicate/state/test/documentation unit. `Research766Evidence` contains only shared field validation and process/protocol classification.

| Carthago | Workbook / rank | Observable predicate retained | Non-overlap / limitation |
|---|---:|---|---|
| R766 | R2855 / 440 | `osascript` + three high-entropy DNS queries to a public resolver for one root in 120s | R763/R764 own ESXi/Linux DNS process families. No encoded-content or tunneling-success claim. |
| R767 | R2774 / 2479 | PowerShell/rundll32/Windows Python + three high-entropy public-resolver DNS queries for one root in 120s | Process family is disjoint from R766/R763/R764. No command line, authoritative-server ownership or C2 success is inferred. |
| R768 | R1968 / 1509 | `osascript` + 12 outbound SYN/small-UDP observations to one public peer/port in 10s | R731/R732 cover Windows/Linux network-tool families. This macOS-oriented candidate does not assert throughput or DoS impact. |
| R769 | R2811 / 2482 | Perl/Ruby + 12 parser-backed cleartext HTTP GET/POST requests to one public peer in 10s | R739 covers curl/wget/Python. Response volume and process novelty are unavailable. |
| R770 | R2817 / 2485 | regsvr32/mshta/wscript/cscript + 8 HTTP-request or TLS/443 payload observations to one public peer in 20s | Replaces unavailable “uncommon/previously unseen process” baseline with a narrow LOLBIN family. No C2 semantics are asserted. |
| R771 | R2744 / 2432 | public source + 12 coherent UDP/161 observations to one private host in 10s | No SNMP PDU/OID decoder exists here, so GETBULK/GETNEXT/community-string/MIB-dump claims are explicitly excluded. |
| R772 | R2699 / 2312 | 20 payload-bearing packets to one private OT-associated service port in 10s | Device dropout, malformed PDU semantics, poll failure, resource exhaustion and DoS impact are unavailable. |
| R773 | R2771 / 2372 | one private source sends coherent UDP/161 to 4 distinct private targets in 30s | Distinct from R771's public-source same-target burst. No OID or authorization semantics are inferred. |
| R774 | R1917 / 1502 | `screensharingd` + private TCP/5900 SYN-ACK to a public client | R759 owns Linux VNC-process exposure; R648 is transport-only VNC exposure. Authentication/session outcome remains unknown. |
| R775 | R2039 / 1514 | `sshd`-attributed private TCP/22 SYN-ACK to public client followed within 90s by zsh/osascript/curl/python3 egress from same host | R765 uses a generic public service SYN trigger. R775 requires an sshd-attributed listener response and a macOS-oriented follow-on process family. |

## Evidence and state boundaries

- Process attribution is best-effort local tuple enrichment, not authenticated endpoint telemetry.
- R766/R767 use parser-backed DNS only and redact the full query from the emitted event after matching.
- R768 uses the existing bounded SYN/small-UDP flood-shape primitive and exact `osascript` attribution.
- R769 uses parser-backed cleartext HTTP only; it does not inspect encrypted HTTPS.
- R770 can count either parser-backed cleartext HTTP requests or typed TLS/443 payload observations, but only when attributed to the narrow Windows LOLBIN family.
- R771/R773 intentionally stop at coherent UDP/161 shape because SNMP PDU/OID/community-string semantics are not currently decoded.
- R772 is rate-only on bounded OT-associated service ports `102, 502, 20000, 44818, 47808, 50000`; it does not classify malformed PDUs or device degradation.
- R775 state is keyed by the private host and expires after 90 seconds; a different host cannot satisfy the follow-on stage.
- All ten use independent cooldown state. Raw `Info`, URL query secrets and DNS labels are not emitted by rule-specific evidence.

## Authored xUnit source — not executed

`Carthago.Tests/R766R775AdvancedAccuracyBatchTests.cs` contains:

- positive shaped scenarios for all ten rules;
- rule-specific benign near misses;
- missing process-attribution checks for process-gated rules;
- contradictory transport/parser failures;
- duplicate-ID, reverse-time and expiry checks for stateful candidates;
- cooldown suppression and recovery for every rule;
- raw-info, URL-query and DNS-label privacy assertions;
- explicit non-convergence for macOS vs Windows DNS families, Perl/Ruby vs Python HTTP, LOLBIN vs PowerShell web traffic, public-vs-internal SNMP, Linux-vs-macOS VNC, and macOS SSH follow-on process family;
- Candidate / Shadow registration and registry uniqueness assertions.

**0 tests executed — 0 builds — 0 CI — 0 GitHub Actions dispatches — 0 packet captures — 0 replays — 0 holdouts.**

## Workbook source references

- R766 ← R2855 (rank 440): https://attack.mitre.org/detectionstrategies/DET0400#AN1123
- R767 ← R2774 (rank 2479): https://attack.mitre.org/detectionstrategies/DET0400#AN1121
- R768 ← R1968 (rank 1509): https://attack.mitre.org/detectionstrategies/DET0343#AN0971
- R769 ← R2811 (rank 2482): https://attack.mitre.org/detectionstrategies/DET0053#AN0145
- R770 ← R2817 (rank 2485): https://attack.mitre.org/detectionstrategies/DET0053#AN0144
- R771 ← R2744 (rank 2432): https://attack.mitre.org/detectionstrategies/DET0453#AN1249
- R772 ← R2699 (rank 2312): https://attack.mitre.org/detectionstrategies/DET0723#AN1856
- R773 ← R2771 (rank 2372): https://attack.mitre.org/detectionstrategies/DET0787#AN2186
- R774 ← R1917 (rank 1502): https://attack.mitre.org/detectionstrategies/DET0178#AN0506
- R775 ← R2039 (rank 1514): https://attack.mitre.org/detectionstrategies/DET0596#AN1639

After successful atomic publication, the next contiguous candidate block is **R776–R785**, subject to a fresh live-branch and registry check.
