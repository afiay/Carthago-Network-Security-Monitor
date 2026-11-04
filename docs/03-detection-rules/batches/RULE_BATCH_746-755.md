# CARTHAGO — R746–R755 independent workbook-derived source candidates

**SOURCE CANDIDATE — UNVERIFIED. xUnit authored; 0 tests, 0 builds, 0 replay runs.**

## Admission basis

Direct work on `feature/carthago-reliability-hardening`. Before this batch was authored, the live branch was `648d7b1854f5f1b3a1d9d23465c16adeb3f4a262` with **745 registered rules / 745 unique IDs**, ending at R745. Candidate selection used the owner-provided `CARTHAGO_R586-R3085_2500_UNIFIED_PRIORITY_RULE_RESEARCH_AND_TESTS(1).xlsx`; no new web research was required.

Higher-ranked workbook rows whose core claim depended on endpoint file-read audit, process lineage, service crashes, credential state, asset inventory, change control, configuration logs or server outcomes were skipped instead of being weakened into misleading detections. Existing specialized families were screened before selection, including generic FTP upload (R248), Windows script-host FTP (R652), generic archive/cloud staging (R500), external SSH/SCP volume (R247), external rsync (R509), cloud-storage TLS (R718), repository API POST (R717), generic macOS non-browser TLS burst (R734), VNC exposure (R648), and the R736–R745 cadence/flood rules.

Each rule below remains an independent class, predicate, state machine, test identity and registry entry. `Research746Evidence` contains only shared validation/classification helpers and one bounded two-stage correlation primitive.

## Ten-rule matrix

| Carthago | Workbook / rank | Observable predicate retained | Non-overlap / limitation |
|---|---:|---|---|
| R746 | R1149 / 112 | `hostd`/`vpxa`/`vmx` + four substantial TLS payload observations to one public peer on 4443/7443/9443/10443/12443 | Distinct from R726 TLS/443 volume and R743 raw uncommon-port cadence. No encryption algorithm, file source, unique TCP byte count, upload or exfiltration claim. |
| R747 | R1361 / 186 | 7-Zip/WinRAR process + four substantial TLS/443 payload observations to one public peer | R500 is generic archive→cloud staging logic. R747 requires exact archive-tool process attribution and does not claim archive creation, file access, destination novelty or exfiltration. |
| R748 | R1477 / 219 | `openssl`/`gpg`/`gpg2`/`age` + four substantial raw TCP payload observations to one public uncommon port | No encoder command line, key material, file input or crypto outcome is visible. Distinct from R743 by process family and from TLS-specific rules by requiring raw TCP on a different bounded port class. |
| R749 | R1215 / 353 | `busybox`/`curl`/`wget`/`ftpput`/`lftp` + parsed external FTP STOR/APPE request | R248 is generic FTP upload; R652 requires Windows script hosts. R749 is ESXi/Linux-shell-style transfer-tool attribution. Server reply, data channel, source file and completion are unknown. |
| R750 | R1765 / 887 | `osascript`/macOS Office/Preview + cloud-storage SNI + four substantial TLS/443 payload observations | R734 explicitly excludes cloud-storage host families. R718 uses Windows PowerShell/Office attribution. No local document read/xattr/upload/exfiltration claim. |
| R751 | R1768 / 888 | `osascript`/`curl`/`git`/macOS Office + GitHub/GitLab/Bitbucket SNI + four substantial TLS/443 payload observations | R717 is cleartext repository-API POST; R734 excludes repository hosts. HTTPS method, auth, git operation and exfiltration remain unknown. |
| R752 | R1724 / 1903 | `msiexec` + parser-backed cleartext HTTP GET ending in `.msi`, `.msp` or `.mst` | Command-line URL, package signature, response/download completion, installation, DLL execution and compromise are unavailable. |
| R753 | R1982 / 972 | `osascript` + three similarly sized low-volume TLS/443 payload observations at 30–90 second cadence | Deliberately low-volume so it does not become R734-style large-payload burst logic. LaunchAgent/launchd scheduling and exfiltration are not observable. |
| R754 | R1850 / 1495 | `scp`/`sftp`/`rsync` + four substantial TCP payload observations to a private peer on 22/873 | R247/R509 are external egress families. R754 is private-peer lateral-transfer shape only; file identity, authentication, direction, destination execution and compromise are unknown. |
| R755 | R1775 / 1400 | public→private VNC/5900 SYN followed within 90s by public egress from the same private host attributed to `osascript`/`zsh`/`curl`/`python3` | R648 is VNC SYN-ACK exposure. R755 is a two-stage temporal sequence. It does **not** assert VNC authentication, exploit success, service crash, process parentage, causality or compromise. |

## Evidence and state boundaries

- Process attribution is existing best-effort local tuple enrichment; it is not authenticated endpoint process telemetry.
- R746, R747, R748, R750, R751 and R754 require four unique monotonic packet IDs in bounded two-minute windows plus observed-packet-byte thresholds. Packet lengths are not TCP unique bytes.
- R749 accepts only parser-backed FTP upload semantics already used by Carthago (`ftp.stor` / `ftp.appe`) and rejects TLS/QUIC/HTTP/DNS contradictions.
- R752 requires a coherent parsed cleartext HTTP GET and strips the query from extension classification; the URI/query is not emitted into rule-specific evidence.
- R753 requires three unique observations, 30–90 second intervals, similar packet sizes and a total cadence window no longer than four minutes.
- R755 stores only a VNC ingress trigger keyed by the private host, then requires a later egress observation from that same host within 90 seconds. Different hosts, duplicate packet IDs, reverse time and expired triggers cannot combine.
- All rules use independent cooldown state. Raw `Info`, URI queries, credentials, payload contents and command lines are not emitted by these rule-specific evidence items.

## Authored xUnit source — not executed

`Carthago.Tests/R746R755AdvancedAccuracyBatchTests.cs` contains:

- positive shaped scenarios for all ten rules;
- independent benign near misses;
- missing local process attribution and contradictory transport failures;
- duplicate-ID, reverse-time and expiry controls for stateful candidates;
- VNC correlation checks for same-host requirement and missing follow-on process attribution;
- cooldown suppression and recovery for every rule;
- raw-info and private-query leakage assertions;
- explicit non-convergence between Windows-script FTP vs ESXi-style FTP, cloud-storage vs code-repository TLS, low-volume cadence vs large TLS burst, and private-peer vs external SSH/SCP transfer;
- Candidate / Shadow registration checks and full registry uniqueness.

**0 tests executed — 0 builds — 0 CI — 0 packet captures — 0 replays — 0 holdouts.**

## Workbook source references

- R746 ← R1149 (rank 112): https://attack.mitre.org/detectionstrategies/DET0503#AN1392
- R747 ← R1361 (rank 186): https://attack.mitre.org/detectionstrategies/DET0512#AN1413
- R748 ← R1477 (rank 219): https://attack.mitre.org/detectionstrategies/DET0503#AN1390
- R749 ← R1215 (rank 353): https://attack.mitre.org/detectionstrategies/DET0149#AN0426
- R750 ← R1765 (rank 887): https://attack.mitre.org/detectionstrategies/DET0548#AN1513
- R751 ← R1768 (rank 888): https://attack.mitre.org/detectionstrategies/DET0318#AN0897
- R752 ← R1724 (rank 1903): https://attack.mitre.org/detectionstrategies/DET0158#AN0445
- R753 ← R1982 (rank 972): https://attack.mitre.org/detectionstrategies/DET0399#AN1120
- R754 ← R1850 (rank 1495): https://attack.mitre.org/detectionstrategies/DET0183#AN0518
- R755 ← R1775 (rank 1400): https://attack.mitre.org/detectionstrategies/DET0118#AN0330

After successful atomic publication, the next contiguous candidate block is **R756–R765**, subject to a fresh live-branch and registry check before allocation.
