# CARTHAGO — R756–R765 independent workbook-derived source candidates

**SOURCE CANDIDATE — UNVERIFIED. xUnit authored; 0 tests, 0 builds, 0 replay runs.**

## Admission basis

Direct work on `feature/carthago-reliability-hardening`. At the beginning of this run the live branch was `d9f070ee6093f08574038107c8e18b6c61a67851` with **755 registered rules / 755 unique IDs**, ending at R755. Candidate selection used the owner-provided `CARTHAGO_R586-R3085_2500_UNIFIED_PRIORITY_RULE_RESEARCH_AND_TESTS(1).xlsx`; no fresh web research was used.

Exact/renamed duplicates were rejected before authoring. In particular:
- workbook R2936 (BITS direct-IP download) already has the live specialized counterpart R686;
- workbook R2938 (Exchange HAFNIUM exploitation) already has R600;
- workbook R2957 (ADSelfService exploitation) already has R591;
- workbook R1130 (TFTP boot) was not used because Carthago already owns both cross-boundary TFTP exchange directions in R708/R715 while the remaining boot-configuration/image-integrity evidence is unavailable;
- generic DNS-tunneling, VNC exposure and browser-User-Agent families were retained only when the new candidate adds an independent process or ordered-sequence predicate.

Every rule below remains a separate ID/class/predicate/state/test/documentation unit. `Research756Evidence` contains only shared field validation, exact process/host classification, privacy-safe DNS shaping, and bounded correlation primitives.

| Carthago | Workbook / rank | Observable predicate retained | Non-overlap / limitation |
|---|---:|---|---|
| R756 | R1158 / 346 | `hostd`/`vpxa`/`vmx` + GitHub/GitLab/Bitbucket SNI + four substantial TLS/443 payload observations | R751 owns the macOS repository family; R717 owns cleartext repository API POST. R756 is ESXi-management attribution only and makes no datastore-read/upload/exfiltration claim. |
| R757 | R1258 / 7 | parser-corroborated unicast LLMNR/NBNS conflicting response followed by same-peer SMB/445 SYN to the responder within 60s | R083 detects repeated conflicting responses; R082 requires independent NTLM relay classification. R757 asserts only the typed two-stage network sequence. |
| R758 | R1335 / 594 | public→private uncommon high-port SYN followed by private→same-public-peer reverse SYN within 90s | Distinct from R704 internal relay and R755 VNC-specific follow-on. No packet-filter/raw-socket/reverse-shell claim. |
| R759 | R1433 / 746 | `x11vnc`/`vncserver`/`Xvnc`/`Xtigervnc` + private TCP/5900 SYN-ACK to public client | R648 is transport-only VNC exposure. R759 independently requires exact VNC-process attribution. Authentication/session success remains unknown. |
| R760 | R2844 / 2450 | `osascript`/Python + outbound cleartext GET/POST + Macintosh browser-like User-Agent | R725 owns curl/wget GET mismatch. R760 uses a disjoint process family and Macintosh browser header. No launch-agent ancestry or spoofing intent is inferred. |
| R761 | R2751 / 2435 | TeamViewer/AnyDesk/ScreenConnect/ConnectWise process + three similar TLS/443 payload observations at 10–60s cadence | Installation/firewall/session evidence is unavailable. The rule asserts recurrent RMM-attributed TLS only. |
| R762 | R1837 / 1863 | `msbuild.exe` + four substantial TLS/443 payload observations to one public peer | Source analytic includes child/module/file/injection evidence. Carthago keeps only exact MSBuild process attribution plus bounded egress. |
| R763 | R2669 / 2416 | BusyBox/nslookup + three high-entropy DNS queries to a public resolver for one root in 120s | R102 is process-agnostic DNS-tunnel shape. R763 reserves an ESXi-style shell/tool family; actual ESXi host role/VIB state is unknown. |
| R764 | R2743 / 2474 | iodine/iodined/dnscat2/dig + three high-entropy DNS queries to a public resolver for one root in 120s | Exact DNS-tool attribution is required; process family is disjoint from R763. Cron/reverse-shell ancestry and tunnel success remain unknown. |
| R765 | R1464 / 11 | public SYN to common Linux service port followed within 90s by public egress from same private host attributed to bash/sh/zsh/curl/wget/Python | R755 owns VNC/5900 follow-on; R765 excludes VNC and asserts only temporal service-attempt→shell/tool-egress correlation. No crash, parentage, exploit success or causality is inferred. |

## Evidence and state boundaries

- Best-effort process attribution is a local tuple enrichment signal, not an authenticated endpoint process event.
- R756 and R762 require four unique monotonic packet IDs and observed-packet-byte thresholds inside two minutes. Packet lengths are not TCP unique bytes or transferred-file sizes.
- R757 requires a trusted LLMNR/NBNS `CONFLICTING_RESPONSE` classification to a private unicast peer before the same peer can satisfy the SMB SYN stage.
- R758 requires the same public origin on both stages; unrelated public peers cannot combine.
- R761 requires three unique similar-size TLS observations with 10–60 second intervals.
- R763/R764 require parser-backed DNS queries, public resolver direction, high-entropy first-label shape, exact process attribution, and three unique observations. DNS query values are redacted from the resulting event.
- R765 state is keyed only by the private service host and expires after 90 seconds; a VNC/5900 trigger cannot prime it.
- All ten candidates use rule-owned cooldown state. Raw `Info`, DNS query labels, URL query parameters, credentials and command lines are not copied into rule-specific evidence.

## Authored xUnit source — not executed

`Carthago.Tests/R756R765AdvancedAccuracyBatchTests.cs` contains:

- positive shaped scenarios for all ten rules;
- rule-specific benign near misses;
- missing process-attribution checks for process-gated candidates;
- contradictory transport/parser failures;
- duplicate-ID, reverse-time and expiry checks for stateful candidates;
- cooldown suppression and recovery for every rule;
- raw-info, URL-query and DNS-label privacy assertions;
- explicit non-convergence checks for R083/R648/R725, the two DNS process families, and VNC-vs-Linux-service follow-on;
- Candidate / Shadow registration and full registry uniqueness assertions.

**0 tests executed — 0 builds — 0 CI — 0 GitHub Actions dispatches — 0 packet captures — 0 replays — 0 holdouts.**

## Workbook source references

- R756 ← R1158 (rank 346): https://attack.mitre.org/detectionstrategies/DET0318#AN0898
- R757 ← R1258 (rank 7): https://attack.mitre.org/detectionstrategies/DET0462#AN1274
- R758 ← R1335 (rank 594): https://attack.mitre.org/detectionstrategies/DET0162#AN0462
- R759 ← R1433 (rank 746): https://attack.mitre.org/detectionstrategies/DET0178#AN0505
- R760 ← R2844 (rank 2450): https://attack.mitre.org/detectionstrategies/DET0898#AN2032
- R761 ← R2751 (rank 2435): https://attack.mitre.org/detectionstrategies/DET0259#AN0714
- R762 ← R1837 (rank 1863): https://attack.mitre.org/detectionstrategies/DET0556#AN1535
- R763 ← R2669 (rank 2416): https://attack.mitre.org/detectionstrategies/DET0400#AN1125
- R764 ← R2743 (rank 2474): https://attack.mitre.org/detectionstrategies/DET0400#AN1122
- R765 ← R1464 (rank 11): https://attack.mitre.org/detectionstrategies/DET0118#AN0328

After successful atomic publication, the next contiguous candidate block is **R766–R775**, subject to a fresh live-branch and registry check before allocation.
