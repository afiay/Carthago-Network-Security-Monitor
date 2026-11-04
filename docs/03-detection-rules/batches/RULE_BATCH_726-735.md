# CARTHAGO — R726–R735 independent workbook-derived source candidates

**SOURCE CANDIDATE — UNVERIFIED. xUnit authored; 0 tests, 0 builds, 0 replay runs.**

## Admission basis

Direct work on `feature/carthago-reliability-hardening`. Before authoring, live HEAD was `552b1c6622273cb8345f7edbf2354a22e93bc871`; the registry contained **725 registered rules / 725 unique IDs**, ending at R725, so R726–R735 were free. A fresh expected-HEAD lease check is still required immediately before publication.

Research comes only from the owner-provided `CARTHAGO_R586-R3085_2500_UNIFIED_PRIORITY_RULE_RESEARCH_AND_TESTS(1).xlsx`. No fresh online research was used to choose this batch. Each candidate remains an independent class, predicate, state machine, test identity and registry entry. Shared code performs only evidence validation and bounded window management.

## Ten-rule matrix

| Carthago | Workbook / rank | Observable predicate retained | Non-overlap / limitation |
|---|---|---|---|
| R726 | R1159 / 115 | `hostd`, `vpxa` or `vmx` + four substantial TLS/443 payload observations to one public peer in two minutes | R423 is inbound ESXi Hostd probing. R726 is outbound process-attributed TLS volume. Packet lengths are not TCP unique bytes and do not prove datastore reads, upload or exfiltration. |
| R727 | R2663 / 247 | Linux script/shell process + direct public TLS/853 | R048/R194 cover DoH patterns; R028 is generic external DNS. R727 specifically requires local script/shell attribution and DoT transport. Resolver-policy violation, DNS contents, tunneling and C2 are not established. |
| R728 | R2665 / 248 | `node`/`nodejs` + TCP SYN to private OT service port 102/502/20000/44818/4840 | R702 is protocol classification mismatch; R683 is HTTP POST on Modbus. R728 is exact Node runtime attribution plus OT connection attempt. |
| R729 | R2666 / 249 | `python`/`python3` + TCP SYN to private OT service port | Same transport boundary as R728 but a distinct runtime identity and independent rule. Script path, parent, user and authorization are unavailable. |
| R730 | R2680 / 251 | `bash`/`sh`/`ash`/`zsh`/`busybox` + TCP SYN to private OT service port | Independent shell-runtime predicate. Command line, remote-session origin and approved asset role are unavailable. |
| R731 | R1274 / 738 | PowerShell/cmd/curl + 12 outbound SYN or small UDP observations to one public peer/port in ten seconds | R002 is generic TCP flood/DoS. R731 requires exact Windows network-tool attribution and also supports bounded UDP. CPU/resource exhaustion and victim impact remain unknown. |
| R732 | R1501 / 752 | bash/sh/zsh/python/curl/wget + 12 outbound SYN or small UDP observations to one public peer/port in ten seconds | Linux-specific independent process family; no kernel throughput, spoofing or DoS outcome is asserted. |
| R733 | R1816 / 892 | macOS utility/Office process + TLS SNI to a bounded text-storage service | R657 is cleartext paste API POST and R635 is Windows system-utility dead-drop TLS. R733 is macOS process attribution + TLS SNI only. |
| R734 | R1949 / 963 | macOS non-browser process + four substantial TLS/443 payload observations to one public peer in two minutes | Explicitly excludes known text-storage, code-repository and cloud-storage host families to avoid neighboring-rule convergence. File access/compression and unique transfer bytes are unavailable. |
| R735 | R1810 / 1300 | ESXi process + parsed HTTP on 902/903 or TLS on 80/8000/8080 | Requires typed protocol/port mismatch only. Certificate validity, payload impersonation, tunnel intent and compromise are not observable. |

## Evidence and state boundaries

- Process identity is existing best-effort local tuple enrichment; it is **not** authenticated endpoint process telemetry.
- R726 and R734 use independent bounded TLS payload windows: four unique packet IDs within two minutes, at least 5,000 observed packet bytes total. Observed packet bytes are not unique stream bytes.
- R727 requires coherent outbound TCP/TLS to destination port 853 and a bounded scripting/shell process set. It does not inspect encrypted DNS payload.
- R728–R730 require a private IPv4 source/destination pair, coherent TCP SYN, no HTTP/DNS/TLS parser contradiction, and one of the explicit OT service ports.
- R731–R732 accept only private→public TCP SYN or bounded small UDP observations; twelve unique monotonic packet IDs to one peer/port/process context are required inside ten seconds.
- R733 requires TLS/443 and SNI under one of the bounded text-storage roots: `pastebin.com`, `hastebin.com`, `paste.ee`, `controlc.com`, `dpaste.org`, `privatebin.net`.
- R734 excludes the above text-storage roots, GitHub/GitLab/Bitbucket, and the existing cloud-storage host family before its generic non-browser TLS burst can complete.
- R735 requires exact ESXi process attribution plus either parsed HTTP on VMware service ports 902/903 or TLS on cleartext web ports 80/8000/8080.
- All rules use independent ten-minute cooldown state. Raw `Info`, request query values, payloads, credentials and command lines are not placed into structured rule evidence.

## Authored xUnit source — not executed

`Carthago.Tests/R726R735AdvancedAccuracyBatchTests.cs` includes:

- one positive real-life-shaped scenario for each rule;
- a rule-specific benign near miss for every predicate;
- missing process telemetry and contradictory TCP/UDP conditions;
- duplicate packet IDs, reverse time and expired windows for correlated rules;
- sub-second flood observations so twelve unique packets can legitimately fit inside ten seconds;
- cooldown suppression and recovery for all ten rules;
- fixed-event privacy assertions;
- explicit non-convergence among Node/Python/shell OT rules, Windows/Linux flood rules and macOS text-storage/general TLS rules;
- Candidate / Shadow registration checks and full registry uniqueness.

**0 tests executed — 0 builds — 0 CI — 0 replay — 0 packet captures — 0 holdouts.**

## Workbook source references

- R726 ← R1159 (rank 115): https://attack.mitre.org/detectionstrategies/DET0548#AN1515
- R727 ← R2663 (rank 247): https://attack.mitre.org/detectionstrategies/DET0934#AN2098
- R728 ← R2665 (rank 248): https://attack.mitre.org/detectionstrategies/DET0936#AN2093
- R729 ← R2666 (rank 249): https://attack.mitre.org/detectionstrategies/DET0933#AN2095
- R730 ← R2680 (rank 251): https://attack.mitre.org/detectionstrategies/DET0931#AN2088
- R731 ← R1274 (rank 738): https://attack.mitre.org/detectionstrategies/DET0343#AN0969
- R732 ← R1501 (rank 752): https://attack.mitre.org/detectionstrategies/DET0343#AN0970
- R733 ← R1816 (rank 892): https://attack.mitre.org/detectionstrategies/DET0284#AN0789
- R734 ← R1949 (rank 963): https://attack.mitre.org/detectionstrategies/DET0512#AN1415
- R735 ← R1810 (rank 1300): https://attack.mitre.org/detectionstrategies/DET0470#AN1297

After successful atomic publication, the next contiguous candidate block is **R736–R745**, subject to a fresh live-branch check before allocation.
