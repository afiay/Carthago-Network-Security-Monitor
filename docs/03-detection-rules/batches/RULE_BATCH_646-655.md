# CARTHAGO — R646–R655 ten independent workbook-derived source candidates

**SOURCE CANDIDATE — UNVERIFIED. 0 builds, 0 tests, 0 replays executed.**

## Branch, provenance and anti-duplicate review

Existing branch `feature/carthago-reliability-hardening` only. Source inventory: owner-provided `CARTHAGO_R586-R3085_2500_UNIFIED_PRIORITY_RULE_RESEARCH_AND_TESTS(1).xlsx`. Original research IDs and URLs retained below; no additional online research. Ten independent predicates and C# classes; no merging/convergence. Shared `Research646Evidence` validates packet tuples and bounded distinct-target windows only.

| New rule | Workbook | Independent observable signature | Nearest existing overlap and distinction |
| --- | --- | --- | --- |
| R646 | R1358 | HTTP firmware upload request to device management endpoint | R236 detects firmware GET/download; this requires a POST with upload path and binary content-type. No change outcome. |
| R647 | R1490 | Known miner process contacting external pool-associated TCP port | R178 detects miner pool DNS, R266 first-seen process; this requires exact miner basename and port to public IP. |
| R648 | R1352 | VNC private listener SYN-ACK response to a public client | R124 RDP exposure and R644 RDP SYN-ACK have a different service; this is VNC TCP/5900 response only. |
| R649 | R1372 | WinRM private listener SYN-ACK response to a public client | R125 flags inbound WinRM service access, not observed server SYN-ACK; this requires response direction and flags. |
| R650 | R1417 | Curl/Wget attributed process outbound public subnet fanout | R017 sweeps internal targets; R036 heavy upload to one target. This requires one process+PID, three public /24s. |
| R651 | R1284 | External CMS content-save POST request observed | R087 monitors webshell upload, R169 admin login; this requires an explicit content-editor save POST from public to private. |
| R652 | R1385 | Script host FTP upload command to public endpoint | R248 generic FTP STOR/appe; this requires correlated local script-host process/PID and parsed request. |
| R653 | R2790 | Public-client Modbus non-write request multi-host sweep | R548 is Modbus WRITE cross-subnet fanout; R653 requires non-write request classification to three hosts in one private /24. |
| R654 | R2782 | Public-client S7Comm multi-host discovery sweep | R225 covers outside-segment S7, R478 block transfer; this requires one public client and three private S7 hosts in one /24. |
| R655 | R2706 | Public-client EtherNet/IP ListIdentity multi-host probe | R488 generic CIP ListIdentity burst and R643 internal sequential scan; this is public-to-private fanout to three exact hosts. |

## Evidence limitations

R646 identifies cleartext HTTP **POST attempts** to explicit device firmware-upgrade routes with declared binary form content type; unlike R236 GET/download, it cannot prove image bytes uploaded, flash write or reboot.

R647 requires an exact miner-process basename and an external pool-associated port. It is not verified malware or a genuine mining-pool server. R648–R649 require a private service **SYN-ACK response** to a genuinely public IPv4 client: VNC 5900 or WinRM 5985/5986, respectively. A SYN-ACK cannot establish successful authentication or organizational exposure behind NAT.

R650 requires a best-effort attributed curl/wget process+PID contacting three distinct public /24 destinations within five minutes. It does not establish a scan, botnet or malicious bandwidth consumption. R651 requires a public-client cleartext HTTP POST to a small exact set of CMS content-save paths and a form/JSON Content-Type; this is **not evidence of defacement**.

R652 requires a parsed FTP STOR/APPE request to a public server, plus a best-effort local script-host process and PID; no uploaded data channel or successful exfiltration is inferred. R653 requires parser-labeled Modbus **non-write** requests on 502 to three private hosts in one /24 from the same public source, excluding typed `modbus.write`. R654 similarly requires parsed S7Comm client-to-server 102 requests to three hosts. R655 requires parsed EtherNet/IP ListIdentity requests to three hosts. These observations do not establish asset ownership, unauthorized access, write outcomes or compromises.

All profiles: candidate maturity, default Shadow mode, fixed outcome text, five-minute window metadata, bounded state (512 fanout keys/96 IDs per key), instance-owned ten-minute outer cooldown (1,024 keys), and no unredacted URI, process path, credentials or packet payload in rule-created evidence. Current mutable `TrafficRecord` fields can be imported/spoofed: successful live packet-producer provenance remains a separate GA gate. No frozen holdout changes or edits to existing rule confidence floors.

## Tests authored, NOT executed

`Carthago.Tests/R646R655AdvancedAccuracyBatchTests.cs` specifies positive cases, benign near misses, process/PID gating, inbound/outbound direction, SYN vs SYN-ACK, unique destination subnet/host threshold, mixed source/subnet failures, typed protocol contradictions, duplicate/out-of-order timestamps, cooldown, redaction, and registry uniqueness/Candidate Shadow defaults. **No test execution was authorized or attempted.**

## Existing owner-workbook sources

- R646 ← R1358: [MITRE research](https://attack.mitre.org/detectionstrategies/DET0167#AN0477)
- R647 ← R1490: [MITRE research](https://attack.mitre.org/detectionstrategies/DET0540#AN1490)
- R648 ← R1352: [MITRE research](https://attack.mitre.org/detectionstrategies/DET0178#AN0504)
- R649 ← R1372: [MITRE research](https://attack.mitre.org/detectionstrategies/DET0477#AN1313)
- R650 ← R1417: [MITRE research](https://attack.mitre.org/detectionstrategies/DET0028#AN0081)
- R651 ← R1284: [MITRE research](https://attack.mitre.org/detectionstrategies/DET0590#AN1622)
- R652 ← R1385: [MITRE research](https://attack.mitre.org/detectionstrategies/DET0149#AN0423)
- R653 ← R2790: [MITRE research](https://attack.mitre.org/detectionstrategies/DET0767#AN2288)
- R654 ← R2782: [MITRE research](https://attack.mitre.org/detectionstrategies/DET0796#AN2253)
- R655 ← R2706: [MITRE research](https://attack.mitre.org/detectionstrategies/DET0902#AN2045)

## Next batch

After successful direct-branch publication and source verification, next source candidate IDs R656–R665. Keep each rule independent; no convergence.
