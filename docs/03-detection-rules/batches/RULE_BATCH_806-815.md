# CARTHAGO — R806–R815 independent network source candidates

**SOURCE CANDIDATE — UNVERIFIED.** xUnit source authored, **0 tests, 0 builds, 0 CI, 0 holdouts, 0 packet replay executed**.

Owner research workbook: `CARTHAGO_R586-R3085_2500_UNIFIED_PRIORITY_RULE_RESEARCH_AND_TESTS(1).xlsx` (Library `libfile_3dce02a91bac8191a6896c8e24e04839`). Original research identifiers are NOT newly allocated CARTHAGO IDs. Ten independently instantiated Candidate/Shadow `EvidenceDrivenPrecisionRuleBase` implementations preserve confidence floor 80 and ten-minute instance cooldowns.

| New rule | Original workbook | Narrow live-field predicate |
|---|---|---|
| R806 | R1175 | docker process issues registry HTTP/80 GET /v2/*/manifests/*, then xmrig process on same host sends public TCP/3333 payload to a different peer within 60 s |
| R807 | R1391 | sshd responds on TCP/22 to a public peer, then ssh opens a private east-west TCP/22 SYN within 90 s |
| R808 | R1426 | ldapmodify local PID sends Kerberos TCP/88 SYN, then LDAP TCP/389 SYN to same private host within 80 s |
| R809 | R1473 | one public source sends cleartext POST /admin/login, then POST /admin/theme to same private portal host within 90 s |
| R810 | R1599 | frpc/frpc.exe local PID sends versioned UDP QUIC/443 to 3 distinct public peers within 60 s |
| R811 | R1700 | remote TCP/9443 certificate expired by 30+ days is observed on 2 different client ports within 90 s |
| R812 | R1759 | openssl/openssl.exe local PID sends 4 non-QUIC UDP/4444 data packets to one public peer within 60 s |
| R813 | R1877 | powershell/pwsh makes 4 distinct external HTTP/80 GET /api/v1/resource/* requests within 60 s |
| R814 | R1972 | powershell HTTP/80 GET /images/*.png|jpg then TLS/8443 payload to a different public peer within 60 s |
| R815 | R2833 | osascript local PID sends 4 alternating short/long TCP TLS/443 packets to same public peer/SNI within 90 s |

## Scope and source-admission limits

These research rows often require a trusted endpoint, hypervisor or network-control-plane source that `TrafficRecord` cannot presently represent. This batch deliberately **does not implement the full MITRE analytic**. It admits only a narrower independently observable packet/process shape. No rule asserts authorization, account creation, portal modification, credential theft, CPU impact, file modification, steganography, proxy traversal, C2 or successful exfiltration.

- **R806 / workbook R1175:** A Docker-process manifest fetch and later xmrig-process pool-port payload do not prove actual container creation, CPU impact, or unauthorized compute use. This sequence is distinct from existing R647's single miner contact.
- **R807 / workbook R1391:** No SSH authentication, delegated trust or sudo event is observed; only successive SSH-related TCP SYN-ACK and SYN legs.
- **R808 / workbook R1426:** No AD account creation or LDAP operation is decoded; process-attributed TCP SYNs to Kerberos and LDAP are the only evidence.
- **R809 / workbook R1473:** No portal file modification, credential content, or session authentication is represented; paired cleartext HTTP POST paths only.
- **R810 / workbook R1599:** QUIC fanout does not establish multi-hop proxying, ESXi execution, or relay ownership; no connection ID hash is assumed.
- **R811 / workbook R1700:** This requires captured certificate validity and two client ports but does not inspect RSA, certificate chains, or key-exchange validity.
- **R812 / workbook R1759:** Packet length and process name do not prove symmetric encryption or entropy; source candidate detects only non-QUIC UDP traffic.
- **R813 / workbook R1877:** No local file reads, clipboard capture, or exfiltration are observed; distinct HTTP API GET paths only.
- **R814 / workbook R1972:** No media file creation, steganographic content or transfer result is visible; only a process-linked two-peer network sequence.
- **R815 / workbook R2833:** Alternating packet sizes do not prove obfuscation, long-lived sessions or C2; four monotonic, bounded observations only.

Each candidate requires coherent protocol, direction and bounded evidence; per-rule state rejects duplicate packet IDs, reversal and expiry. R810 explicitly handles versioned QUIC without requiring `QuicConnectionIdHash` (currently not populated by the capture path). R811 checks actual certificate expiry, not merely a self-signed name, and does not require `TlsVersion` from the server-certificate packet. R814 requires the second TLS peer to differ from the preceding HTTP peer. R815 uses small/large **alternation**, not the previously implemented fixed-size cadence predicate.

Risk of benign positives remains: legitimate mining benchmarks, SSH jump administration, directory maintenance, portal deployment, QUIC proxies, expired certificates on labs, UDP instrumentation, API monitoring, download scripts, and macOS automation may all resemble one subset. Static evidence consists solely of original workbook identifier, predicate marker and unknown-outcome marker. No raw `Info`, credential, URI, hostname, payload or actor identifiers are inserted into custom evidence strings.

The xUnit source was written before implementation, covering positive, benign near-miss, missing/contradictory protocol, duplicate, reverse-time, expiry, cooldown recovery, privacy, independent predicates and registry singleton Candidate/Shadow properties. **Execution intentionally prohibited by owner; no pass/fail is claimed.** Existing signatures, prior rules and detection behavior are unchanged.

## Workbook source links

- R806 / R1175: https://attack.mitre.org/detectionstrategies/DET0540#AN1492
- R807 / R1391: https://attack.mitre.org/detectionstrategies/DET0488#AN1345
- R808 / R1426: https://attack.mitre.org/detectionstrategies/DET0003#AN0007
- R809 / R1473: https://attack.mitre.org/detectionstrategies/DET0480#AN1320
- R810 / R1599: https://attack.mitre.org/detectionstrategies/DET0359#AN1023
- R811 / R1700: https://attack.mitre.org/detectionstrategies/DET0543#AN1500
- R812 / R1759: https://attack.mitre.org/detectionstrategies/DET0143#AN0404
- R813 / R1877: https://attack.mitre.org/detectionstrategies/DET0186#AN0531
- R814 / R1972: https://attack.mitre.org/detectionstrategies/DET0235#AN0651
- R815 / R2833: https://attack.mitre.org/detectionstrategies/DET0053#AN0146

**Next free CARTHAGO ID: R816 — SOURCE CANDIDATE — UNVERIFIED.**
