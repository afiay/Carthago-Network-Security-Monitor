# CARTHAGO — R666–R675 independent workbook-derived source candidates

**SOURCE CANDIDATE — UNVERIFIED. 0 builds, 0 tests, 0 replays executed.**

## Branch and provenance

Existing branch `feature/carthago-reliability-hardening` only. Research inventory: `CARTHAGO_R586-R3085_2500_UNIFIED_PRIORITY_RULE_RESEARCH_AND_TESTS(1).xlsx`, using its pre-researched MITRE/Sigma references without any additional online research. Original research IDs are preserved. Ten independent C# rule classes, independent predicates and instance-owned cooldowns; **no convergence**.

| Carthago rule | Original research / priority rank | Narrow observable behavior | Closest overlap / independent signal | Unsupported inference explicitly excluded |
|---|---|---|---|---|
| R666 | R2932 / 1804 | Specific SQL injection token in cleartext HTTP GET URI | R085 detects broader SQLi; this requires one of a restricted set of concrete query tokens in a parser-labeled GET. | Only observed URI bytes, no database execution, returned data, or HTTP status. |
| R667 | R1955 / 2090 | Script process publishes MQTT control-topic request to external broker | R229 monitors retained-topic abuse and R115 frequency; this requires non-retained control-topic publish plus unusual attributed script process. | MQTT parser labels a publish request; no client identity, broker acceptance, C2 or actuation outcome is established. |
| R668 | R2020 / 1066 | Rundll32-associated HTTP API POST to a public host | R268 matches a different list of interpreter processes for HTTP/DNS, R642 script browser-claim POST; this requires rundll32 and explicit API POST. | Process-to-flow PID attribution is best effort; HTTP request is not C2 or delivery evidence. |
| R669 | R1988 / 2096 | System binary TLS ClientHello on nominal HTTP port 80 | R151 is HTTP/2 ALPN on uncommon port and R012 general TLS heuristic; this requires unexpected TLS on TCP/80 plus exact system utility name. | No TLS cert validation, server authentication, or protocol impersonation proof. |
| R670 | R2022 / 2103 | Four regularly spaced fixed-size ICMP echo requests | R021 generic ICMP tunneling and R033 oversized echo detect different inputs; this requires four same-length echoes with bounded inter-arrival spacing. | A regular ping sequence is often benign and does not prove C2 or tunneling. |
| R671 | R2056 / 2108 | Eight large raw TCP payload observations from an attributed script process | R658 detects uniform moderate-size timed observations; this requires repeated large non-HTTP/non-TLS payload packets on uncommon ports. | Observed packet payload length is not directional application bytes, delivery, data content or demonstrated junk traffic. |
| R672 | R1977 / 1961 | PowerShell POST with long Base64-like data parameter to named web host | R664 requires GET to IP literal and R253 checks Base64 in POST via its own heuristic; this requires PowerShell/PID, named public host, and exact data parameter shape. | Query characters cannot prove encoding purpose, payload content or C2. |
| R673 | R2037 / 1270 | Script HTTP GET with repeated double-percent-encoded segments | R019 generic encoded URI, R619 Java expressions; this requires multiple explicit double-percent markers plus attributed script process. | This is URL-encoding shape, not a proved custom encoder, malware or successful execution. |
| R674 | R1993 / 1963 | Same local PID receives public TCP SYN then initiates external high-port SYN | R263 user-space proxy egress covers an individual flow; this is ordered two-direction network behavior from same local address and attributed process. | Two SYNs do not prove process spawning, packet forwarding, NAT, an established proxy or a C2 relay. |
| R675 | R2023 / 1067 | System utility TLS SNI contact to web collaboration endpoint | R635 uses historical dead-drop service families YouTube/Facebook/Pastebin; this requires different collaboration hosts and exact atypical local system utility. | No upload/download, persistent session, malicious C2 use, TLS content, or reliable process executable identity. |

## Evidence boundaries

- R666 is a restricted exact-selector GET request from R2932; unlike the source webserver rule, Carthago does not have `sc-status` and cannot exclude the original 404 response cases. R667 requires a parser-observed MQTT publish, wire-observed control-topic flag, **non-retained** status, and exact locally attributed unusual process/PID; no broker authentication or result evidence.
- R668 requires outbound cleartext POST to an `/api/` path on a narrow port set and a locally attributed `rundll32.exe` process; R669 requires a TLS parser observation with SNI to port 80 and an unusual system utility. Neither confirms C2, exploit or service impersonation.
- R670 requires four same-length ICMP echo requests with 9–31 second inter-arrival times; do not infer tunneled content. R671 requires eight observed, large, non-HTTP/TLS TCP payload records from one script-like local process over an uncommon port in a bounded two-minute window. Observed payload lengths do **not** establish transfer, content, payload entropy, or server ACK.
- R672 looks at a restricted long URL-safe `data=` value in a cleartext HTTP POST from an attributed PowerShell process to a named web host (not IP literal). R673 requires four double-percent-encoding markers in a GET from an attributed script process. Neither identifies a true encoding algorithm or software exploit.
- R674 correlates an inbound public-source SYN with a later outbound high-port SYN from the same locally attributed process/PID within 40 seconds. It does not establish traffic forwarding, a relay, authentication, packet bridging or malicious proxy. R675 requires TLS SNI at a small set of collaboration web host families with a local system utility; no upload, data content, C2, or file disclosure inference.
- All process-to-flow IDs are best-effort local Windows tuple attribution; imported `TrafficRecord` values are mutable and do not independently establish actual process creation. Security confidence and source viability remain to be verified.
- Defaults: Candidate maturity, Shadow runtime, ten-minute independent cooldown, bounded per-rule state (512 sequence keys), typed IP/L4 gates, fixed redacted per-rule evidence labels and `*_unknown` outcomes. No frozen holdout, sensor, UI, automation or existing rule-confidence changes.

## xUnit source authored, not executed

`Carthago.Tests/R666R675AdvancedAccuracyBatchTests.cs` contains positives and negatives for each rule, absent parser and wrong method/host/process, MQTT publish/retain flags, TLS port and SNI, ICMP timing/length, large payload sequence thresholds, URL-safe query shapes, host/PID mismatch in bridged SYN sequence, source-only outcome, duplicate IDs/cooldown, registry uniqueness, Candidate/Shadow defaults.

**No tests or builds executed**; no PASS claims or production promotion.

## Original pre-researched reference URLs

- R666 ← R2932: [1804 — original workbook source](https://github.com/SigmaHQ/sigma/blob/ccbb0369507f796db0b0ae6854c8a2be471b9d84/rules/web/webserver_generic/web_sql_injection_in_access_logs.yml)
- R667 ← R1955: [2090 — original workbook source](https://attack.mitre.org/detectionstrategies/DET0002#AN0002)
- R668 ← R2020: [1066 — original workbook source](https://attack.mitre.org/detectionstrategies/DET0444#AN1225)
- R669 ← R1988: [2096 — original workbook source](https://attack.mitre.org/detectionstrategies/DET0470#AN1294)
- R670 ← R2022: [2103 — original workbook source](https://attack.mitre.org/detectionstrategies/DET0457#AN1258)
- R671 ← R2056: [2108 — original workbook source](https://attack.mitre.org/detectionstrategies/DET0011#AN0030)
- R672 ← R1977: [1961 — original workbook source](https://attack.mitre.org/detectionstrategies/DET0108#AN0302)
- R673 ← R2037: [1270 — original workbook source](https://attack.mitre.org/detectionstrategies/DET0326#AN0928)
- R674 ← R1993: [1963 — original workbook source](https://attack.mitre.org/detectionstrategies/DET0445#AN1229)
- R675 ← R2023: [1067 — original workbook source](https://attack.mitre.org/detectionstrategies/DET0425#AN1189)

## Next batch

After direct-branch publication, next contiguous source IDs: R676–R685. Continue ten independent non-converged rules with workbook provenance and no test execution until explicitly authorized.
