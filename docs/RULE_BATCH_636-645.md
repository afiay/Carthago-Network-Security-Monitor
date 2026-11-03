# CARTHAGO — R636–R645 independent source candidates

**SOURCE CANDIDATE — UNVERIFIED. Source and xUnit authored; 0 builds, 0 tests, 0 replays executed.**

## Branch and source

Direct existing branch `feature/carthago-reliability-hardening`, following R625. Original workbook: `CARTHAGO_R586-R3085_2500_UNIFIED_PRIORITY_RULE_RESEARCH_AND_TESTS(1).xlsx`. The owner supplied the research URLs and selectors; no additional web research was performed. Every workbook ID remains a research ID; new sequential registry IDs R636–R645 are independent C# rule classes.

## Rule matrix / predicate nonoverlap

| Carthago ID | Research ID / priority queue | Specific observable event | Kind | Closest existing rule and differentiation | Hard evidence limitation |
|---|---|---|---|---|---|
| R636 | R3013 / rank 1258 | OMIGOD-like unauthenticated WSMan POST attempt | http | R089 generic command injection and R074 WinRM traffic; exact unauthenticated /wsman POST with positive Content-Length is distinct | HTTP 200, server command and successful exploit are unavailable; absence of an Authorization header in the capture summary is not authenticated absence. |
| R637 | R2385 / rank 1690 | Historical GALLIUM-associated DNS indicator query | dns | R003 feed-based IOC and R614 historical DPRK domains; exact GALLIUM-era DNS names not in those candidate predicates | Historical 2019 research, stale domains and possible reuse; DNS query is not evidence of actor attribution. |
| R638 | R2190 / rank 1616 | Process outbound TCP contact across multiple callback-associated ports | multiport | R013 unusual service port and R266 first-seen process: this requires one attributed local process to contact two distinct researched ports on one external peer within five minutes | The workbook's Linux log producer is absent; only a best-effort locally attributed Windows TCP-flow analogue is implemented. Distinct port contact is not confirmed malware. |
| R639 | R2146 / rank 1094 | Local process TLS SNI contact to ngrok developer-domain variants | process | R389/R517 use existing ngrok.io/app scopes; this exact ngrok-free.dev or ngrok.dev TLS SNI family additionally requires attributed local process | TLS SNI alone does not establish an initiated connection, use of a tunnel or payload transfer; approved ngrok deployments are common. |
| R640 | R2267 / rank 1145 | Local process TLS SNI contact to regional ngrok tunnel endpoints | process | R639 only .dev domain family; R517 generic ngrok handshake differs from an exact tunnel.<region>.ngrok.com SNI and local process conjunction | No established tunnel, authentication, ownership or file transfer can be inferred from SNI and best-effort PID attribution. |
| R641 | R2012 / rank 1410 | Office process-associated high-entropy DNS query | dnsprocess | R094 DGA-like query analyzes a domain only; this rule requires Office process/PID and a high-diversity numerical QNAME label | Best-effort process association and domain entropy cannot establish a DGA or process execution; Office telemetry may be absent. |
| R642 | R2769 / rank 2446 | Script interpreter HTTP POST with browser-like user agent | httpprocess | R172 scanner UA/browsing mismatch and R268 interpreter DNS/HTTP; this requires a POST plus browser claim and an explicit interpreter PID/name, not generic HTTP | No process parent lineage or API-caller provenance; a browser-like User-Agent is not proof of spoofing and the local PID may be untrusted. |
| R643 | R2707 / rank 2317 | Sequential EtherNet/IP ListIdentity private-subnet discovery walk | otwalk | R488 EtherNet/IP ListIdentity burst counts protocol packets; this requires strictly sequential distinct private host addresses in one /24 within five minutes | Does not establish PLC identity, authorized engineer inventory, full subnet scan or unauthorized access. Capture can miss packets and suppress a true walk. |
| R644 | R2472 / rank 1740 | Internal RDP listener SYN-ACK response to public client | rdpsynack | R124 flags RDP access attempts across a boundary; this requires server-to-public-client TCP SYN-ACK from source port 3389 and does not duplicate a mere request | An SYN-ACK proves network handshake response only, not authenticated RDP access or true external Internet exposure through NAT. |
| R645 | R1342 / rank 367 | Cleartext login-form POST to a punycode HTTP host | phishform | R193 lookalike-domain DNS and R130 credential stuffing do not require the specific cleartext POST/form/punycode-host combination | Cannot inspect credential contents, verify domain mimicry or infer phishing; legitimate internationalized domains and tests may match. |

## Evidence contracts and source-only boundaries

- R636: parser-labeled cleartext POST `/wsman`, explicit positive `Content-Length` and a captured header summary without Authorization. This is an **unauthenticated-looking request**, not confirmation of the exploit or its success; completeness of the header capture is unproven.
- R637: seven exact, historical GALLIUM DNS names. No inference of actor attribution or fresh IOC validity. R641: process-associated Office DNS query with one sufficiently diverse long label, requiring PID and best-effort process name. Both require `DnsSignatureRequestEvidence.TryGetQuery`. `RedactQuery` is used to prevent full QNAME leakage from generated events.
- R638: two *distinct* researched callback-associated TCP ports to the same external peer, from one attributed local process within five minutes; bound 512 tracked keys and 64 IDs/key. This is more restrictive than a single unusual port. Cannot claim malware beacon or Linux-origin process telemetry.
- R639 and R640: separate, mutually exclusive ngrok TLS SNI families with a local process label. R639 uses `.ngrok-free.dev/.ngrok.dev`; R640 uses literal `tunnel.<region>.ngrok.com` names. No DNS-only evidence, authentication, actual tunnel setup, or payload transfer is inferred. SNI reachability may vary.
- R642: parser-labeled HTTP POST, browser-like User-Agent and locally attributed interpreter process/PID. No verified API call, parent lineage or malicious impersonation inference.
- R643: ordered EtherNet/IP ListIdentity messages over TCP/44818 from one private source to three successive distinct private IPs in one /24 within five minutes. Unlike a generic burst, packets must have the wire-derived `ethernetip.listidentity` marker. This is a discovery *shape*, not proof of scanning all hosts, controller identity or unauthorized access.
- R644: IPv4 TCP SYN-ACK, *source* port 3389, private server to publicly routed destination. This is server-response evidence, distinct from a client RDP probe; no completed login, RDP session, or Internet exposure verified.
- R645: cleartext HTTP POST to a login endpoint with form Content-Type and explicit `xn--` label in `HttpHost`. Internationalized domains are legitimate; no asserted phishing or credential capture.

All profiles: Candidate maturity, default Shadow, independently implemented predicates, instance-owned ten-minute cooldown, 1,024-key outer bound, fixed redacted evidence, and no new producers. Untrusted imported `TrafficRecord` fields can simulate predicates, so live capture and independent producer integrity are blocking validation gates.

## Authored xUnit scenarios

`Carthago.Tests/R636R645AdvancedAccuracyBatchTests.cs` contains positive/near-miss cases, wrong methods, missing authorization/body controls, suffix impersonation, DNS response negatives, process/PID gates, mixed peers, repeated ports, stale windows, sequential versus unordered EtherNet/IP discovery, TCP SYN-ACK versus SYN, internal-only destinations, browser versus interpreter process, redaction, registry uniqueness, and cooldown. **No tests executed**.

## Research references provided in the workbook

- R636 ← R3013 (rank 1258): [source](https://github.com/SigmaHQ/sigma/blob/ccbb0369507f796db0b0ae6854c8a2be471b9d84/rules-emerging-threats/2021/Exploits/CVE-2021-38647/zeek_http_exploit_cve_2021_38647_omigod_no_auth_rce.yml)
- R637 ← R2385 (rank 1690): [source](https://github.com/SigmaHQ/sigma/blob/ccbb0369507f796db0b0ae6854c8a2be471b9d84/rules-emerging-threats/2020/TA/GALLIUM/win_dns_analytic_apt_gallium.yml)
- R638 ← R2190 (rank 1616): [source](https://github.com/SigmaHQ/sigma/blob/ccbb0369507f796db0b0ae6854c8a2be471b9d84/rules/linux/network_connection/net_connection_lnx_susp_malware_callback_port.yml)
- R639 ← R2146 (rank 1094): [source](https://github.com/SigmaHQ/sigma/blob/ccbb0369507f796db0b0ae6854c8a2be471b9d84/rules/windows/network_connection/net_connection_win_domain_ngrok.yml)
- R640 ← R2267 (rank 1145): [source](https://github.com/SigmaHQ/sigma/blob/ccbb0369507f796db0b0ae6854c8a2be471b9d84/rules/windows/network_connection/net_connection_win_domain_ngrok_tunnel.yml)
- R641 ← R2012 (rank 1410): [source](https://attack.mitre.org/detectionstrategies/DET0039#AN0109)
- R642 ← R2769 (rank 2446): [source](https://attack.mitre.org/detectionstrategies/DET0898#AN2029)
- R643 ← R2707 (rank 2317): [source](https://attack.mitre.org/detectionstrategies/DET0739#AN2171)
- R644 ← R2472 (rank 1740): [source](https://github.com/SigmaHQ/sigma/blob/ccbb0369507f796db0b0ae6854c8a2be471b9d84/rules/network/zeek/zeek_rdp_public_listener.yml)
- R645 ← R1342 (rank 367): [source](https://attack.mitre.org/detectionstrategies/DET0102#AN0285)

## Publication and next step

This document records source authoring only, not tested recognition accuracy or deployment readiness. Preserve immutable holdouts and other automations. Next unallocated rule block after an actual successful publication is R646–R655.
