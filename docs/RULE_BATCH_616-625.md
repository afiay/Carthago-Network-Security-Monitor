# CARTHAGO — R616–R625 independent workbook-based detection candidates

**SOURCE CANDIDATE — UNVERIFIED. xUnit tests authored, 0 executed; builds 0; replays 0.**

## Identity and boundary

Work directly on `feature/carthago-reliability-hardening`. Base registry R001–R615. Add independent R616–R625, preserving original research IDs from the owner-provided `CARTHAGO_R586-R3085_2500_UNIFIED_PRIORITY_RULE_RESEARCH_AND_TESTS(1).xlsx`, without fresh online research or convergence. Each has its own class, signature predicate, and instance-owned cooldown; shared helpers are limited to existing evidence hygiene.

## Rule matrix (source candidate only)

| Rule ID | Workbook ID | Independent specific behavior | Strongest overlap and distinction | Evidence limitation |
|---|---|---|---|---|
| R616 | R2269 | Exchange ECP Virtual Directory Reset Request | R319 generic OWA/ECP probing; exact SetObject+Reset+VirtualDirectory request not an authenticated virtual-directory change | The Sigma source requires HTTP 200 and machine-account username ending $, neither is established by the packet record. |
| R617 | R2280 | SolarWinds SUPERNOVA LogoImageHandler Clazz Request | R602 SolarWinds WebResource.axd API request is a different path and predicate | Cannot observe original Sigma branch based solely on HTTP 500; only joint logoimagehandler+clazz URI is detected. |
| R618 | R2283 | Exchange ProxyShell Autodiscover Back-End Request | R608/R609 require OWA mastermailbox or encoded-at PowerShell paths; this requires autodiscover.json and a back-end target | Workbook marks 200/301 response as success; rule recognizes only an HTTP request, without validating response. |
| R619 | R2922 | Encoded Java Expression in HTTP Request URI | R089 generic command injection and R084 Log4Shell patterns; this detects only four specific percent-encoded Java expressions, not general injection | Headers, HTTP status and server execution unavailable; may overlap general injection alerts but distinct exact encoded selectors. |
| R620 | R2941 | LocaltoNet Service DNS Query | R389/R517 are Ngrok tunnel indicators, not LocaltoNet domain DNS signatures | Sigma originally requires an initiated process connection. This narrower DNS-only variant cannot attribute a process or an established tunnel. |
| R621 | R3070 | Historical 3CX-associated Domain DNS Query | R003 threat-feed hit uses feed reputation, not this historical domain enumeration; any real IOC intersection must be suppressed operationally | Sigma requires association with 3CXDesktopApp.exe; a DNS QNAME cannot establish process or malware, and historical domains may be stale. |
| R622 | R2237 | Notepad Process External TCP Egress | R266 generic first-seen process egress and R267 masquerade name heuristics; this is exact notepad.exe on external TCP excluding printer port 9100 | Best-effort Windows process-to-flow mapping lacks authenticated execution or path identity. This is conditional evidence only. |
| R623 | R2904 | Dialer Process External TCP Egress | R266 generic novel process egress; exact dialer.exe independent of novelty | Sigma requires System32 path, which is not reliably present in ProcessName. Basename cannot establish signature or path. |
| R624 | R2956 | AddInUtil Process External TCP Egress | R266 generic first-seen process egress; exact AddInUtil name independent of novelty | PID/name can be resolved only on visible local sockets and may be missing or stale. No causal execution claim. |
| R625 | R2979 | Equation Editor Process External TCP Egress | R266 novel and R267 masquerade are separate from exact eqnedt32.exe egress | Process identity is best-effort and no signed executable path or malicious payload is established. |

## Producer and runtime scope

- R616–R619: parsed cleartext HTTP request metadata (`TrafficRecord.HttpMethod`, `HttpUri`, `ApplicationProtocol`), evaluated through existing `WebSignatureRequestEvidence.TryGet`. No raw URI/headers retained in event evidence. R616 and R618 lack original Sigma HTTP response/status; R616 lacks username information.
- R620–R621: parsed DNS query fields through existing `DnsSignatureRequestEvidence.TryGetQuery`. They are **DNS queries**, not proven established outbound connections. Historical 3CX domains are dated indicators; neither R621 nor R620 establishes malicious activity, process identity or exfiltration.
- R622–R625: only TCP egress with source private and destination public, positive PID and observed basename using existing `NetworkBatch266270Evidence.ProcessEgress`. `WindowsProcessResolver` is best-effort, and the mutable `TrafficRecord.ProcessName` lacks independently authenticated process attribution. These must remain Shadow/conditional until producer tests prove live reachability and no spurious attribution. R623's basename alone does not prove the original path restriction.
- Existing `WebSignatureCooldown` provides instance-owned 10-minute cooldown, bounded key count and monotonic timestamp protection. Each rule independently evaluates one uncombined predicate. No packet handling, shared sensor, holdout, UI or coordinator modification.
- Fixed schema values only for evidence: workbook reference, literal matched condition, and honest outcome. No raw payload, URL, full DNS QNAME, process path or credentials in emitted structured evidence. Confidence floor 84 for HTTP, 80 for DNS, 82 for process; HTTP High except R619 Medium; DNS Medium; process Medium/High. All Candidate / Shadow by default.

## xUnit authored, NOT executed

`Carthago.Tests/R616R625AdvancedAccuracyBatchTests.cs` specifies positive and benign negatives; wrong producer, conflicting metadata, DNS response, wrong port, missing QNAME, malformed domains, missing process/PID, notepad printing-port suppression, private destination, duplicate ID, timestamp/cooldown, event redaction, separate Exchange signatures, registration and Shadow invariants.

No compilation, tests, replay or workflow execution is authorized. No PASS claims. Future checks must include live capture producer validation and scenario-specific false positives. The original Sigma research is a candidate reference, not proof of successful exploitation or production accuracy.

## Research citations retained in source workbook

- R616 → R2269 — Exchange ECP Virtual Directory Reset Request (http).
- R617 → R2280 — SolarWinds SUPERNOVA LogoImageHandler Clazz Request (http).
- R618 → R2283 — Exchange ProxyShell Autodiscover Back-End Request (http).
- R619 → R2922 — Encoded Java Expression in HTTP Request URI (http).
- R620 → R2941 — LocaltoNet Service DNS Query (dns).
- R621 → R3070 — Historical 3CX-associated Domain DNS Query (dns).
- R622 → R2237 — Notepad Process External TCP Egress (process).
- R623 → R2904 — Dialer Process External TCP Egress (process).
- R624 → R2956 — AddInUtil Process External TCP Egress (process).
- R625 → R2979 — Equation Editor Process External TCP Egress (process).

## Next batch

R626–R635 after direct publication; keep 10 independent candidate rules, prioritize workbook provenance and strict no-duplicate predicate review.
