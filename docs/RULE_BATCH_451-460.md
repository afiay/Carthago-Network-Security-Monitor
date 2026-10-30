# GA R451–R460 — MQTT, discovery and printing evidence boundaries

**SOURCE CANDIDATE — UNVERIFIED · 2026-10-30.** Branch:
`feature/carthago-reliability-hardening`. Live base HEAD:
`54fb01bd553a3b0134782cd2809450f7837984f1`; source commit `7f94a2e37c53981cb71d5e927b99c9638c316db3`;
authored-test commit `95f4be3099c80e25efbef50e85f289919d7d3066`. The final documentation
commit is the atomic publication target; its SHA is recorded by the GitHub
branch ref and the run report, not self-referenced in its own contents.
**180 authored xUnit invocations; 0 executed. No build, test, replay, CI,
runner, benchmark or capture was run.**

## Evidence-first ten-rule matrix

The [PacketHandler](../Carthago/Services/PacketHandler.cs) can populate
wire-derived `mqtt.connect` for a **limited MQTT CONNECT shape** and
`mqtt.publish` for PUBLISH, but
[NetworkBatch226230Wire](../Carthago/Services/NetworkBatch226230Wire.cs)
does not retain username/password flag provenance or correlate a broker
CONNACK acceptance. The UDP/5353 parser can populate typed mDNS question
name/type/response flag. These observations are **real parser capabilities**,
not proof of authentication, host role, abnormal discovery, or exposure.
[TrafficRecord](../Carthago/Models/TrafficRecord.cs) has no validated
SSDP request/response pairing, IPP operation/response, NetBIOS browser-election
message, NBNS distinct-name sweep, approved media-host inventory, or database
query/result-set export correlation. Packet port, protocol label, HTTP
request shape, client headers and `Info` are not independent audit evidence.
HTTPS decryption is not available.

Original profiles are **Alert** mode. The source change does not modify any
rule class, default severity, confidence floor, threshold, window, cooldown,
approved source or mode configuration.

| Rule and original behavior name | Observed producer / missing decisive provenance | Original severity; floor; threshold; window; cooldown | Disposition and legitimate-traffic false-positive risk |
| --- | --- | --- | --- |
| R451 MQTT Anonymous Login Pattern | Some CONNECT frames are wire-classified; no retained CONNECT credential flags or correlated CONNACK acceptance. TCP 1883/8883 and an MQTT label do not establish anonymous login. | High; 82%; 1; 15m; 30m | **BLOCKED**. Authorized unauthenticated test brokers, device onboarding, retained publish traffic |
| R452 Database Large Result Export Pattern | Packet bytes and outbound direction exist; no decoded database query, correlated result-set size, export authorization or destination attribution. Original minimum is 10 MiB. | High; 82%; 1; 15m; 30m | **BLOCKED**. Approved ETL, replication, backups and analytics exports |
| R453 mDNS Service Enumeration High Rate | UDP/5353 mDNS question name/type can be parsed; no calibrated high-rate baseline or distinct service-enumeration series. Four observations in five minutes may be ordinary. | Medium; 76%; **4**; 5m; 20m | **BLOCKED**. Bonjour service browsing, printers, normal OS discovery |
| R454 SSDP MSEARCH External Answer | Port 1900 or M-SEARCH text lacks attributed discovery request, correlated SSDP response and verified external-answer direction. | Medium; 76%; 1; 5m; 20m | **BLOCKED**. UPnP devices, media hubs, management scans |
| R455 AirPlay Discovery From Non Media Host | Typed mDNS AirPlay service question may exist; no authenticated non-media host-role inventory or approved discovery policy. | **Low**; 76%; 1; 5m; 20m | **BLOCKED**. AirPlay discovery from general-purpose laptops and phones |
| R456 Chromecast Discovery Burst | Typed mDNS Google Cast question may exist; no independently distinct per-source burst series or normal discovery baseline. | **Low**; 76%; **4**; 5m; 20m | **BLOCKED**. Cast discovery from browsers, mobile devices and media controllers |
| R457 Printer JetDirect External Access | TCP/9100/631 metadata cannot establish JetDirect printer identity, external authorization or a completed printing operation. | Medium; 76%; 1; 5m; 20m | **BLOCKED**. Remote print servers, VPN print queues, approved maintenance |
| R458 IPP Printing From External Host | HTTP/631 request shapes are not decoded IPP operation IDs, authenticated printer identity, accepted print jobs or external-host policy. | Medium; 76%; 1; 5m; 20m | **BLOCKED**. Authorized remote IPP printing and health checks |
| R459 SMB Browse Election Anomaly | SMB/NetBIOS traffic is not a parsed browser-election datagram or independently corroborated election anomaly. | **Low**; 76%; 1; 5m; 20m | **BLOCKED**. Legacy Windows browsing, failover, workgroup changes |
| R460 NetBIOS Name Query Sweep | UDP/137 and text are not decoded NBNS name questions, distinct targets or a per-source sweep series. | Medium; 76%; **4**; 5m; 20m | **BLOCKED**. Legacy name resolution, inventory and administrative diagnostics |

All ten return `MissingTelemetry` when core source/destination/behavior
telemetry is absent, otherwise `InsufficientEvidence` with the exact
missing-producer reason. No new positive operational detection is claimed.
This source candidate prevents generic token/port/path scores from emitting
unsupported alerts; **it also means these ten rules emit no alerts until
the missing producer contracts are satisfied**. This is not measured
precision, recall, or field certification.

## Implementation, contracts and privacy

- [ServiceExposureEvidenceBoundary.cs](../Carthago/Engine/Rules/Expansion/ServiceExposureEvidenceBoundary.cs)
  adds R451–R452 explicit MQTT outcome and database result-export gaps.
- [LocalDiscoveryEvidenceBoundary.cs](../Carthago/Engine/Rules/Expansion/LocalDiscoveryEvidenceBoundary.cs)
  adds R453–R460 explicit discovery, host-role, printer, browser-election
  and NBNS producer gaps. This is a pure, stateless switch; no new flags.
- [EvidenceDrivenPrecisionRuleBase.cs](../Carthago/Engine/Rules/Expansion/EvidenceDrivenPrecisionRuleBase.cs)
  invokes the existing and new boundaries after core telemetry validation
  and before generic scoring, threshold windows, cooldown state, confidence
  calculation and detection-event construction. No producer or trust status
  is invented.
- [NetworkBatch451460AccuracyTests.cs](../Carthago.Tests/NetworkBatch451460AccuracyTests.cs)
  is the sole new authored xUnit test file; **UNEXECUTED**.
- Original public R451–R460 rule classes, profiles, rule IDs, modes,
  severity, thresholds, time windows, cooldowns, source approvals, privacy
  controls, baseline/journal safeguards and shared APIs are unchanged.
  No capture, network I/O, credential retention, new dependency, or parser
  allocation was added.
- Original descriptor mismatches remain visible, not silently rewritten:
  R451 is native MQTT but `RequireHttp=true` and `RequireCleartext=true`;
  R453's configured ports are 53/853/784, not 5353; R456 lists Cast
  service ports rather than mDNS/5353; R459 includes HTTP methods for a
  native browser-election behavior; R460 has no port indicators. These
  require separate producer/API review before enabling detections.
- **Privacy limit:** existing HTTP request-target/header retention predates
  this GA; fail-closed alert evaluation does **not** redact prior capture
  buffers. No real credentials appear in authored tests. A separate
  targeted HTTP header/query redaction GA remains open.

## Exact authored scenario inventory — 180, ZERO executed

One `[Theory]` has **17 variants × 10 rules = 170 invocations**; a
second `[Theory]` has **one original-profile invariant × 10 = 10**.
All seventeen variants apply independently to R451, R452, R453, R454,
R455, R456, R457, R458, R459 and R460.

| Variant | Authored source-only expectation |
| --- | --- |
| plausible | Port, MQTT label, mDNS/IPP/SSDP service clue or native name alone cannot establish outcome |
| typed-observation | Existing MQTT CONNECT and typed mDNS question observations do not imply authentication, abnormal rate or host role |
| descriptor-spoof | Free-form `Info` asserting success is not trusted provenance |
| approved-ops | Legitimate media discovery, printing, database backup and monitoring remain benign |
| forged-audit | Client-controlled `X-Authenticated-Audit` and role headers do not establish audit |
| tls-only | TLS-only metadata cannot decrypt service operations |
| missing-source | Missing source produces `MISSING_CORE_TELEMETRY` and no event |
| malformed-target | Invalid encoded path / malformed service name cannot prove a decoded operation |
| secret-placeholder | Synthetic credential-shaped URI/header text cannot enter a new detection event |
| wrong-direction | Internal-to-internal metadata does not prove external misuse |
| wrong-protocol | Incorrect TCP/UDP transport does not authenticate native protocol behavior |
| threshold-burst | Five observations cannot manufacture missing evidence, including thresholds of four |
| claimed-success | Claimed CONNACK, IPP job or SSDP response in text is not a correlated server outcome |
| duplicate-id | Reused observation ID cannot produce a match |
| spoofed-service-name | Host/process/service labels do not attest target identity |
| fragmentary-native | One-byte packet plus protocol words is not a decoded exchange |
| after-cooldown | Repetition after 31 and 62 minutes does not create provenance |
| profile-invariant | Original Alert mode, confidence, threshold, window and cooldown are preserved |

**180 concrete xUnit invocations AUTHORED; 0 EXECUTED.**
No positive case is supportable without the missing producer; the typed
clues are not promoted into false operational positives. The historical
4,940/4,940 Windows checkpoint predates this batch and is not verification.

## Divergence review, outstanding GAs and next batch

Pre-change: inspected live HEAD `54fb01bd553a3b0134782cd2809450f7837984f1`, recent independent UI commits,
R441–R450 source/test/docs, original ten R451–R460 classes, shared
evaluator, MQTT wire parser, PacketHandler's mDNS producer, TrafficRecord
and original profiles. No previous R451–R460 candidate or test file was
present in the live tracked tree.

Pre-publication: recheck the live branch and compare exactly five
detection-owned paths, source/test/docs ancestry, boundary reason codes,
C# naming/API compatibility, original profiles, no added secrets, and
disjoint UI ownership. Static source review is **not** a compile or runtime
pass. Any unresolved divergence blocks publication.

Outstanding quality GAs: owner-authorized Windows build and execution
of the 180 authored cases; independently vetted MQTT CONNECT/CONNACK
authentication outcome; decoded IPP/SSDP/NBNS/browser-election operations;
authenticated printer/media asset inventory; distinct mDNS query series
with calibrated benign baselines; database query/result correlation;
HTTP query/header privacy regression; benign/malicious field datasets,
memory/latency bounds and measured precision/recall.

Frozen R102 V1 remains **FAILED 4/6**; V2 has **0/4 approved external
sources**. Preserve R102 80%, R118 86%, R163 84% and external R102
0.75 floors. Independent R343/R295/R275/R163 replay obligations remain
open and do not block unrelated source development.

**Next contiguous GA: R461–R470**, only after the full candidate is
safely published and the next run inspects live source and docs.

## Authoritative protocol and engineering references

- [OASIS MQTT 3.1.1 specification](https://docs.oasis-open.org/mqtt/mqtt/v3.1.1/os/mqtt-v3.1.1-os.html)
- [RFC 6762 — Multicast DNS](https://www.rfc-editor.org/rfc/rfc6762)
- [RFC 6763 — DNS-Based Service Discovery](https://www.rfc-editor.org/rfc/rfc6763)
- [UPnP Device Architecture 1.1](https://openconnectivity.org/developer/specifications/upnp-resources/upnp/)
- [RFC 8010 — Internet Printing Protocol](https://www.rfc-editor.org/rfc/rfc8010)
- [RFC 1002 — NetBIOS Name Service](https://www.rfc-editor.org/rfc/rfc1002)
- [Rule documentation standard](rules/RULE_DOCUMENTATION_STANDARD.md)
