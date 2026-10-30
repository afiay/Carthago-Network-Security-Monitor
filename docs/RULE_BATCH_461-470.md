# GA R461–R470 — DHCP, ARP, IPv6 and wireless control evidence boundaries

**SOURCE CANDIDATE — UNVERIFIED · 2026-10-30.** Branch: `feature/carthago-reliability-hardening`. Live inspected base HEAD `d061bdb276629917f1e63c83507f2af8f27f3b47`; source commit `bfe817ee7a3b0e24a7dbd6c255f27187b8905c9d`; authored-test commit `2cd4ba6eace2d4242e34f453bc1603cdec27a0bd`. The documentation-descendant commit is the single non-forced atomic publication target; its exact SHA is reported after publication, because a commit cannot contain its own SHA.

**190 concrete xUnit invocations AUTHORED; 0 EXECUTED.** No build, xUnit, replay, holdout, CI, Windows runner, benchmark or production capture.

## Evidence-first review and ten dispositions

The current [TrafficRecord](../Carthago/Models/TrafficRecord.cs) includes source/destination, ports, protocol, MAC source/destination and an ICMP type/code field. These are packet observations, **not** validated DHCP lease state, authorized DHCP-server inventory, ARP binding history, SLAAC prefix history, CAPWAP controller authorization, Bluetooth gateway identity, ADB authentication or MDM enrollment outcomes. The [PacketHandler](../Carthago/Services/PacketHandler.cs) labels some ICMPv6 packets, but does not establish trusted Router Advertisement prefix transitions; generic traffic and `Info` do not substitute for typed protocol decoders. No authenticated network-controller/MDM inventory or outcome producer is connected to these ten rule predicates. Encrypted TLS content is not decrypted.

| Rule / original behavior | Decisive missing producer and predicate | Original mode; severity; floor; threshold; window; cooldown | Disposition and legitimate-traffic risk |
| --- | --- | --- | --- |
| R461 DHCP Starvation Candidate | DHCP client identifier series, distinct requests and server lease exhaustion; absent from the current rule evaluation contract | Alert; High; 76%; 1; 5m; 20m | **BLOCKED** · `DHCP_DISTINCT_CLIENT_LEASE_EXHAUSTION_UNAVAILABLE` · Legitimate mass device onboarding, DHCP renewal and lab stress tests |
| R462 DHCP Rogue Offer Detected | Decoded server OFFER, trusted DHCP-server inventory and policy mismatch; absent from the current rule evaluation contract | Alert; High; 76%; 1; 5m; 20m | **BLOCKED** · `DHCP_OFFER_SERVER_AUTHORITY_UNAVAILABLE` · Approved redundant DHCP servers, relay and failover |
| R463 ARP Gratuitous Storm | Decoded gratuitous ARP, deduplicated per-source rate and calibrated baseline; absent from the current rule evaluation contract | Alert; Medium; 76%; 4; 5m; 20m | **BLOCKED** · `ARP_GRATUITOUS_RATE_BASELINE_UNAVAILABLE` · HA failover, VRRP and IP mobility |
| R464 ARP Duplicate MAC FlipFlop | Time-ordered IP-to-MAC binding transitions and known failover exemptions; absent from the current rule evaluation contract | Alert; High; 76%; 1; 5m; 20m | **BLOCKED** · `ARP_IP_MAC_BINDING_TRANSITIONS_UNAVAILABLE` · NIC bonding, virtual machines and switch mobility |
| R465 IPv6 SLAAC Prefix Change | Router Advertisement prefix options, router authority and prefix history; absent from the current rule evaluation contract | Alert; Medium; 76%; 1; 5m; 20m | **BLOCKED** · `IPV6_ROUTER_ADVERTISEMENT_PREFIX_HISTORY_UNAVAILABLE` · Router renumbering, planned IPv6 migration |
| R466 WiFi Controller Admin Probe | Verified controller identity, admin request and response/authz context; absent from the current rule evaluation contract | Alert; High; 76%; 1; 5m; 20m | **BLOCKED** · `WIFI_CONTROLLER_IDENTITY_AND_PROBE_OUTCOME_UNAVAILABLE` · Controller polling, backups and authorized administrators |
| R467 CAPWAP External Controller Attempt | Decoded CAPWAP control exchange, controller policy and external direction; absent from the current rule evaluation contract | Alert; High; 76%; 1; 5m; 20m | **BLOCKED** · `CAPWAP_CONTROL_EXCHANGE_AND_CONTROLLER_POLICY_UNAVAILABLE` · Approved cloud controllers, CAPWAP mobility |
| R468 Bluetooth Gateway Internet Egress | Trusted Bluetooth gateway asset role and correlated unapproved outbound flow; absent from the current rule evaluation contract | Alert; Medium; 76%; 1; 5m; 20m | **BLOCKED** · `BLUETOOTH_GATEWAY_ASSET_ROLE_AND_EGRESS_UNAVAILABLE` · Approved Bluetooth bridges and cloud synchronization |
| R469 Android Debug Bridge Network Access | Decoded ADB authentication/handshake and device authorization policy; absent from the current rule evaluation contract | Alert; High; 76%; 1; 5m; 20m | **BLOCKED** · `ADB_PROTOCOL_HANDSHAKE_AND_ACCESS_POLICY_UNAVAILABLE` · Developer workstations, managed Android testing |
| R470 Mobile MDM Enrollment Burst | Authenticated enrollment outcome, distinct devices and benign rate baseline; absent from the current rule evaluation contract | Alert; Medium; 76%; 4; 5m; 20m | **BLOCKED** · `MDM_ENROLLMENT_OUTCOME_BURST_UNAVAILABLE` · Planned device fleet enrollment and re-provisioning |

**All ten dispositions are BLOCKED.** The shared [evaluator](../Carthago/Engine/Rules/Expansion/EvidenceDrivenPrecisionRuleBase.cs) already invokes [LocalDiscoveryEvidenceBoundary](../Carthago/Engine/Rules/Expansion/LocalDiscoveryEvidenceBoundary.cs) after core telemetry validation and **before** generic scoring, burst state, confidence, cooldown or `DetectionEvent` construction. GA R461–R470 adds ten explicit missing-producer contracts to that existing guard. Core-telemetry gaps return `MISSING_CORE_TELEMETRY`; otherwise the specific reason code above is returned with `InsufficientEvidence`. This is source-only behavior and is **not** a verified runtime result.

A real packet on UDP/67 or 68, ARP traffic, ICMPv6 Router Advertisement type 134, UDP/5246, TCP/5555 or HTTPS/443 is **not sufficient** to prove the named attack. These guards prevent unsupported attribution, but also mean these ten rules **cannot emit operational detections** until trusted producers and explicit rule contracts are integrated. No positive operational test is currently supportable; no precision or recall claim follows.

## Source scope, preserved contracts and privacy

- Modified only `Carthago/Engine/Rules/Expansion/LocalDiscoveryEvidenceBoundary.cs`, added `Carthago.Tests/NetworkBatch461470AccuracyTests.cs`, and updated this batch document and `docs/RULE_HARDENING_PROGRESS.md`. No engine/model/service parser or capture API was changed; the existing evaluator's dispatch path was reused.
- All ten original rule classes, IDs, descriptions, configuration keys, **Alert** modes, severity levels, **76%** confidence floors, **5-minute** windows, **20-minute** cooldowns and thresholds (**R463 and R470 = 4; others = 1**) remain unchanged. No profile/mode/approval relaxation, no new memory state or parser allocation.
- R466 retains `RequireHttp=true`; this does not prove a controller's identity. R465's existing ICMPv6 type/code metadata is not RA prefix option history. R468's port 443 does not attest a Bluetooth gateway. R469's TCP/5555 is not an authenticated ADB handshake. R470 has no authenticated enrollment event producer. No synthetic asset identity, HTTPS decryption or fake audit flag was added.
- No new credential capture or retention. Existing HTTP request-target/header privacy review remains a **separate GA**; this source guard does not sanitize existing capture buffers. Authored inputs use synthetic placeholders only.
- The independent UI stream owns `Carthago/Views/**`, `Carthago/Controls/**`, themes and `docs/design/**`; none were edited. The original detection behavior descriptors are preserved for a future trusted integration, rather than silently redefined.

## Authored regression scenario inventory — 190, ZERO executed

One xUnit `[Theory]` supplies **18 variants × 10 rule IDs = 180 invocations**, and a second `[Theory]` supplies **one profile invariant × 10 = 10**. Every variant applies to each of R461, R462, R463, R464, R465, R466, R467, R468, R469 and R470. Tests are **authored, UNEXECUTED**.

| Variant | Source-only assertion intent |
| --- | --- |
| plausible | Port, protocol, text or HTTP path without independently verified outcome |
| typed-observation | A plausible packet-level protocol label is not authenticated service or asset evidence |
| descriptor-spoof | Free-form Info asserts successful misuse without trusted provenance |
| approved-ops | Authorized DHCP maintenance, HA failover, controller polling and MDM enrollment |
| forged-audit | Client-controlled HTTP headers claim controller identity and enrollment success |
| tls-only | Encrypted metadata cannot establish a decoded command or server outcome |
| missing-source | Absent source returns MISSING_CORE_TELEMETRY and no event |
| missing-destination | Absent destination/host/behavior context returns MISSING_CORE_TELEMETRY |
| malformed-target | Malformed URI/host and truncated protocol labels cannot prove behavior |
| secret-placeholder | Synthetic token-shaped URI/header input must not create a detection event |
| wrong-direction | Internal-to-internal flow does not establish unauthorized external access |
| wrong-protocol | Transport mismatch does not authenticate DHCP, CAPWAP or ADB behavior |
| threshold-burst | Six uncorroborated observations cannot satisfy a trusted anomaly predicate |
| claimed-success | Text claiming lease exhaustion, rogue server, ADB or MDM success is not audit |
| duplicate-id | Reused observation identifier cannot manufacture a validated event |
| spoofed-service-name | Process/host/application labels cannot attest managed asset role |
| fragmentary-native | One-byte packet plus native protocol words is not a decoded exchange |
| after-cooldown | Repetition after 21/42 minutes cannot create missing provenance |
| profile-invariant | Original Alert mode, threshold, confidence, window and cooldown unchanged |

The synthetic records test fail-closed outcomes and invariant profiles; they are not positive malicious captures. Windows compilation, actual assertion results, and detection recall remain unverified.

## Divergence review and outstanding quality GAs

**Pre-change:** Inspected live remote HEAD `d061bdb276629917f1e63c83507f2af8f27f3b47` including UI GA UI-11, [R451–R460](RULE_BATCH_451-460.md), all ten original R461–R470 classes, current evaluator and boundary, PacketHandler, TrafficRecord, prior authored tests and [documentation standard](rules/RULE_DOCUMENTATION_STANDARD.md). No preexisting R461–R470 batch document or authored batch test file was present. Original rule profiles were compared individually.

**Pre-publication controls:** Confirm the ten reason codes are exact and uniquely mapped; source/test/docs files are detection-owned; no changed rule class, shared API, secret, threshold, confidence, mode, capture producer, UI file or frozen holdout. Recheck live remote HEAD and reconcile only disjoint changes; publish a complete candidate through one expected-HEAD-protected non-forced ref update. Static source inspection is not a build.

**Outstanding GAs:** Owner-authorized Windows compilation and execution of 190 authored invocations; typed DHCP message/lease and approved-server inventory; decoded ARP binding transitions with failover policy; ICMPv6 RA prefix option provenance and router history; CAPWAP authenticated controller exchange; Wi-Fi controller identity and response correlation; Bluetooth gateway inventory; ADB authentication/authorization; MDM enrollment audit and distinct-device rate baseline; HTTP query/header redaction review; benign and malicious field captures, bounded memory/latency and measured false-positive/recall evidence.

Historical **4,940/4,940** checkpoint predates this candidate. Frozen R102 V1 remains **FAILED 4/6**, V2 **0/4 approved external sources**. Preserve confidence floors R102 80%, R118 86%, R163 84%, external R102 0.75, approvals, journal, privacy, baseline and holdout invariants. Independent R343/R295/R275/R163 replay GAs do not block unrelated source development.

**Next contiguous GA: R471–R480**, only after this complete candidate is safely published and the next run inspects the then-live branch.

## Authoritative protocol and engineering references

- [RFC 2131 — Dynamic Host Configuration Protocol](https://www.rfc-editor.org/rfc/rfc2131)
- [RFC 826 — Ethernet Address Resolution Protocol](https://www.rfc-editor.org/rfc/rfc826)
- [RFC 4861 — IPv6 Neighbor Discovery](https://www.rfc-editor.org/rfc/rfc4861)
- [RFC 4862 — IPv6 Stateless Address Autoconfiguration](https://www.rfc-editor.org/rfc/rfc4862)
- [RFC 5415 — CAPWAP Protocol Specification](https://www.rfc-editor.org/rfc/rfc5415)
- [Android Debug Bridge documentation](https://developer.android.com/tools/adb)
- [Microsoft C# naming conventions](https://learn.microsoft.com/en-us/dotnet/csharp/fundamentals/coding-style/identifier-names)
- [Rule documentation standard](rules/RULE_DOCUMENTATION_STANDARD.md)
