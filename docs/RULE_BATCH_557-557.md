# CARTHAGO — GA R557: outbound Modbus write-request public-subnet fanout

**Branch:** `feature/carthago-reliability-hardening`  
**Audit base HEAD:** `ddaea2f88f042713a1fc50bfe5a7400c10107b17` (2026-11-02).  
**Status:** **SOURCE CANDIDATE — UNVERIFIED; TESTS AUTHORED; 0 EXECUTED.** No restore, build, xUnit, replay, holdout, CI, runner, capture or packet scan was executed.

## Threat decision, provenance and deduplication

**R557 — Outbound Modbus Write Public-Subnet Fanout** maps to **P0038 Modbus / P0039 Modbus/TCP**, one family with partial wire recognition. Existing **R240** detects individual Modbus write-request semantics; **R548** detects public-to-private three-target fanout; **R223** covers generic OT network boundaries. None requires **one RFC1918 source sending parser-classified Modbus write requests to three distinct public destination /24 networks in five minutes**. This is a registered ordinary `IotOtAdvancedPrecisionDetectionRuleBase` rule, not a separate inspector.

**Malicious hypothesis:** unexpected multi-network outbound write attempts from a private engineering host or gateway toward public Modbus endpoints may indicate unapproved controller interaction, remote multi-site probing or policy drift. It does **not** prove an endpoint is a PLC, an authenticated operator, an accepted write, changed register values, process impact or exploitation. Approved engineering, vendor maintenance, commissioning, multi-site integration, VPN and NAT are realistic benign lookalikes.

**Policy:** High severity, Candidate maturity, **Shadow** default, **90% minimum confidence**, **3 distinct globally routable public /24s** in **300 seconds**, **600-second cooldown**. Reject Modbus reads, server responses, port/Info-only claims, public or reserved sources, private or reserved destinations, same-/24 retries, malformed or contradictory TCP/IPv4/HTTP/DNS/TLS metadata, duplicate IDs and out-of-order observations.

## Existing evidence producer and runtime boundary

- **Producer:** `PacketHandler` early TCP payload → `OtProtocolLight.TryIdentifyTcp` bounded MBAP/function-code recognition → `TrafficRecord.ApplicationProtocol = modbus.write` with typed `Id`, `Source`, `Destination`, `IpVersion`, `IsTcp`, `IsUdp`, `Protocol`, ports, `L4Len` and `Length`. Only functions 5, 6, 15 and 16 are recognized as write shapes; there is no full Modbus decode, register-value validation or server outcome.
- **Trust limitation:** `ApplicationProtocol` is publicly settable on `TrafficRecord`; imported records can forge the label. Trusted capture-origin provenance, approved source inventory and destination roles are needed **before Alert promotion**. IP addresses do not authenticate devices.
- **State:** instance-owned bounded `NetworkBatch226230Evidence.Window` (4096 source buckets, max 512 packet IDs and 512 targets per source), monotonic observation and deduplication, bounded 10m cooldown. Destination uniqueness is public /24, not individual hosts; saturation fails closed.
- **Privacy and journal:** emit only fixed operation, boundary, count, window and destination-port markers. Do not copy `Info`, register values, payload, identities or secrets. `RuleEngine` owns journal-first persistence, Shadow/Disabled policy and suppression.
- **Visibility:** cleartext first-segment TCP/502 only; no Modbus Security/TLS on 802, multi-segment reconstruction, remote controller response, historian or process change. NAT and one-sided capture can distort topology.
- **Preservation:** R102/R118/R163 confidence floors 80/86/84%, frozen R102 V1 historical 4/6, pending V2, UI and historical protocol inventory are untouched.

## Advanced xUnit scenarios — authored only

**21 methods (18 Fact, 3 Theory); 32 concrete invocations (18 Fact, 14 InlineData); 0 executed.** Scenarios include bounded real Modbus wire-classifier positive, read/response/truncation negative, three public-/24 match, internal/same-/24 benign negatives, reserved/nonprivate addresses, operation and Info spoofing, malformed/contradictory evidence, distinct sources, duplicate and out-of-order IDs, window expiry, cooldown, concurrency, redaction and registry/Shadow/Candidate/90% invariants. None was compiled or run.

**Changed files:** `Carthago/Engine/Rules/Expansion/R557_OutboundModbusWritePublicSubnetFanoutRule.cs`; `Carthago.Tests/R557AdvancedAccuracyBatchTests.cs`; `Carthago/Engine/Rules/Catalog/RuleRegistry.cs`; `docs/RULE_BATCH_557-557.md`; `docs/rules/PROTOCOL_INFORMED_THREAT_BACKLOG.md`.

## Dated research and blocked higher-fidelity candidate

- [Modbus Organization specification V1.1b3](https://www.modbus.org/modbus-specifications), published **2012-04-26**, describes the write function codes; this rule does not inspect register values.
- [MITRE ATT&CK ICS T0836](https://attack.mitre.org/techniques/T0836/), last modified **2026-10-13**, and [DET0776](https://attack.mitre.org/detectionstrategies/DET0776/) emphasize authorized write sources, safe setpoint ranges and process/historian corroboration; these are **not** established by R557.
- [CISA KEV](https://www.cisa.gov/known-exploited-vulnerabilities-catalog) is an exploitation-evidence prioritization source, not proof of a Modbus exploit here. [FIRST EPSS](https://www.first.org/epss/) estimates CVE exploitation likelihood, not this behavior; no candidate-specific CVE/EPSS or confirmed exploitation is asserted.
- **BLOCKED:** a high-fidelity unauthorized parameter-change detector needs a trusted engineering-source/asset inventory and independently observed controller readback or historian process-state evidence. Owner approval is required before any shared producer integration. No speculative rule was registered for that outcome.

**Next proposed cursor R558** only after fresh live registry, producer and overlap audit. No P0501 or isolated protocol GAs.
