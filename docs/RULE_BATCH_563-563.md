# GA R563 — parsed default HTTP Basic credential followed by Modbus write-request shape

**Branch:** `feature/carthago-reliability-hardening` · **Base SHA:** `e28fb36b93d4c8bb83a825c613c0539401d48820`.  
**Status:** **SOURCE CANDIDATE — UNVERIFIED; TESTS AUTHORED; 0 EXECUTED.**
The proposed publication contains the rule, registration, source-authored tests, this GA document and detection-owned backlog together. The exact publication commit is the resulting protected branch HEAD (a commit cannot include its own SHA); source and authored tests share that commit. This is not production promotion.

## Novel behavior and reachability

| R ID / P research | Required observed behavior | Existing-rule overlap and maturity |
| --- | --- | --- |
| **R563 — default HTTP Basic then Modbus write**, **P0038 Modbus / P0039 Modbus-TCP**; HTTP/1.x is a necessary existing capture input but **P0001 HTTP/2 and P0002 HTTP/3 are NOT direct provenance for this HTTP/1.x signature** | One RFC1918 client sends a complete bounded cleartext HTTP/1.x administrative request bearing a `PacketHandler`-derived known-default Basic credential flag, then a bounded `modbus.write` request shape to the **same RFC1918 target in another /24** within 120 seconds; distinct packet IDs, coherent TCP/IPv4 and monotonic observation required. | **High / Candidate / Shadow / confidence floor 90% / one ordered pair / 120s / 600s cooldown**. R549 matches default-Basic attempts to three private subnets; R551/R559/R560 concern BACnet-to-Modbus sequences, not this HTTP-admin-to-Modbus pair. R237 involves IoT default-web admin; this is a distinct cross-service *ordered* sequence, not proof of a compromised controller. |

The HTTP default-credential boolean has an internal setter and is populated by `PacketHandler` after complete HTTP header parsing and credential redaction. The existing `NetworkBatch236240Evidence.ModbusWrite` uses a bounded `PacketHandler`-classified `modbus.write` label and TCP/502 metadata; **the label is publicly writable in `TrafficRecord`, and packet-only provenance is insufficient to authenticate a device, an operator, or a controller response**. Both first-segment cleartext operations must be visible; TLS, Modbus Security/TLS, retransmission gaps and fragmented/out-of-order captures are not supported. An imported record cannot set the HTTP source-only flag. The rule cannot identify accepted writes, login success, dangerous register values, CVE exploitation, or process impact.

## Safety, constraints and benign lookalikes

- Realistic benign cases: approved cross-VLAN commissioning and engineering-tool sequences, factory-reset recovery and authorized security assessment; routing/proxy attribution may differ. An explicitly approved administrator client is suppressed by existing `ApprovedAssetRegistry` policy; absent approvals do **not** establish unauthorized access.
- A pair must share exact IPv4 endpoints, not merely a subnet. The request must use an administrative path and recognized cleartext HTTP port; Modbus must use a parsed TCP/502 write shape, never just TCP/502, `Info`, headers or guessed services.
- One rule instance tracks at most **512 exact client-target pairs**, at most **64 unique packet IDs per pair**, bounded 120-second correlation and ten-minute cooldown; saturation, stale packets, duplicates and out-of-order evidence fail closed.
- Only fixed labels, count and window enter `DetectionEvidenceItem`. No Basic Authorization bytes, username, URI, Host, register/value, raw Info, HTTP header text, or payload is copied to `DetectionEvent`. The ordinary `RuleEngine` owns JSONL journal-first persistence.
- No shared `PacketHandler`, `TrafficRecord`, telemetry model, registry contracts beyond additive R563 registration, UI, protocol-research ledger, holdout, R102/R118/R163 floor or original RNNN behavior is changed. Promotion needs trusted capture provenance, approved engineering roles/change windows, device/operation outcomes and negative replay.

## Source-owned files and scenarios

- `Carthago/Engine/Rules/Expansion/R563_DefaultBasicThenModbusWriteRule.cs`
- `Carthago/Engine/Rules/Catalog/RuleRegistry.cs` — one explicit new ID
- `Carthago.Tests/R563AdvancedAccuracyBatchTests.cs` — **15 xUnit methods, 15 concrete invocations AUTHORED, 0 EXECUTED**
- `docs/RULE_BATCH_563-563.md`; `docs/rules/PROTOCOL_INFORMED_THREAT_BACKLOG.md`

The 15 independent `[Fact]` scenarios cover raw packet-derived HTTP and Modbus classifications, an ordered positive, Modbus read benign negative, unknown/duplicated Authorization, non-admin route and wrong target, same-subnet and alternate source, reversed/equal-time order, expiry and out-of-order, duplicate packet ID, imported forged HTTP flag, contradictory TLS/QUIC/port-only records, cooldown suppression, concurrent duplicate, privacy/redaction and registry/Shadow/confidence invariants. All are source-authored only. **No dotnet restore, build, test, xUnit, replay, holdout, CI, runner or capture was executed.** No detection precision, recall, F1 or field reliability has been measured.

## Primary specification and threat research

- [Modbus Organization — Modbus Application Protocol Specification V1.1b3](https://www.modbus.org/docs/Modbus_Application_Protocol_V1_1b3.pdf): function 06 is a write-single-register **request**, not evidence of accepted process changes.
- [MITRE ICS T0836, Modify Parameter](https://attack.mitre.org/techniques/T0836/) (last modified **2026-10-13**) and [DET0776](https://attack.mitre.org/detectionstrategies/DET0776/): actual parameter-change detection requires authorized engineering sources, asset roles, process-state and change-control corroboration missing here.
- [CISA KEV](https://www.cisa.gov/known-exploited-vulnerabilities-catalog) and [FIRST EPSS](https://www.first.org/epss/): no specific CVE exploitation or current EPSS probability is established for this cross-service sequence. EPSS forecasts likelihood; packet presence proves neither exploit nor outcome.

**Next cursor: proposed R564**, only after live-source/registry/dedup/producer review; prefer a different strongly observable attack-behavior family rather than multiplying fanout mirrors. Frozen R102 V1 and pending V2 remain unchanged.
