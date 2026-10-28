# R271–R275 — corroborated threat-intel source and fail-closed correlation/identity controls

**CANDIDATE — UNVERIFIED.** Authored 2026-10-28 on existing `feature/carthago-reliability-hardening`. **60 advanced xUnit facts authored (14+11+11+11+13), ZERO executed.** Static source/diff inspection only. No dotnet build, xUnit, replay, benchmark, V1/V2 holdout, CI, GitHub Actions or Windows runner.

## Commits and exact paths

- Source: `eef05eb707b50bcafcb536ae58d12d046ce0be52`. Production files: `Carthago/Engine/Rules/Expansion/R271_ThreatFeedIocWithLowReputationOverlapRule.cs` through `R275_OAuthDeviceCodePhishingIndicatorRule.cs`, `Carthago/Engine/Rules/Expansion/NetworkBatch271275Evidence.cs`, and narrow privacy changes to `Carthago/Engine/Rules/Expansion/EvasionInfraPrecisionDetectionRuleBase.cs`.
- Advanced tests: `5ee517694f5e162269ea50a56a206808ea0e3ab4`. Fixture: `Carthago.Tests/NetworkBatch271275Context.cs`. Test classes: `Carthago.Tests/R271AdvancedAccuracyBatchTests.cs` through `Carthago.Tests/R275AdvancedAccuracyBatchTests.cs`.
- Ledger: `docs/RULE_HARDENING_PROGRESS.md`. This batch: `docs/RULE_BATCH_271-275.md`.
- Deferred verifier unchanged: `scripts/verify-all-rule-batches.ps1`. PowerShell 5.1-safe encoding and single verifier policy retained. Nothing executed.

## Rule-specific observable contracts and test scenarios

**R271 (14 facts; conditional positive helper contract, live unverified):** A **source** IPv4 address of a typed inbound TCP record must exactly match the locally loaded `ThreatFeedService.TryMatch` snapshot (feed confidence >=75, nonempty source provenance, built within 48 hours) **and** have independent **source-IP** reputation enrichment (`ReputationIsMalicious=true`, score >=75, >=2 reports, last seen within 30 days). The reputation UI performs a manual lookup of the record **source**; it is not a verified synchronous packet enrichment path. Source and feed must refer to the same IP. Test facts cover typed positive helper, mismatched IOC, missing malicious flag, low score, low report count, stale reputation, stale feed, absent feed provenance, reversed direction, contradictory transport, packet-Info spoof, reserved documentation IP, missing IP version, and preserved 88/1/Alert. Positive helper fixture is **synthetic typed contract only**, not a successful live feed hit, alert or field recall. No feed refresh or external request is triggered by the detector. No raw packet Info or process path is emitted.

**R272 (11 facts; intentional fail-closed):** A packet record cannot attest to distinct emitted rule IDs, rule families, detection-event provenance or per-host correlation. Previous destination-count/Info-label logic could fabricate a multi-signal surge. The detector now returns `NoMatch` until a trusted detection-event correlation adapter exists. Facts cover packet-label spoofing, multiple packets, multiple destinations, duplicate/replay, out-of-order, process spoof, missing source, contradictory protocol, fabricated rule labels, HTTP URI labels and preserved 82/3/Alert. **No positive test was fabricated.**

**R273 (11 facts; intentional fail-closed):** Packet GeoIP is not a successful IdP authentication. The current `TrafficRecord` has no authenticated account, sign-in outcome, session ID or IdP event provenance. Facts cover geo country and coordinate changes, Info spoof, IdP SNI, HTTP user parameter, two-country sequence, replay, out-of-order, missing source, contradictory DNS/HTTP and preserved 78/2/Alert. **No positive sign-in sequence was fabricated.**

**R274 (11 facts; intentional fail-closed):** No trusted MFA push event IDs, account correlation, delivery/outcome or approval/denial telemetry exists in `TrafficRecord`. Facts cover Info spoof, repeated packet bursts, Duo host, HTTP path, process spoof, query token, replay, out-of-order, contradictory transport, missing source and preserved 78/3/Alert. **No positive MFA fatigue event was fabricated.**

**R275 (13 facts; intentional fail-closed):** Neither device-code initiation nor `device_code`/`user_code` query parameters establish phishing. `PacketHandler` does not decrypt HTTPS, and there is no authenticated IdP device-flow audit or independently verified phishing event in the rule context. Facts cover synthetic device/user-code combination, routine initiation, partial parameters, Info spoof, lookalike host, consent-query claim, SNI-only, replay, out-of-order, secret non-emission, contradictory transport and preserved 78/1/Alert. **No positive phishing result was fabricated.**

**Legacy compatibility risk:** `Carthago.Tests/AdvancedIdentityAndWindowsExpansionRuleTests.cs` and the existing R275 paired replay expect a synthetic device-code/user-code URI to match. The new conservative fail-closed behavior intentionally conflicts with that legacy expectation. **Those legacy tests, labeled replays and frozen evidence were not modified or executed.** At owner-authorized test time, reconcile the mismatch by obtaining a real authenticated IdP audit producer and analyst-approved labels, not by restoring untrusted phishing claims or relabeling frozen samples.

## Privacy, precision and promotion constraints

R271's shared event path suppresses raw `Info` and process names and redacts destinationHost; evidence contains only typed source/destination IP, numeric reputation/feed confidence and source count, no raw feed indicators or tokens. R272–R275 emit no match/evidence without trusted producers. No new mutable global windows or unbounded state were added; R271 uses the existing cooldown. The threat-feed snapshot and manual source-IP reputation must be independently populated, with their live availability unverified. IPv6 source correlation is not implemented.

**No policies, confidence floors, thresholds, default modes, asset approvals, baseline readiness or approved architecture were weakened.** R271=88/1/Alert; R272=82/3/Alert; R273=78/2/Alert; R274=78/3/Alert; R275=78/1/Alert. These are profile declarations, **not** evidence of validated alerts. All changes are CANDIDATE/UNVERIFIED.

Known capture gaps remain: no HTTPS decryption or full TCP reassembly; PacketHandler does not populate `DnsTtl`/`DnsAnswers`, process attribution or authenticated IdP events. R262 fragment and R227 Profinet L2 positives remain contract-only; R228 OPC UA parser absent. Content-Length is declared, not transferred; a different /24 is not approved segmentation. Frozen R102 V1 **FAILED 4/6** immutable, V2 independent licensed PCAP and analyst approval **PENDING**. Earlier user-run R001–R125 and synthetic 48/48 do not validate this batch or field emitted-alert recall.

**Next: R276–R280, then R281–R285**, unless the live remote branch/ledger advances. No tests until the owner explicitly says "now it's test time".
