# Rule accuracy batch 14 — R066–R070

**Status: CANDIDATE — UNVERIFIED.** 48 advanced xUnit facts authored (9 + 9 + 10 + 9 + 11). No build, xUnit, replay benchmark, frozen holdout, Windows runner or other automated test was executed.

| Rule | Evidence and state changes | Facts |
| --- | --- | ---: |
| R066 First-Time Country for Host | Validated ISO-2 destination enrichment, rejected contradictory GeoIP/WHOIS values and nonpublic egress, preserved three-country warmup, required two distinct novel-country observations and a ready durable baseline. | 9 |
| R067 Rogue IPv6 Router Advertisement | Required ICMPv6 type 134/code 0, IPv6 link-local source, all-nodes multicast destination, hop limit 255 and valid unicast Ethernet MAC. A ready baseline gates an in-memory, corroborated router identity change; a first ordinary RA is silent. | 9 |
| R068 IPv6 Neighbor Discovery Sweep | Required structured ICMPv6 NS type 135/code 0, hop limit 255 and 15 distinct *unicast* IPv6 destinations within the configured window. Per-source bounded state rejects duplicate/out-of-order timestamps and suppresses repeated episode alerts. | 10 |
| R069 IPv6 Duplicate Address / Spoofing | Required structured ICMPv6 NA type 136/code 0, hop limit 255, a validated MAC and a capture-path target annotation agreeing with the IPv6 source. A ready baseline gates a repeated MAC identity conflict; uncorroborated DAD text is ignored. | 9 |
| R070 Teredo / 6to4 / ISATAP Tunnel Use | Required explicit transition-protocol classification plus corroborating UDP/3544 or IPv6 transition-address structure, with two distinct observations on the same flow. Bounded state, 10-minute inactivity rearm and episode suppression. | 11 |

## Implementation and privacy

Five existing telemetry rule adapters now implement narrow evidence-gated EvaluateAsync overrides. Shared Ipv6BatchEvidence supplies packet validation, MAC normalization, distinct-target tracking, temporal confirmation and generic redacted alert evidence. R066 reuses the prior AssetNetworkEvidence/AssetNetworkBaseline gate. R067/R069 reuse the existing per-instance AssetConflictTracker and only consult baseline readiness; **raw MACs are not written to the durable baseline**. No raw Info, WHOIS organization, MAC or country enrichment is placed in alert descriptions.

Five new advanced test classes and an isolated typed-traffic factory cover true positives, close benign negatives, protocol/endpoint contradictions, timestamp duplicates, source isolation, stale windows, privacy and cancellation. No traffic-only synthetic replay labels were manufactured for IPv6 packets that require parsed ICMPv6 fields.

## Preserved contracts

R066 retains three-country warmup and durable baseline readiness. R068 preserves its default threshold of 15 and five-minute window while reading existing per-rule Threshold/WindowSeconds overrides; it does not lower configured values. No production severity, confidence floor (R102=80%, R118=86%, R163=84%), Shadow/Disabled policy, approved asset, baseline-readiness safeguard or frozen holdout fixture was changed. All candidate events still pass the existing runtime tuning and suppression pipeline.

## Known limitations and risks

R066 ISO-2-only parsing intentionally misses full-text WHOIS country names and IPv6 egress; GeoIP quality is not independently established. R067 detects corroborated router identity changes, **not** a policy-verified rogue router; legitimate failover and virtual routers may resemble this. R068 cannot safely count multicast NS target addresses because TrafficRecord does not expose a parsed ND target; unicast-only NS coverage may have low recall. R069's target annotation is still unstructured capture text, not an independent parsed target field, and legitimate proxy-ND or failover may resemble a conflict. R070 classification depends on trustworthy application enrichment and transition-address metadata; legitimate tunnels may match, while encapsulation without those fields is excluded. Episode state is per rule instance and not restart-durable.

Compilation, adapter integration, replay compatibility, regressions and detection-quality metrics are **not verified**. No claim of precision, recall, F1 or gate acceptance is made.

## Deferred verification

The single Windows entry point remains `scripts/verify-all-rule-batches.ps1`; its RNNNAdvancedAccuracyBatchTests.cs filename contract automatically discovers all five new classes. Do not invoke it or any other build/test/runner command until the owner explicitly says **"now it's test time"**.

**Next batch: R071–R075.**
