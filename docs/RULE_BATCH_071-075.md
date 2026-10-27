# Rule accuracy batch 15 - R071-R075

**Status: CANDIDATE - UNVERIFIED.** 35 advanced xUnit facts authored (7 per rule). No build, xUnit, replay benchmark, frozen holdout, Windows runner or other project test was executed.

| Rule | Candidate evidence and state changes | Facts |
| --- | --- | ---: |
| R071 IPv6 Traffic on IPv4-Only Network | Requires operator opt-in `Rules.R071.Ipv4OnlyApproved=1`, exact `NetworkType=IPv4Only` enrichment, a ready non-learning baseline, non-link-local unicast IPv6 transport, and two distinct observations of one flow. | 7 |
| R072 Suspicious Multicast Discovery Burst | Counts only typed IPv6 UDP mDNS (ff02::fb/5353), LLMNR (ff02::1:3/5355), and SSDP (ff02::c/1900). Per-source/per-service default 20 observations in 60 seconds. | 7 |
| R073 RDP Lateral Movement Burst | Counts five distinct internal IPv4 TCP SYN destinations to port 3389 in five minutes per initiating host. | 7 |
| R074 WinRM / PowerShell Remoting Sweep | Counts five distinct internal IPv4 TCP SYN destinations to port 5985 or 5986 in five minutes, isolated by source and port. | 7 |
| R075 WMI / DCOM Lateral Movement | Requires both structured WMI/DCOM application classification and internal TCP SYN to RPC endpoint mapper port 135. Three distinct targets in five minutes per source/classification. | 7 |

## Code and coverage

A shared `NetworkBatch071075Evidence` helper validates structured endpoint/transport fields and emits redacted evidence without raw `Info`, credentials, MACs or payload text. A thread-safe bounded window tracks distinct destinations or unique observation timestamps, isolates sources/services, rejects duplicate and out-of-order timestamps, and rearms after expiry. R071 reuses the existing IPv6 sequence state and durable baseline-readiness gate.

Five new `RNNNAdvancedAccuracyBatchTests.cs` classes and one typed-traffic factory cover genuine positives, close benign negatives, evasions, incomplete/contradictory evidence, duplicate timestamps, stateful sequences, isolation, cancellation and privacy. No misleading traffic-only development replay labels were fabricated for fields that require structured capture metadata.

## Preserved contracts

No production rules.json defaults, existing rule severity, configured threshold override, confidence floors (R102=80%, R118=86%, R163=84%), Shadow/Disabled policy, approved asset, baseline-readiness safeguard or frozen holdout fixture was changed. R072-R075 continue to read configured Threshold and WindowSeconds overrides. R071 is fail-closed without explicit policy opt-in; the opt-in is not a substitute for an independently approved asset inventory or runtime rule enablement. Existing tuning and suppression remain authoritative.

## Limitations and deferred verification

R071 depends on reliable NetworkType enrichment and operator policy; without explicit opt-in it intentionally emits no violation claim. R072 may still observe legitimate service discovery storms and excludes IPv4 multicast. R073/R074 can resemble authorized administration and do not prove authentication or remote execution. R075 depends on trustworthy WMI/DCOM classification; TCP/135 alone is not WMI proof, and dynamic RPC ports are outside this candidate. State is per rule instance and not restart-durable; counters cap at 4096 observations/targets per key. The candidate may reduce recall on incomplete capture records.

Compilation, adapter compatibility, full regression, precision, recall, F1 and acceptance are **not verified**.

## Deferred one-run Windows verification

`scripts/verify-all-rule-batches.ps1` remains the sole entry point. Its filename-based discovery will include all five new classes. Do not invoke it, any xUnit/build/replay/holdout command, or the Windows runner until the owner explicitly says **"now it's test time"**.

**Next batch: R076-R080.**
