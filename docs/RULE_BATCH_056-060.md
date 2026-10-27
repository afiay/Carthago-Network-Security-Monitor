# Rule accuracy batch 12 — R056–R060

**Status: CANDIDATE — UNVERIFIED.** 48 advanced xUnit facts (9 + 9 + 10 + 10 + 10) authored. No builds, xUnit, replay benchmark, frozen holdout, or Windows runner executed.

**Source/test candidate commit:** `8494092f871fbeea46cce72500706f9c2406944d`. Publication used sequential, checked, non-forced fast-forward file commits on the existing branch; no unrelated files were overwritten.

| Rule | Evidence/precision and state changes | Advanced xUnit facts |
| --- | --- | ---: |
| R056 Time Skew / Clock Jump | Preserve inclusive 60-second threshold; reject stale/future/non-UTC health snapshots; suppress duplicate clock-skew episodes; rearm on recovery or sign reversal; avoid exposing exact offset. | 9 |
| R057 New Device Appeared on Network | Require two distinct, matching ARP is-at claims for one RFC1918 address and valid unicast source MAC; isolate devices, reject replayed timestamps and contradictory headers; do not assert authorization status. | 9 |
| R058 New MAC Vendor Seen | Track globally administered MAC OUI prefixes, not guessed vendor names; establish a silent initial prefix baseline and require two distinct observations for a novel prefix; exclude locally administered MACs. | 10 |
| R059 Same MAC Using Multiple IPs | Require a previously observed private IP and two temporally distinct ARP claims for a second private IP by the same MAC; cancel unconfirmed conflicts on baseline reassertion; isolate MAC histories. | 10 |
| R060 Same IP Used by Multiple MACs | Require a previously observed MAC and two temporally distinct corroborated ARP claims for a second MAC on the same private IP; isolate IP histories; reject duplicate, stale and contradictory evidence. | 10 |

## Evidence and scope

The asset rules only consume explicit local-link `ARP ... is-at ...` claims whose sender IP and Ethernet source MAC agree with the claim. Generic Ethernet MAC/IP pairings on routed TCP/UDP traffic are not trusted: the MAC may identify a gateway rather than the source host. Invalid IPv4, public addresses, multicast/broadcast MACs, missing headers, malformed or contradictory ARP summaries, and non-UTC evaluation timestamps cannot seed the new state. The in-memory trackers are per rule instance, lock-protected, time-bounded, and size-bounded; the retained MAC values are not included in detection summaries or evidence.

R057 and R058 are **inventory observations**, not authorization verdicts. R058 reports novelty of an OUI prefix rather than claiming a verified vendor name. R059 and R060 are **address-mapping anomalies**, not independent proof of spoofing or compromise. Configured rule modes, confidence floors (R102=80%, R118=86%, R163=84%), asset-approval/baseline-readiness safeguards, and frozen holdout identities were not edited. No rule was disabled, no threshold was lowered, and no malicious labels were altered.

The R056 scenarios use typed `RuleEngineHealthSnapshot` evidence. R057–R060 scenarios use typed, internally consistent ARP observations. No traffic-only replay fixture was fabricated for a health clock, and no malicious labels were assigned to legitimate inventory changes; the existing replay/holdout datasets remain untouched.

## Deferred verification and residual risks

The only acceptance entry point remains `scripts/verify-all-rule-batches.ps1`; it discovers all five new advanced test classes by filename. It is **not run** until the owner explicitly says `now it's test time`. All 48 facts are authored, not executed, and there is no precision/recall/F1 claim.

- The ARP summary format and sender-MAC availability depend on the capture path. Real traffic with missing or differently formatted ARP evidence may be excluded; this needs later integration verification.
- ARP spoofing, DHCP failover, proxy ARP, virtual interfaces, address aliases and authorized device onboarding can look similar. R059/R060 deliberately report an inventory anomaly without a malicious verdict.
- A fresh in-memory baseline is not a durable approved inventory. Restart can re-observe devices and vendor prefixes. Production novelty semantics require durable, explicitly ready and approved asset baselines before promotion.
- MAC OUI prefixes are not reliable vendor identity for locally administered or randomized addresses; those are excluded from R058.
- Per-instance state does not survive restart. The 2-minute confirmation and 30-minute idle retention are candidate evidence windows, not validated field thresholds.
- All new code and tests remain uncompiled and unexecuted. The eventual single Windows run must verify compilation, regression, replay, holdout, coverage and any unexpected detection-quality impact.

**Next batch after this candidate: R061–R065.**
