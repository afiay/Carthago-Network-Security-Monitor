# Rule accuracy batch 13 — R061–R065

**Status: CANDIDATE — UNVERIFIED.** 37 advanced xUnit facts authored (7 + 7 + 7 + 8 + 8). No builds, xUnit, replay benchmark, holdout, or Windows runner executed.

| Rule | Evidence and state improvements | Advanced facts |
| --- | --- | ---: |
| R061 Sensitive Host Communicating Externally | Validate RFC1918 source, routable public destination, attributable TCP initiation and corroborated source-service role; do not classify DNS lookups or a sensitive destination port as a sensitive host. | 7 |
| R062 New Service Opened on Internal Host | Require an internal server-side TCP SYN-ACK; silent first service, two distinct sightings of a new port, bounded per-host state. | 7 |
| R063 Workstation Acting Like Server | Require five distinct private clients initiating to the same internal host and service port within five minutes; exclude known enriched server processes, link-local and public endpoints; suppress repeat alerts in an episode. | 7 |
| R064 First-Time Destination for Host | Require structured outbound TCP, routable public destination, eight known destinations, ready durable baseline and two distinct observations of novelty. | 8 |
| R065 First-Time ASN for Host | Validate numeric ASN and attributable public egress; require three known ASNs, ready durable baseline and two distinct observations of novelty. | 8 |

## Scope and evidence

A shared AssetNetworkEvidence component provides conservative IPv4 endpoint validation, reserved-range exclusions, TCP direction checks, bounded per-instance state, and durable BaselineStore observation. The five R061–R065 adapters are updated without editing other rules or the existing ExtendedRuleDetectors implementation. All alert descriptions are generic and omit raw process text, HTTP content, ASN, and organization values. Tests use typed traffic records and isolated ready-baseline fixtures, not fabricated malicious replay labels.

R063's five-source threshold, R064's eight-destination warmup and R065's three-ASN warmup remain intact. No production mode, severity, confidence floor (R102=80%, R118=86%, R163=84%), asset approval, baseline readiness, Shadow/Disabled policy, or frozen holdout label was changed. R064/R065 require a ready nonlearning durable baseline and successful observation persistence; no readiness bypass or synthetic accuracy claims are permitted.

## Outstanding risks

R061 depends on accurate source-port and service/process enrichment, and text corroboration for SQL Server remains lower trust than endpoint instrumentation. A SYN-ACK in R062 establishes a server response, not a newly deployed or authorized service; UDP services are not covered. R063 may observe authorized scanners or load balancers. R064/R065 use per-instance warmup, so a restart can delay novelty detection even with a ready persisted baseline. The first-seen ASN depends on enrichment attribution and freshness. The candidate explicitly excludes IPv6 until its public-routability semantics are reviewed. In-memory trackers do not persist episode state.

## Deferred verification

The sole future Windows entry point is scripts/verify-all-rule-batches.ps1. Its filename contract discovers all five new R061–R065 advanced test classes. All 37 facts are authored but not executed; no build, replay, holdout, or field precision/recall/F1 claim is made. Testing remains deferred until the owner explicitly says "now it's test time".

**Next batch: R066–R070.**
