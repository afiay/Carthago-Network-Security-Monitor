# R106-R110 candidate detection hardening
**CANDIDATE — UNVERIFIED.** Five rules and 25 advanced xUnit facts authored. No build, xUnit, replay, holdout or Windows runner execution occurred.

| Rule | Change | Advanced cases |
| --- | --- | --- |
| R106 | Structured TCP admin probe before sweep state; typed outbound HTTP upload and packet dedup. | Four-target positive, insufficient sweep, stale sweep, forged Info, download/SNI contradiction. |
| R107 | Typed outbound upload and dedup before byte/event/destination windows; no free-text metadata. | Six destinations, benign download, one destination, duplicate record, contradictory evidence. |
| R108 | Typed coherent TCP flows and packet dedup; upload evidence excludes free-text and volume-only claims. | Outbound-heavy, balanced inbound, low volume, replay, contradictory SNI/transport. |
| R109 | Typed HTTP GET, URI-path payload classification only, dedup, URI query redaction. | Script fetch, normal blob, README, Info-only claim, duplicate/token privacy. |
| R110 | Typed HTTP upload, parsed chat action, dedup, bot/webhook URI redaction. | Telegram send, generic browsing, GET webhook, Info-only claim, token/SNI contradiction. |

Source helper: `Carthago/Engine/Rules/Abstractions/NetworkBatch106110Evidence.cs`.
Shared test fixture: `Carthago.Tests/NetworkBatch106110Context.cs`.
Windows acceptance entry point remains `scripts/verify-all-rule-batches.ps1`; it is **not executed**.
Existing confidence floors, configured thresholds, Shadow/Disabled policy, asset approvals, baselines and frozen holdout remain unchanged. No manufactured replay labels or accuracy metrics.

Risks: R106 shared sweep state still needs operational bounding and approval context; R107/R108 window concurrency and timestamp skew need live evaluation; R109/R110 redact raw paths to prevent credential exposure but reduce path-level analyst visibility. Tests are candidate source only, not measured pass evidence.
