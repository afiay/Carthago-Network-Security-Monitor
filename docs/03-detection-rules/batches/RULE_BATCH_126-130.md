# R126-R130 identity-access evidence and state hardening

**CANDIDATE - UNVERIFIED.** 35 new xUnit facts (seven per rule); none executed.
No Windows runner, build, replay, frozen holdout or benchmark was invoked.

| Rule | Precision change | Authored cases |
| --- | --- | --- |
| R126 | Require attributed TCP SSH failure rather than SSH text or port alone; independent record-ID burst in a bounded per-instance window. | Eight failures, duplicate replay, success negative, missing transport/classification, internal/UDP negatives, expiry, privacy/Shadow. |
| R127 | Require coherent TCP HTTP request, explicit admin route and actual IP boundary; exclude vendor-appliance portals and ambiguous substrings. | Inbound positive, internal benign, generic login, appliance separation, method/UDP, SNI/docs, privacy/Shadow. |
| R128 | Require vendor-attributed host and management route; do not promote vendor strings in Info; generic admin belongs to R127. | Appliance positive, generic admin, docs, forged Info, internal/UDP, SNI/method, privacy/Shadow. |
| R129 | Require observable GET callback query with nonempty SAMLResponse/id_token/access_token or an HTTP redirect target; fragments and normal code/state callbacks do not count. | Token query, code/state benign, fragment negative, cleartext redirect, noncallback/empty token, transport/SNI, privacy/Shadow. |
| R130 | Require POST login submission with attributed HTTP transport; count only identity-attributed or explicitly failed requests, dedupe packet IDs, require 20 failures or 5 distinct identities within a 20-request window. | Failed burst, replay, single-identity benign, many identities, GET/transport negatives, expiry/missing identity, privacy/Shadow. |

All five keep their configured default Shadow policy, thresholds, windows,
cooldowns and minimum confidence. R102 80%, R118 86%, R163 84% and
asset approval/baseline-readiness gates are unchanged. Frozen V1 R102 remains
FAILED at 4/6; V2 awaits independent approved PCAPs. No holdout files or
replay labels changed. The single later Windows verification entry point
`scripts/verify-all-rule-batches.ps1` remains unchanged and automatically
discovers R126-R130 advanced test classes.

**Privacy:** IdentityAccessPrecisionDetectionRuleBase omits raw HTTP
paths from auto-generated evidence for R127-R130 (as already done
for R123). The rules emit fixed route categories and fixed cooldown
categories; raw authentication query values, redirect targets, and path
segments are not persisted. Burst state retains identity strings only
in bounded, instance-owned memory for distinct counting.

**Unverified risks:** SSH failure text is parser-adjacent, not a typed
authentication outcome; HTTP fields require a trusted capture/proxy adapter.
Source and destination must be parseable IPs and can reject proxy-only
host telemetry. HTTP fragments are not wire-observable, intentionally
suppressed. Vendor-host classification is intentionally narrow and may
miss other appliances. Out-of-order events do not increase burst counts.
The per-instance 256-key/512-event bounds may evict busy tenants;
cooldown behavior remains governed by existing precision runtime.
Operational false positives, emitted alerts and concurrent capture
require later owner-authorized evaluation.

**Next contiguous batch: R131-R135.**
