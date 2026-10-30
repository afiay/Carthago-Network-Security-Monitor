# GA R421–R430 — Management endpoint and service-exposure provenance

**SOURCE CANDIDATE — UNVERIFIED · 2026-10-30.** Existing branch:
`feature/carthago-reliability-hardening`. Inspected live base HEAD `7ca931226e8f08b9c98bfd0546ea51f68ff6f99f`. Source/test commits and
publication SHA are recorded in the GA report. A Git commit cannot contain
its own SHA; final publication is the documentation-descendant branch HEAD.

## Ten-rule evidence contracts and original profiles

All ten original rule classes inherit
[NetworkApplianceExposurePrecisionDetectionRuleBase](../Carthago/Engine/Rules/Expansion/NetworkApplianceExposurePrecisionDetectionRuleBase.cs).
The shared [evaluator](../Carthago/Engine/Rules/Expansion/EvidenceDrivenPrecisionRuleBase.cs)
uses early [PacketHandler](../Carthago/Services/PacketHandler.cs) HTTP
request metadata, endpoints and ports. The bounded 4,096-byte early TCP
inspection is not TLS decryption, authenticated service inventory,
request/response correlation, verified access-control outcome or malicious
probe attestation. `Info`, Host and client-supplied headers are untrusted.
The original `RequiredTelemetry` profile expresses intent, not proof
that all its fields have authoritative producers.

| ID | Original rule name | Observable request clue | Missing trusted evidence | Disposition | Mode / severity / floor | Threshold / window / cooldown | Legitimate-traffic false-positive risk |
| --- | --- | --- | --- | --- | --- | --- | --- |
| R421 | Synology DSM Admin Probe | `/webman/`, TCP/5000 | Trusted Synology DSM asset identity and distinct admin-probe behavior are absent. | **BLOCKED** | Alert / High / 82% | 1 / 10m / 30m | Normal NAS administration and photo web API |
| R422 | VMware vCenter SOAP Probe | `/sdk`, TCP/443 | Trusted vCenter identity and parsed SOAP operation provenance are absent. | **BLOCKED** | Alert / High / 82% | 1 / 10m / 30m | Authorized vSphere SDK clients and backups |
| R423 | VMware ESXi Hostd Probe | `/host`, TCP/443 | Trusted ESXi hostd identity and differentiated probe behavior are absent. | **BLOCKED** | Alert / High / 82% | 1 / 10m / 30m | ESXi maintenance and health checks |
| R424 | Proxmox API Exposure Probe | `/api2/json`, TCP/8006 | Trusted Proxmox identity and correlated externally reachable API response are absent. | **BLOCKED** | Alert / High / 82% | 1 / 10m / 30m | Proxmox API automation and monitoring |
| R425 | Apache Solr Admin Probe | `/solr/admin`, TCP/8983 | Validated Solr service identity and probe sequence are absent. | **BLOCKED** | Alert / High / 82% | 1 / 10m / 30m | Search-cluster maintenance and SolrCloud checks |
| R426 | Elasticsearch Cluster Info External | `/_cluster/health`, TCP/9200 | Trusted Elasticsearch identity and correlated cluster-info response are absent. | **BLOCKED** | Alert / High / 82% | 1 / 10m / 30m | Routine cluster health monitoring |
| R427 | Kibana Console Exposure | `/app/dev_tools`, TCP/5601 | Validated Kibana identity and access-control response evidence are absent. | **BLOCKED** | Alert / High / 82% | 1 / 10m / 30m | Authorized Dev Tools use and proxy routing |
| R428 | Grafana Admin Login Probe | `/api/admin`, TCP/3000 | Verified Grafana identity and authenticated probe/audit context are absent. | **BLOCKED** | Alert / Medium / 82% | 1 / 10m / 30m | Legitimate dashboard login and admin automation |
| R429 | Prometheus Metrics Exposure External | `/api/v1/query`, TCP/9090 | Trusted Prometheus identity and correlated metrics/query response are absent. | **BLOCKED** | Alert / Medium / 82% | 1 / 10m / 30m | Routine metrics scraping and PromQL automation |
| R430 | Jupyter Notebook Token Probe | `/tree?token=synthetic-placeholder`, TCP/8888 | Validated Jupyter identity and token-verification outcome are absent. | **BLOCKED** | Alert / High / 82% | 1 / 10m / 30m | Normal notebook login and research sessions |

R422 and R423 share ordinary VMware SDK paths, so the request alone
cannot distinguish vCenter from ESXi. R425's `/solr/#/` fragment is not
transmitted in a normal HTTP request. R426 cluster health and R429
Prometheus queries are ordinary monitoring requests, not exposure proof.
R430's token-bearing URI may contain credentials: never promote raw
query values into detection evidence. R421/R424/R427/R428 may be normal
management paths. No successful login, exploit, unauthorized scan or
exposure is asserted from a request shape.

## Source changes, compatibility and privacy

- [EvidenceDrivenPrecisionRuleBase.cs](../Carthago/Engine/Rules/Expansion/EvidenceDrivenPrecisionRuleBase.cs):
  ten per-ID missing-producer reasons before `CollectSignals`, window
  mutation, confidence, cooldown or event construction.
- [NetworkBatch421430AccuracyTests.cs](../Carthago.Tests/NetworkBatch421430AccuracyTests.cs):
  adversarial and original-profile regression contracts, UNEXECUTED.
- [Progress ledger](RULE_HARDENING_PROGRESS.md): next GA and evidence status.

All ten original classes, public IDs, Alert modes, severities, confidence
floors, threshold 1, 10-minute windows, 30-minute cooldowns, approvals,
suppression, privacy, journal, baseline and frozen R102 evidence remain
unchanged. No new capture, credential storage, raw headers or query values,
response-body collection, shared API or UI change. These rules cannot emit
until independently trusted producers are integrated. This prevents
unsupported attribution but does not validate detection recall.

## Exact authored xUnit inventory — 120 invocations, ZERO executed

Two `[Theory]` methods yield 11 adversarial variants plus one original
profile invariant **for every ID R421 through R430** (110 + 10 = 120).

| Scenario | Contract and expected outcome |
| --- | --- |
| plausible | Rule-specific endpoint/port request with no authenticated service/response; exact missing-producer reason, no event |
| descriptor-spoof | `Info` claims verified product and successful attack; no event |
| normal-admin | Benign browser login and approved administration; no attribution |
| forged-asset-header | Client-provided product/verification/outcome headers cannot attest exposure |
| tls-only | Encrypted metadata cannot reveal management request or outcome |
| missing-source | Missing source attribution cannot produce an event |
| malformed-path | Invalid encoding and traversal-like path cannot establish a probe |
| privacy-placeholder | Synthetic token-like URI/header cannot generate alert evidence |
| wrong-direction | Internal-to-internal administration is not external exposure |
| repeated-requests | Eight requests cannot manufacture authenticated identity or outcome; exact reason |
| claimed-verified | `Info` says HTTP 200 and verified probe; no authenticated evidence |
| profile-invariant | Alert mode, original threshold/floor/window/cooldown preserved |

**120 concrete xUnit invocations AUTHORED, 0 EXECUTED.**
No build, xUnit, replay, holdout, CI, benchmark, Windows runner or
production capture. No compile, pass, precision, recall or certification
claim. Historical 4,940/4,940 predates these candidates.

## Static divergence review and outstanding GAs

Before change: live HEAD, R411–R420 source/tests/docs, R421–R430
original rule classes, real HTTP metadata producer and shared evaluator
inspected. Before publication: verify only owned evaluator, new tests,
this batch document and ledger differ; confirm no UI/other rules,
serialized contracts, credential capture or thresholds changed.
Open quality GAs: owner-authorized Windows compilation and execution of
120 scenarios; authenticated product/asset inventory, verified
request-response outcomes and scan classification; approved admin
allowlists; privacy audit of existing HTTP URI token retention;
representative benign/malicious field corpora, measured false positives,
false negatives and performance. Independent R343/R295/R275/R163
replay GAs remain open. Frozen R102 V1 FAILED 4/6 and V2 0/4 approved
sources; confidence floors preserved.

**Next consecutive development GA: R431–R440**, only after coherent
publication and fresh live HEAD inspection.

## References

- [Elasticsearch REST APIs](https://www.elastic.co/docs/reference/elasticsearch/rest-apis)
  — health and cluster endpoints are normal administrative APIs.
- [Prometheus HTTP API](https://prometheus.io/docs/prometheus/latest/querying/api/)
  — `/api/v1/query` is a standard request, not proof of public exposure.
- [Rule documentation standard](rules/RULE_DOCUMENTATION_STANDARD.md).
