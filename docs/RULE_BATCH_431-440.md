# GA R431–R440 — Service identity and database protocol evidence

**SOURCE CANDIDATE — UNVERIFIED · 2026-10-30.** Existing branch:
`feature/carthago-reliability-hardening`. Live base HEAD:
`174ecd2fc072ac59bdf5ae1d11b8c218487803e5`. Source commit: `c54e830a6b4e0d09f99747f8a6b7d38d1d2f9acd`; authored-test commit:
`208bb779d5ec5422904d70543c970d6712356def`. **Publication SHA is the final documentation commit/remote
HEAD**, recorded by GitHub after the single expected-HEAD protected update;
a Git commit cannot contain its own SHA. **0 builds, 0 tests executed.**

## Evidence-first ten-rule matrix

[PacketHandler](../Carthago/Services/PacketHandler.cs) currently emits
packet/flow metadata and bounded early cleartext HTTP method, request-target,
Host and request-header observations. These are *client request clues*, not
authenticated server inventory, native database login/RESP/Memcached protocol
decodes, correlated server responses, successful access, or malicious intent.
TLS metadata is not decrypted. The existing
[precision evaluator](../Carthago/Engine/Rules/Expansion/EvidenceDrivenPrecisionRuleBase.cs)
formerly allowed generic signal scoring of untrusted names/ports/paths.

| Rule and original name | Real clue / absent trusted producer | Original Alert severity, confidence, threshold, window, cooldown | Disposition and legitimate false-positive risk |
| --- | --- | --- | --- |
| R431 Airflow Admin Endpoint Probe | HTTP `/api/v1/dags`, `/admin/`, port 8080 are request clues; verified Airflow target, response and probe sequence absent | High; 82%; 1; 10m; 30m | **BLOCKED**. DAG inventory, orchestration health checks, approved administration |
| R432 Consul Nomad Admin Probe | `/v1/agent`, `/v1/jobs`, ports 8500/8600/4646 are ambiguous; authenticated target/ACL context absent | High; 82%; 1; 10m; 30m | **BLOCKED**. Service discovery, scheduler clients, ACL-authorized API use |
| R433 PostgreSQL External Login Attempt | TCP flow and generic SQL words; no parsed PostgreSQL startup/auth exchange or server outcome | High; 82%; 1; 15m; 30m | **BLOCKED**. DBA access, ETL, backup and monitoring |
| R434 MySQL External Login Attempt | TCP flow and generic SQL words; no parsed MySQL handshake/login or authentication outcome | High; 82%; 1; 15m; 30m | **BLOCKED**. Replication, migrations and approved remote DBA |
| R435 MSSQL External Login Attempt | TCP/1433 is a port clue; no TDS LOGIN7/authentication evidence or trusted target identity | High; 82%; 1; 15m; 30m | **BLOCKED**. SQL Server management, scheduled ETL and backups |
| R436 MongoDB External Exposure Probe | Generic database traffic; no MongoDB wire protocol, correlated response or external reachability proof | High; 82%; 1; 15m; 30m | **BLOCKED**. Database monitoring, backups, admin clients |
| R437 Redis CONFIG SET Indicator | TCP/6379, `config set` text; no parsed RESP command/arguments or source attribution | Critical; 82%; 1; 15m; 30m | **BLOCKED**. Authorized runtime configuration |
| R438 Redis Replication Abuse Indicator | TCP/6379, `replicaof`/`slaveof` text; no parsed RESP command, replication state or response | Critical; 82%; 1; 15m; 30m | **BLOCKED**. Legitimate replication reconfiguration |
| R439 Memcached Stats Enumeration | TCP/11211; no parsed `stats` command/response or independent flow sequence | Medium; 82%; **4**; 10m; 30m | **BLOCKED**. Cache telemetry and diagnostic polling |
| R440 Elasticsearch Snapshot Repository Probe | HTTP `/_snapshot` on 9200 is a request shape; no trusted Elasticsearch target, access-control result or correlated response | High; 82%; 1; 15m; 30m | **BLOCKED**. Authorized snapshot listing, backups and repository maintenance |

The source names, original `RequiredTelemetry`, `RequiredFields`,
`PathIndicators`, `Methods`, `Ports`, public rule IDs, serialized
contracts, default Alert modes, severities and profiles are preserved. The
existing R433–R435 `RequireHttp=true` flag is a separate original contract
mismatch for native database protocols; it was **not silently changed**.
R432 mixes Consul and Nomad API surfaces, while port 8600 does not itself
attest an HTTP API. R440's broad original health/index path indicators are
not sufficient evidence of a snapshot repository probe.

## Source-only change, boundaries and privacy

- [ServiceExposureEvidenceBoundary.cs](../Carthago/Engine/Rules/Expansion/ServiceExposureEvidenceBoundary.cs)
  centralizes ten precise missing-producer reason codes, without new telemetry,
  inferred server identity, synthetic evidence flags or credential storage.
- [EvidenceDrivenPrecisionRuleBase.cs](../Carthago/Engine/Rules/Expansion/EvidenceDrivenPrecisionRuleBase.cs)
  invokes this fail-closed boundary **after core source/destination/protocol
  validation but before HTTP applicability, generic signals, burst counters,
  confidence, cooldown, or `DetectionEvent` construction**. This order is
  deliberate for native PostgreSQL/MySQL/TDS flows.
- [NetworkBatch431440AccuracyTests.cs](../Carthago.Tests/NetworkBatch431440AccuracyTests.cs)
  is newly authored and **UNEXECUTED**. No existing test file was rewritten.
- No UI, model, service, parser, capture, runner, workflow, shared API, holdout,
  rule class, configuration, approval, baseline, journal or confidence-floor
  change. No payload/secret capture, raw HTTP query/header evidence, or new
  outbound communication. No new state/allocations per packet beyond a
  nullable tuple of static strings; existing window/cooldown state is not
  touched for these ten rules.

**Consequence:** These ten rules now intentionally emit **no alerts** until
trustworthy producer integration is separately designed and validated. This
suppresses unsupported family/product/outcome attribution but does **not**
establish detection recall or a verified false-positive rate.

## Exact authored xUnit scenario inventory — 140, ZERO executed

One parameterized adversarial `[Theory]` contributes **13 invocations per
rule** (130 total), plus one original-profile `[Theory]` contributes
**one invocation per rule** (10 total). The inventory applies independently
to **each** of R431, R432, R433, R434, R435, R436, R437, R438, R439 and R440.

| Scenario | Authored contract |
| --- | --- |
| plausible | Product-like request or native TCP port alone returns exact missing-producer reason; no event |
| descriptor-spoof | `Info` asserts verified compromise; no trust promotion |
| benign-maintenance | Authorized health/DBA/orchestrator activity not attributed as attack |
| forged-audit | Client-controlled headers claim authentication and success; no event |
| tls-only | Encrypted request without decrypted method/path cannot establish action |
| missing-source | Core provenance failure, no event |
| malformed-path | Invalid encoding/target and generic native text cannot establish action |
| privacy-placeholder | Synthetic token-bearing URI/header does not enter alert evidence |
| wrong-direction | Internal administrative flow is not external probe proof |
| wrong-protocol | UDP metadata cannot impersonate an authenticated native protocol exchange |
| repeated-threshold | Four independent requests cannot satisfy missing producer, including R439 threshold 4 |
| claimed-success | `Info` claims HTTP 200/login success, but no authenticated response exists |
| duplicate-id | Duplicate observation cannot fabricate a validated event |
| profile-invariant | Original Alert mode, confidence 82%, threshold (R439=4), window and cooldown preserved |

**140 concrete xUnit invocations AUTHORED; 0 EXECUTED.**
No positive assertion is scientifically supportable without the missing
producer; all cases are negative/adversarial/profile invariants. No build,
xUnit, replay, holdout, benchmark, CI, Windows runner or production capture
was performed. Historical 4,940/4,940 predates these changes.

## Static divergence review and remaining quality GAs

Pre-change: inspected live HEAD, R421–R430 publication, all ten original
R431–R440 classes, `PacketHandler`, `TrafficRecord`, shared evaluator,
original profiles and the current test pattern. Pre-publication: compare
exact owned paths against refreshed remote HEAD, check source/test/docs
descend from the same base and no UI stream changes are overwritten.
Source-only inspection is **not** compilation or runtime verification.

Outstanding GAs: owner-authorized pinned-SHA Windows build and execution
of the 140 authored scenarios; trusted service inventory, native PostgreSQL,
MySQL, TDS, MongoDB, Redis RESP and Memcached command/response producers;
authenticated Airflow/Consul/Nomad/Elasticsearch response correlation;
approved administration and backup allowlists; privacy review of existing
HTTP URI/header retention; measured benign/malicious precision/recall and
bounded resource costs. Frozen R102 V1 remains **FAILED 4/6**, V2 has
**0/4** approved external sources; R102 80%, R118 86%, R163 84% and
external R102 0.75 floors remain unchanged. Independent
R343/R295/R275/R163 replay GAs remain open.

**Next contiguous development GA: R441–R450**, after atomic publication and
fresh live HEAD/source inspection. No unrelated workstream is blocked.

## Authoritative references

- [Airflow public REST API interface](https://airflow.apache.org/docs/apache-airflow/stable/_api/index.html)
- [Consul agent HTTP API](https://developer.hashicorp.com/consul/api-docs/agent)
- [Nomad jobs HTTP API](https://developer.hashicorp.com/nomad/api-docs/jobs)
- [PostgreSQL frontend/backend protocol](https://www.postgresql.org/docs/current/protocol-flow.html)
- [Redis CONFIG SET](https://redis.io/docs/latest/commands/config-set/)
- [Memcached basic text protocol](https://docs.memcached.org/protocols/basic/)
- [Elasticsearch snapshot repository API](https://www.elastic.co/docs/api/doc/elasticsearch/operation/operation-snapshot-get-repository)
- [Rule documentation standard](rules/RULE_DOCUMENTATION_STANDARD.md)
