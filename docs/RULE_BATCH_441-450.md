# GA R441–R450 — Database and message-broker evidence boundaries

**SOURCE CANDIDATE — UNVERIFIED · 2026-10-30.** Existing branch:
`feature/carthago-reliability-hardening`. Live base HEAD:
`d074155048f8aed1dc8fbf2dd9c630663dc7d323` (after independent UI GA UI-09). Source commit:
`20d3a534ad91f5aaac1bbb047a851414e25bf503`; authored-test commit:
`8c6eaa16d02fb03274fcedff0299c4b3423055ed`; Kafka contract correction:
`1e55dbbf8a962bef3923dc3cd68c18953c55107a`. Final publication SHA is the documentation-descendant
remote HEAD after the single non-forced expected-HEAD update (a commit
cannot contain its own SHA). **0 builds, 0 tests executed.**

## Evidence-first ten-rule matrix

The existing [PacketHandler](../Carthago/Services/PacketHandler.cs)
produces packet/flow metadata, early cleartext HTTP request method/target/Host
and retained request-header observations, plus other independently parsed
protocols. The [TrafficRecord](../Carthago/Models/TrafficRecord.cs) has no
authenticated Cassandra CQL, Oracle TNS, Kafka, ZooKeeper four-letter or NATS
client/server exchange, nor correlated verified server responses or service
inventory for these ten behaviors. HTTPS payloads are **not** decrypted.
`Info`, application-protocol labels, client-supplied headers, URI paths and
ports cannot substitute for a trusted producer. No HTTP status or successful
access is inferred from a request.

All ten original profiles remain **Alert, confidence floor 82%, cooldown
30 minutes**. Every row below preserves the original default severity,
threshold and observation window. Original `RequiredTelemetry` includes
Flow/Http/Payload for all ten; this is a legacy descriptor contract, not proof
that each native protocol has an HTTP parser.

| Rule and existing name | Observed clue / independently missing producer | Original severity; threshold; window | Disposition; benign false-positive risk |
| --- | --- | --- | --- |
| R441 Cassandra CQL External Probe | TCP 9042/9160 or CQL text; no framed CQL OPTIONS/STARTUP and response attribution, verified service or external probe outcome. Port 9160 also represents legacy Thrift, not native CQL. | High; 1; 15m | **BLOCKED**. Approved drivers, migrations, cluster health, backups |
| R442 Oracle TNS Enumeration | TCP 1521 and TNS words; no decoded listener exchange, service-name enumeration sequence, or server response. | High; **4**; **10m** | **BLOCKED**. DBA discovery, failover, monitoring, ETL |
| R443 CouchDB Admin Probe | HTTP configuration/admin-like route, e.g. `/_node/_local/_config`; no authenticated CouchDB identity, access-control response, or probe intent. | High; 1; 15m | **BLOCKED**. Approved configuration reads, maintenance |
| R444 InfluxDB Query Endpoint Exposure | HTTP `/query` route; no verified InfluxDB target, response, authorization state or externally reachable query result. | High; 1; 15m | **BLOCKED**. Monitoring dashboards, legitimate InfluxQL clients |
| R445 ClickHouse HTTP SQL Probe | HTTP request on likely SQL interface; no verified ClickHouse service, SQL request/response attribution or access outcome. | High; 1; 15m | **BLOCKED**. BI queries, ETL, approved SQL consoles |
| R446 Neo4j Browser Exposure Probe | HTTP `/browser/` or `/db/` route; no verified Neo4j server/UI response or authentication outcome. Port 7687 is Bolt, not Browser HTTP. | High; 1; 15m | **BLOCKED**. Graph administration, internal dashboards |
| R447 RabbitMQ Management Probe | HTTP `/api/overview` or `/api/whoami` request; no verified RabbitMQ identity, management response or access outcome. | High; 1; 15m | **BLOCKED**. Monitoring, management automation |
| R448 Kafka Broker External Access | TCP 9092/9093 or `kafka` text; no decoded, correlated Kafka request/response exchange or broker identity. Kafka does not require a connection handshake. | High; 1; 15m | **BLOCKED**. Producers, consumers, approved external clients |
| R449 Zookeeper Four Letter Word Probe | TCP 2181, `ruok`/`stat`/`mntr`/`cons` words; no attributed native command and server reply. A word in an HTTP path is not a four-letter command. | **Medium**; 1; 15m | **BLOCKED**. Operations health checks and diagnostics |
| R450 NATS Broker External Access | TCP 4222/6222/8222 or `nats` text; no correlated server INFO/client CONNECT and authorization evidence. 6222 is commonly cluster routing; 8222 monitoring. | High; 1; 15m | **BLOCKED**. Approved messaging clients, clusters, health checks |

**Reachable behavior after this source change:** these ten rules return explicit
`InsufficientEvidence` missing-producer reason codes when core telemetry is
present, and `MissingTelemetry` for absent core provenance. They intentionally
emit **no alerts** without trusted upstream evidence. This prevents unsupported
service/protocol/outcome attribution, **not** a measured precision or recall
improvement. No positive operational scenario is currently supportable.

## Source changes, contracts and privacy

- [ServiceExposureEvidenceBoundary.cs](../Carthago/Engine/Rules/Expansion/ServiceExposureEvidenceBoundary.cs)
  extends the existing static, allocation-bounded missing-producer switch with
  ten rule-specific reason codes; no invented producer or trust flag.
- [EvidenceDrivenPrecisionRuleBase.cs](../Carthago/Engine/Rules/Expansion/EvidenceDrivenPrecisionRuleBase.cs)
  reuses the existing guard after core source/destination/protocol validation,
  **before** HTTP applicability, generic scoring, burst state, confidence,
  cooldown and event construction. The only change to this file is a comment
  describing the expanded R431–R450 boundary.
- [NetworkBatch441450AccuracyTests.cs](../Carthago.Tests/NetworkBatch441450AccuracyTests.cs)
  contains new xUnit source; **AUTHORED, UNEXECUTED**. Existing tests unchanged.
- Original public R441–R450 rule classes, IDs, categories, enabled flags,
  RequiredTelemetry/RequiredFields, methods, path/port indicators, default
  profiles, runtime modes, approvals, privacy controls, baseline/journal
  safeguards and shared API contracts are unchanged. No new capture, secrets,
  HTTP response parser, flow state, packet allocation or outbound I/O.
- Original descriptor inconsistencies remain separate integration proposals:
  native CQL/TNS/Kafka/ZooKeeper/NATS rules include HTTP telemetry and GET/POST
  methods despite describing native protocols; R444 and R447 describe HTTP
  behavior without `RequireHttp=true`; R449's path indicators describe native
  commands. Do not silently change these stable contracts before a reviewed
  producer/API migration.
- **Privacy limit:** the existing PacketHandler retains some HTTP request
  target/header text. A fail-closed rule prevents a new alert, **not** prior
  capture or in-memory retention. Future privacy GA must review credential
  query/header exposure on CouchDB, InfluxDB, ClickHouse, RabbitMQ and NATS
  clients, with minimal redaction and independently authored regression
  contracts. These fixtures contain only synthetic placeholders.

## Exact authored xUnit scenario inventory — 170, ZERO executed

One parameterized `[Theory]` contributes **16 invocations per rule**
(160 total); the original-profile `[Theory]` contributes **one per rule**
(10 total). All sixteen variants apply independently to R441, R442, R443,
R444, R445, R446, R447, R448, R449 and R450.

| Variant | Authored expected contract |
| --- | --- |
| plausible | Product-like HTTP path or native service port alone returns the exact missing-producer reason; no event |
| descriptor-spoof | `Info` claims verified exploitation/authentication; no trust promotion |
| approved-ops | Authorized monitoring, backup, administration or broker client does not become an attack |
| forged-audit | Client-controlled HTTP headers claiming service verification/success do not establish an audit |
| tls-only | TLS metadata without decrypted HTTP method/path does not establish an action |
| missing-source | Absent source produces core missing-telemetry reason; no event |
| malformed-target | Invalid encoded request target / truncated native frame is not a valid protocol decode |
| secret-placeholder | Synthetic query/header token placeholder cannot enter a new detection event |
| wrong-direction | Internal-to-internal flow cannot prove an external exposure |
| wrong-protocol | UDP metadata cannot impersonate native TCP/HTTP exchange |
| threshold-burst | Five independent observations cannot fabricate a missing producer, including R442 threshold 4 |
| claimed-success | Descriptive text claiming HTTP 200 or authentication success is not server evidence |
| duplicate-id | Duplicate observation ID does not manufacture evidence |
| spoofed-service-name | Host, process and ApplicationProtocol labels cannot attest service identity |
| fragmentary-native | One-byte record and native protocol keywords are not decoded frames/messages |
| after-cooldown | Repeated observations after 31 and 62 minutes still cannot emit without evidence |
| profile-invariant | Original Alert mode, 82% floor, threshold, window and 30-minute cooldown remain unchanged |

**170 concrete xUnit invocations AUTHORED; 0 EXECUTED.**
The 16 negative/adversarial cases per rule are deliberate: a genuine positive
would require a trusted producer that does not exist in the current data
contract. No builds, xUnit, replay, holdout, CI, Windows runner, benchmarking,
or production capture performed. The historical **4,940/4,940** full regression
checkpoint predates this batch and is not verification of it.

## Static divergence review and outstanding GAs

Pre-change: read live HEAD `d074155048f8aed1dc8fbf2dd9c630663dc7d323`, the prior R431–R440 source/test/doc
candidate, original ten rule classes and profiles, PacketHandler/TrafficRecord,
shared evaluator, existing boundary and test pattern. Checked same-branch UI
GA UI-09 ownership and avoided all UI paths.

Pre-publication: verify the exact five changed paths against refreshed live
HEAD, source/test/docs ancestry, reason-code consistency, naming, original
profiles, no secret capture and no unrelated changes. Source-only inspection
is **not** compilation, static analyzer execution or runtime validation.

Outstanding GAs: owner-authorized pinned-SHA Windows build and 170 xUnit
invocations; vetted native protocol decoders and request/response correlation;
authenticated service identity and asset inventory; verified external reachability
and approved administration policy; HTTP query/header privacy review; benign
versus malicious field datasets, latency/memory bounds and measured precision
and recall. R102 V1 remains **FAILED 4/6**; V2 has **0/4 approved external
sources**. Preserve R102 80%, R118 86%, R163 84% and external R102 0.75 floors.
Independent R343/R295/R275/R163 replay obligations remain open and do not
block this source-development batch.

**Next contiguous development GA: R451–R460**, after complete atomic
publication and a fresh live HEAD/source inspection. Do not begin the next
batch before this one is published.

## Authoritative protocol and engineering references

- [Cassandra CQL native protocol](https://cassandra.apache.org/doc/stable/cassandra/reference/native-protocol.html)
- [Oracle Net Services documentation](https://docs.oracle.com/en/database/oracle/oracle-database/19/netag/)
- [CouchDB configuration API](https://docs.couchdb.org/en/stable/api/server/configuration.html)
- [InfluxDB v1 query endpoint](https://docs.influxdata.com/influxdb/v1/api/query/)
- [ClickHouse HTTP interface](https://clickhouse.com/docs/en/interfaces/http)
- [Neo4j Browser deployment](https://neo4j.com/docs/browser/deployment-modes/neo4j-server/)
- [RabbitMQ management HTTP API](https://www.rabbitmq.com/docs/management)
- [Apache Kafka binary request/response protocol](https://kafka.apache.org/38/design/protocol/)
- [ZooKeeper four-letter-word commands](https://archive.apache.org/dist/zookeeper/zookeeper-3.9.0/website/zookeeperAdmin.html)
- [NATS client protocol INFO/CONNECT](https://docs.nats.io/reference/protocols/client)
- [Rule documentation standard](rules/RULE_DOCUMENTATION_STANDARD.md)
