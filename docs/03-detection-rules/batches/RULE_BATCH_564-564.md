# GA R564 — correlated Redis CONFIG SET OK replies across private subnets

**Branch:** `feature/carthago-reliability-hardening` · **Base HEAD:** `c33137d2128200441a43b8f95129e98db29f5321`.  
**Status:** **SOURCE CANDIDATE — UNVERIFIED; TESTS AUTHORED; 0 EXECUTED.** Source, registry, authored tests and detection-owned documents are one atomic publication candidate. The final publication SHA is recorded by the Git ref, not embedded recursively into this commit.

## New behavior and deduplication

| Rule / P input | Live evidence producer and exact predicate | Rule policy and overlap |
| --- | --- | --- |
| **R564** — external Redis CONFIG SET OK-shaped replies across private subnets; **P0024 RESP / Redis** | Existing `PacketHandler` must observe SYN, SYN-ACK, first complete RESP2 `CONFIG SET` request and a correlated first server `+OK\r\n` reply for **each** connection. Same public IPv4 client receives **two** such replies from distinct RFC1918 **/24** Redis server networks on distinct ephemeral client ports within **300 seconds**. Parser-only `RedisRespConfigSetReplyOkObserved` is required; reply direction is **private server → public client**. | **High · Candidate · Shadow · confidence floor 90% · threshold 2 private /24s · 300s window · 600s cooldown.** R437 identifies CONFIG SET attempts; R561 counts three errors on one client/server pair; R562 observes two errors then OK on one pair. **R564 is the first cross-server/subnet correlation of independently correlated OK replies**, not a duplicate of the same-pair transitions. |

The producer's internal-set `RedisRespConfigSetReplyOkObserved` flag is not populated by JSON imports or arbitrary `Info` text. The existing `PacketHandler` RESP2 inspector already correlates a complete first request with an in-order server reply after a SYN/SYN-ACK; no new inspector, schema, capture path, helper, or protocol GA was introduced. A reply shaped `+OK` is consistent with the [Redis CONFIG SET return contract](https://redis.io/docs/latest/commands/config-set/), but **does not authenticate the server or client, prove the parameter was security-relevant, establish durability, or demonstrate exploitation**. TLS-encrypted Redis, segmented first commands, missing handshakes and proxy replays are outside this sensor's claim.

## Safety and false positives

- A public management gateway, NAT, approved Redis fleet administrator or recovery automation can legitimately change multiple Redis clusters. **Explicit** `Approved.AdminHosts` suppresses known benign client activity; an empty list is not evidence of unauthorized access. No inferred approved maintenance window is invented.
- Only globally routable IPv4 clients and RFC1918 Redis servers qualify; reserved documentation/test addresses, CGNAT, same-/24 servers, reused client port, wrong reply direction, duplicate packet ID, out-of-order/equal timestamps, stale observations and contradictory TLS/HTTP/DNS fail closed.
- Instance-owned lock guards at most **512 public clients**, **32 private /24s per client** and **128 distinct packet IDs per client**. A match consumes the subnet observations; another independent two-subnet sequence within ten minutes returns `SuppressedMatch` with no duplicate event. Expired state is pruned, and saturation fails closed.
- Evidence contains only fixed operation/direction labels, counts, window and predicates; never RESP parameters/values, error strings, raw `Info`, HTTP headers, credentials, server lists or payloads. The normal `DetectionEvent` still records the observed **server→client** packet endpoints. `RuleEngine` owns journal-first persistence and downstream delivery.
- Promotion needs independently authenticated Redis server audit, approved client/service-account context, affected parameter identity and change-control evidence. Do not infer an exploited CVE, a durable configuration change or a security impact from packet-only `+OK`.

## Authored source and scenarios

- `Carthago/Engine/Rules/Expansion/R564_ExternalRedisConfigSetOkSubnetFanoutRule.cs`
- `Carthago/Engine/Rules/Catalog/RuleRegistry.cs` — exactly one additive R564 registration.
- `Carthago.Tests/R564AdvancedAccuracyBatchTests.cs` — **18 xUnit methods, 22 concrete invocations authored, 0 executed** (17 `[Fact]` and one five-case `[Theory]`).
- `docs/RULE_BATCH_564-564.md`; `docs/rules/PROTOCOL_INFORMED_THREAT_BACKLOG.md`.

The authored cases cover real bidirectional TCP producer recognition; positive two-subnet correlation; same-subnet, mixed public clients, error replies, missing handshake and unrelated PING; distinct ephemeral ports; duplicate IDs; equal/out-of-order timestamps and five-minute expiry; cooldown suppression; concurrent duplicate evaluation; Info/port/TLS/QUIC contradiction; forged JSON flag; five reserved/private address cases; secret-redacted evidence; explicit approvals and registry/Candidate/Shadow/90% floor. **No build, dotnet, xUnit, replay, holdout, capture, CI, runner, scan or benchmark was executed.** Confidence, precision, recall, F1 and field performance are unmeasured.

## Rejected alternatives and research context

- **AWS EC2 IMDS credentials → external FTP STOR/APPE:** a valuable candidate informed by [AWS's role-credential endpoint](https://docs.aws.amazon.com/AWSEC2/latest/UserGuide/instance-metadata-security-credentials.html) and [MITRE T1552.005](https://attack.mitre.org/techniques/T1552/005/) (last modified **2026-05-12**) / [DET0001](https://attack.mitre.org/detectionstrategies/DET0001/) (last modified **2026-05-12**), but **BLOCKED**: generic `HttpUri`/`HttpHost` are writable fields without an immutable IMDS credential-request provenance flag; no metadata response or FTP transfer outcome. Do not claim credential theft or build a speculative R564 from a user-supplied Host header.
- **DNS rebinding answer → subsequent HTTP request:** **BLOCKED**: current live `PacketHandler` parses DNS question and RCODE but does not populate `DnsAnswers`/`DnsTtl` from raw packets. R197 already covers private-answer evidence when externally provided; no capture-proven join exists. A shared producer integration would require owner approval.
- **CVE priority:** [CISA KEV](https://www.cisa.gov/known-exploited-vulnerabilities-catalog) is a known-exploitation catalog, while [FIRST EPSS](https://www.first.org/epss/) forecasts next-30-day exploitation probability; neither provides a Redis exploitation verdict from these packet shapes. No specific CVE or current EPSS score asserted. The Redis [CONFIG SET](https://redis.io/docs/latest/commands/config-set/) documentation was consulted **2026-11-02**; Redis's simple `OK` reply is not authenticated telemetry.

**Next cursor:** proposed **R565**, preferably a different observable threat family after live producer and duplicate audit. Frozen R102 V1, pending V2, R102/R118/R163 floors 80/86/84%, original RNNN behavior, historical protocol ledger and UI ownership remain unchanged.
