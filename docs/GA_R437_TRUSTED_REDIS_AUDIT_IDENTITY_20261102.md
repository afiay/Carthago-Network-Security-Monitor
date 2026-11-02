# GA R437 — Trusted Redis audit identity and authorization evidence

**Status:** SOURCE CANDIDATE — UNVERIFIED. No Windows build, xUnit, benchmark, trusted producer or independent external capture was executed in this GA. No R437 positive detections or Alert-mode promotion.  
**Branch:** `feature/carthago-reliability-hardening` only.  
**Last owner-green baseline:** `e73650fc594179d6c7c1db5d5b933a8eff4bd082` — zero-warning Release build, 9,762/9,762 xUnit. The earlier Redis request/reply correlation GA remains separately unverified.

## Why this GA reuses the existing trust system

Carthago already implements `TrustedAuditReceiptVerifier` with operator-pinned RSA-PSS/SHA-256 public-key trust anchors, rule-specific operation scoping, signed claim schema validation, replay rejection, bounded lifetime, and `TrustedAuditReceiptCorrelation` requiring **two distinct verified signing issuers** under the same verifier registry with matching actor/resource/trace hashes. We extend that existing mechanism for R437 instead of introducing an unauthenticated Redis socket listener, a second signer, or a new detection-rule series.

Redis documentation distinguishes:
- `ACL LOG`: authentication failures and denied ACL events; **not successful CONFIG SET transaction auditing**.
- `CLIENT LIST`: connection/ACL username metadata, **not authoritative historical CONFIG SET success**.
- Redis Software's optional `connection_and_crud` audit stream: a command event has `action: "command"`, `command`, `status`, client/server IP and port, database UID, connection ID and sequence counters. For command records **status 9 = completed successfully, 10 = failed**. The documented command name `CONFIG` does *not* by itself attest the **SET subcommand**, nor does the notification transport provide a signed authenticated identity guarantee. Auditing is optional, nonblocking, can drop records, and is not an independent capture source.
- A trusted external collector would have to separately establish the exact `CONFIG SET` operation, server identity, account authorization and capture-to-audit transaction key before making a claim. **Do not sign a generic `CONFIG`/status=9 record as `RedisConfigSetCommandSucceeded` without this evidence.**

Sources:
- https://redis.io/docs/latest/commands/acl-log/
- https://redis.io/docs/latest/commands/client-list/
- https://redis.io/docs/latest/operate/rs/security/audit-events/
- https://redis.io/docs/latest/management/security/acl/

## Implemented source-only primitives

1. `TrustedAuditReceiptVerifier.RuleOperations` now permits *only* the exact signed R437 operation `RedisConfigSetCommandSucceeded`, with the original operator-provisioned issuer `AllowedRuleIds` scope. Existing signature domain separation, strict canonical claim fields, public-key requirements and replay cache remain unchanged. A generic `RedisConfigCommandSucceeded` or wrong rule ID is rejected even if signed.
2. `EnvironmentTuningOptions.Approved.RedisServers` is an **optional, explicit operator inventory** added alongside the pre-existing `Approved.AdminHosts`. `ApprovedAssetRegistry.HasApprovedRedisServers` and `IsApprovedRedisServer` reuse existing normalized host matching. Missing inventory is **UNCONFIGURED**, not automatically trusted; no existing approval rule's decision changes.
3. `RedisTrustedAuditCandidateGate` accepts **only** an existing `CorrelatedAuditReceipts` capability (never raw JSON, packet Info or a free-form trusted flag), a capture-only Redis server-reply `TrafficRecord`, an explicitly configured `ApprovedAssetRegistry`, and a separately captured UTC event timestamp. It requires both receipt rule/operations to be R437, matching signed client/server endpoints with the reverse-direction packet, observed TCP/6379 `RedisRespConfigSetReplyOkObserved` without error, two signed event timestamps within 30 seconds of observed capture, a configured approved Redis server, and a configured admin allowlist. It differentiates approved clients, unapproved clients, missing inventory, mismatched endpoints and clocks.
4. `RedisSignedAuditCandidateIntake` combines existing `TrustedAuditReceiptVerifier.TryVerify`, `TrustedAuditReceiptCorrelation.TryCorrelate`, and the R437 gate. It is **opt-in** and must be supplied a verifier constructed from externally provisioned pinned public keys and an isolated approval registry. It never creates signing keys, accepts unsigned Redis Software events, subscribes to network traffic, or changes existing R437 evaluation/registration.
5. **ALL outcomes are non-alerting:** `RedisAuditCandidateAssessment.AlertPermitted` is fixed `false`. Even a correctly signed pair, matching wire endpoints/timestamps, configured Redis-server inventory and unapproved client returns `UnapprovedClientRequiresTransactionBinding` / `R437_SIGNED_AUDIT_CANDIDATE_TRANSACTION_UNBOUND`. This is a **candidate for independent review**, not a confirmed attack or newly observed R437 true positive.

### Why a signed pair is still insufficient for a live alert

An RSA-PSS signature proves integrity relative to the pinned collector signing key and claim scope. Two different signing keys are not necessarily two independent original evidence sources. A signed receipt's `TraceHash` is currently correlated **between audit receipts only**; `PacketHandler` does not produce an independently authenticated, shared per-transaction ID matching that trace hash. The IP addresses and ±30-second timestamps can collide under NAT, connection reuse, bursts and attacker-crafted traffic.

Furthermore, a configured `Approved.AdminHosts` allowlist is **operator policy**, not proof of an actual authenticated Redis username or ACL. `Approved.RedisServers` is **inventory**, not a Redis server certificate or authoritative command log. Neither is substituted for true authorization evidence.

The next approval step requires a validated Redis-audit collector (e.g. authenticated receiver with certificate pinning or protected IPC), independent server identity/ACL attribution, genuine `CONFIG SET` subcommand evidence, a nonreplayable common transaction key, audit drop/retention monitoring, and operator review of signing key custody/independence. Those dependencies are not fabricated, deployed or connected by this GA.

## Authored tests — NOT EXECUTED

`Carthago.Tests/RedisTrustedAuditCandidateGateTests.cs` covers:
- Two independently pinned RSA-PSS issuers, exact R437 operation scope, same-registry correlation, and a signed candidate that **still cannot alert**.
- Tampered/wrong signer, replay of already-consumed receipts, one signer attempting to corroborate itself, missing receipt, wrong command-operation claim.
- No Redis-server inventory, unknown server, no admin-host policy, approved vs unapproved administrator, missing/negative/reversed/wrong-port wire replies.
- Audit/capture endpoint mismatch and ±30-second offset fail-closed, including mismatched UTC offset.
- End-to-end intake using real test-generated RSA signing keys (synthetic claims only). Tests neither provide nor imply original Redis Software data or valid real-world attacker labels.

No protected holdout datasets, replay labels or rules beyond the exact R437 verifier-operation scope were changed.

## Independent detection-quality gate before any R437 positive detection

1. **Code gate, exact SHA:** On owner test-time authorization, clean fast-forward pull on the existing branch and record the SHA. Run `dotnet build -c Release`; then targeted `Resp2CommandInspectorTests|Resp2SimpleReplyInspectorTests|RedisRespCaptureIntegrationTests|RedisTrustedAuditCandidateGateTests|TrustedAuditReceiptVerifierTests|TrustedAuditReceiptCorrelationTests|TuningBenchmarkTests` with separate TRX, followed by the full `Carthago.Tests` suite. Do not report passing until Windows output is recorded.
2. **Producer gate, original-source:** Operators supply verified provenance for real Redis server(s), authorized Redis command/ACL audit and signer configuration. Verify exact CONFIG SET subcommand and success/failure; verify key custody and transport authenticity. Metrics must include audit dropped messages, connection reuse, source timestamp skew and missing/null instrumentation.
3. **Transaction gate:** Bind original captured flow *and* producer audit to the same nonreplayable transaction identifier (not just two audit receipts or IP/time). Establish server certificate/process identity and caller authorization; prove every approval state is safe, particularly missing inventory and unapproved administrators.
4. **Independent labeled data:** A review team collects source-authorized positive and benign samples **independent from rule authors**. Include unauthorized successful CONFIG SET, failed ACL requests, legitimate DBA/admin changes, tools and backups, pipelined/split/TLS/RESP3 traffic, NAT and connection reuse, missing audit, forged/tampered signatures, backpressure and replay. Split development/calibration from an immutable holdout; never copy test fixtures into external holdout.
5. **Metrics:** Use existing `DetectionQualityMetrics`, `TuningBenchmarkDetectionFunnelAnalyzer`, and missed-positive reports. Record raw recognition, verified audit coverage, actual eligible emitted alerts, TP/FP/FN/TN, precision, recall, specificity, false alarms per monitored day, detection latency and confidence intervals with sample-size limits. Treat missing denominators as **N/A**, not as 100% precision; a deliberately non-alerting detector has zero alert-level recall for malicious samples. Preserve original `redis-config-set` malicious replay and the missed R437 expected match until genuinely validated.
6. **Decision:** **NOT READY FOR POSITIVE ALERTS** at this checkpoint. No trustworthy external source dataset, verified signed collector deployment, common transaction key, full regression result for new code, or independent precision/recall metrics exists. The source contract can be tested; it cannot certify real detection accuracy.

**Immutable constraints:** Frozen Holdout V1 remains FAILED 4/6 and unchanged; V2 remains PENDING_EXTERNAL_CAPTURE_AND_REVIEW with zero approved; minimum confidence R102 80%, R118 86%, R163 84%; R437 default minimum 82 unchanged; no branch proliferation or unsafe alert-mode promotion.
