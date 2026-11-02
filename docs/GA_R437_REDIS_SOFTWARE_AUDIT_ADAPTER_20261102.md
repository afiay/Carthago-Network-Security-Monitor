# GA R437 — Redis Software audit-source adapter and TCP evidence diagnostics

**Status: SOURCE CANDIDATE — UNVERIFIED**. Code and synthetic tests committed to the existing `feature/carthago-reliability-hardening` branch. No owner Windows build, xUnit, original-source capture or independent detection-quality run has yet checked this GA. **Last exact owner GREEN:** `65826c3ec087cbd7c5306f1f32ce8dbc86d24e31` — Release build, **9,854/9,854 xUnit**. The hourly automation can append unrelated commits, which remain separately unverified.

## Purpose and actual output

This GA makes Redis Software's real, published audit **notification schema** consumable by Carthago's existing evidence architecture *without creating new rules, a parallel detector, an unauthenticated listener, or artificial R437 true positives*. It adds a **bounded, opt-in diagnostic interface** that accepts one complete external notification and a separately generated `PacketHandler` Redis response record, correlates the vendor event's endpoints/ports/time with that capture record, and reports missing evidence or ambiguity.

**This is not an operationally deployed authenticated Redis audit producer.** The operator still needs to configure Redis Software auditing, deploy an authenticated and framed collector, establish Redis server identity/ACL and trustworthy per-command subcommand provenance, provision public signing keys and secure the transport before the source can produce trusted evidence. No TLS, listener, secret, private signer, source-cert trust pin, Redis server credentials, automatic network egress or background process is created by this code.

## Official Redis Software fields and hard limitation

Redis Software can send audit notifications for connection establishment, authentication, individual commands and disconnects to an external TCP listener. Documented examples include `ts` (Unix seconds), `action`, `id` (proxy connection ID), `srcip`/`srcp` (client), `trgip`/`trgp` (server endpoint), `bdb_uid`, `audit_worker_id`, `audit_seq`, `status` and `command`. The audit stream is **best-effort**: the database prioritizes availability and can drop events. `audit_seq` is worker-specific and useful for detecting observed gaps, but does not prove that all records arrived, especially after the final observed event. The documented Redis Software command status is **9 for completed** and **10 for failed**. These codes apply to command records, not auth records.

**Critical blocker:** the published command event gives a command name such as `config` and a result, but it does **not** independently authenticate the `SET` subcommand of `CONFIG SET`. A generic `CONFIG` + status 9 must **never** be promoted or signed as `RedisConfigSetCommandSucceeded` solely based on this vendor event. Capturing a `CONFIG SET` request and `+OK` reply may help with diagnostics, but cannot by itself establish a unique audit-to-packet transaction, authenticated Redis server, authorization or persistent configuration change.

Primary reference: https://redis.io/docs/latest/operate/rs/security/audit-events/

## Committed components

| Source file | Purpose and boundaries |
| --- | --- |
| `Carthago/Services/TrustedAudit/RedisSoftwareAuditNotificationParser.cs` | Accepts one already-framed JSON notification, max 16 KiB, strict syntax and required numeric/endpoint fields. Handles `new_conn`, `auth`, `command`, `close_conn`. Returns a privacy-minimized immutable `RedisSoftwareAuditObservation` retaining only IPs/ports, database UID, connection ID, Unix timestamp, worker and sequence, command class `GenericConfig/Other` and command outcome `Succeeded/Failed`. No key strings, command arguments, error text, username, ACL text or raw payload are preserved. `ProvesConfigSetSubcommand` and `AuthenticatedProducer` are fixed **false**. |
| `Carthago/Services/TrustedAudit/RedisSoftwareAuditContinuityTracker.cs` | Tracks every event kind per provisioned producer ID + worker ID, not per database or only command. Detects first observation, contiguous sequence, duplicate/rollback, gaps and capacity exhaustion. A gap/duplicate poisons the worker's state until operator-reviewed reinitialization. Caps worker streams at 256; event streams are not restarted silently on reconnect. `NoGapObserved` is diagnostic and `AuthenticityEstablished` is fixed **false**. |
| `Carthago/Services/TrustedAudit/RedisSoftwareAuditWireCorrelation.cs` | For a generic `CONFIG` vendor command, compares an already correlated capture-only Redis `TrafficRecord` to audit client/server **TCP 4-tuple** (including the client ephemeral port), time ≤30s, status 9/10 vs RESP2 `+OK/-error`, configured approved Redis server inventory and admin policy, plus healthy audit-sequence diagnostic. Every result is **non-alerting** and **does not prove the CONFIG SET subcommand**. |
| `Carthago/Services/TrustedAudit/RedisSoftwareAuditDiagnosticIntake.cs` | One opt-in facade `Inspect(provisionedSourceId, completeVendorNotification, capturedReply, capturedReplyUtc)` combining parser, sticky sequence tracker and network correlation. Returns fixed, sanitized reason codes. Provisioned source ID is supplied by an **external authenticated collector**, not read from untrusted JSON. This class itself provides **no authentication** and **cannot generate a signed R437 receipt**. |
| `environment-tuning.sample.json` | Shows optional `approved.redisServers: []`; empty remains unconfigured and fail-closed. Existing `Approved.AdminHosts` unchanged. |
| `Carthago.Tests/RedisSoftwareAuditSourceTests.cs` | Authored tests for published notification schema, command success/error, connection/auth/close event shapes, bounds, duplicate JSON fields, privacy and key/error non-retention, numeric/string ports, sequence/gap/duplicate/poison and bounded worker streams. **NOT RUN**. |
| `Carthago.Tests/RedisRespCaptureIntegrationTests.cs` | Added integration cases using existing SYN/SYN-ACK TCP/6379 fixture and RESP2 `CONFIG SET` + `+OK` producer. Checks generic CONFIG verdict, approved admin case, wrong audit port/time/outcome/command, sequence gap, opt-in intake and replay. **NOT RUN**. |

**No changes** to `PacketHandler`'s existing signed request/reply checks, `R437_RedisCONFIGSETIndicatorRule` evaluation, R561/R562 counters or maturity, `TrustedAuditReceiptVerifier`'s RSA-PSS domain separation or allowed rule operation, `RedisSignedAuditCandidateIntake`'s pinned-receipt path, rule thresholds or runtime policy.

## Why this is a real integration subgate, not a product-readiness claim

The earlier GA exposed `TrafficRecord.RedisRespConfigSetReplyOkObserved` / `RedisRespConfigSetReplyErrorObserved` only after a bounded SYN-anchored RESP2 exchange. This GA joins real Redis Software notification **fields** with that same wire-derived object, matching both IP addresses **and both TCP ports**, which is stronger than earlier IP/time-only signed receipt correlation. This is meaningful code reuse, but still not cryptographic server authentication or a unique causal transaction key: a Redis proxy or NAT can change the observed socket endpoints, a source may drop records, and the untrusted audit JSON may be fabricated. The raw `audit_seq` and `id` are vendor-side metadata; the TCP packet does not expose either as a trusted wire-level transaction ID. The `GenericConfigSubcommandUnproven` status is intentionally the best possible unapproved-client result from published generic audit fields.

**No signed CONFIG SET success claim is produced from this vendor metadata.** In particular, a Redis Software notification cannot be passed directly to `RedisSignedAuditCandidateIntake.Assess` as an equivalent to the two independently validated RSA-PSS-signed claims.

## Unchanged evidence and holdout controls

- R437 remains fail-closed without independently attested CONFIG SET identity, authorization and source provenance.
- R561/R562 remain Candidate/Shadow; confidence floors R561 86%, R562 88%, R437 82%, R102 80%, R118 86%, R163 84% unchanged.
- Frozen V1 holdout historical FAILED 4/6 is immutable. V2 still PENDING_EXTERNAL_CAPTURE_AND_REVIEW with **0 approved** source captures.
- The original malicious `redis-config-set` replay expectation remains an unresolved missed positive until an independently measured source-backed detector can justify an alert; no fixtures were relabeled and no failed tests were waived.

## Exact-SHA owner Windows verification gate (only on authorization)

An operator-invoked, fail-fast script is now included at `scripts/verify-redis-software-audit-ga.ps1` (commit `c6529fe`). From the repository root on Windows, the owner can run `& .\\scripts\\verify-redis-software-audit-ga.ps1` to check the branch, clean tree, fast-forward, exact SHA, Release build, targeted Redis tests, and full xUnit suite with separate TRX in a fresh results directory. `-TargetedOnly` explicitly skips the full suite and must never be represented as a full GA. **This script was authored, not executed.**

Alternatively, from a clean feature-branch checkout, fast-forward, record exact `git rev-parse HEAD`, then `dotnet build -c Release` **before** any `--no-build` test.

Targeted filter:

```powershell
$filter = @(
    "FullyQualifiedName~RedisSoftwareAuditSourceTests"
    "FullyQualifiedName~RedisRespCaptureIntegrationTests"
    "FullyQualifiedName~RedisTrustedAuditCandidateGateTests"
    "FullyQualifiedName~TrustedAuditReceiptVerifierTests"
    "FullyQualifiedName~TrustedAuditReceiptCorrelationTests"
    "FullyQualifiedName~R561AdvancedAccuracyBatchTests"
    "FullyQualifiedName~R562AdvancedAccuracyBatchTests"
) -join "|"
dotnet test Carthago.Tests/Carthago.Tests.csproj -c Release --no-build `
    --filter $filter `
    --logger "trx;LogFileName=redis-software-audit-ga.trx" `
    --results-directory build-verify
```

Then run the **complete** `Carthago.Tests` suite, with a new TRX and nonzero-exit check, preserving the exact SHA. Test counts may grow under concurrent automation. Do not execute production Redis command auditing or replay against external endpoints as part of routine unit tests.

## Subsequent gates required for positive detection

1. **Authenticated collector:** operator-approved Redis Software connection auditing `connection_and_crud`, a bounded transport relay with independently provisioned mTLS or authenticated protected IPC, verified Redis server identity/certificate or protected host provenance, source fingerprint and key custody. Published Redis Software raw audit TCP notifications are not signed. Explicitly define secure framing; do not infer framing from examples.
2. **Audit-source provenance:** original command audit capturing *exact* `CONFIG SET`, not merely the `CONFIG` family; verified ACL/user identity and server success/rejection, data-provenance rights and audit drop metrics `audit_sink_dropped_messages`, `audit_sink_pending_bytes`, `audit_sink_disconnect_loss_events`, with per-worker sequence health.
3. **Unique transaction binding:** independent, nonreplayable association between exact command, approved server identity, client connection/port or proxy ID, audit per-worker sequence, packet capture and server response. Mere 30s IP/port coincidence is **not** an authenticated unique transaction.
4. **Detection-quality:** independently labeled attack and benign admin samples, NAT/proxy, retransmits, packet loss, TLS/RESP3, command errors and audit drop conditions; measure producer completeness, TP/FP/FN/TN, precision, recall and false alarms by time and profile. Report undefined precision as N/A, not 100%. Keep calibrations separate from frozen holdout. Promote only through explicit owner approval after independent quality evidence.

**Disposition:** New source integration is **CANDIDATE — UNVERIFIED**, and **R437 POSITIVE ALERT: NOT APPROVED**.
