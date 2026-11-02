# GA R437 — Pinned mutual-TLS Redis audit relay and audit delivery-health boundary

**Status:** SOURCE CANDIDATE — UNVERIFIED, as of the 2026-11-02 source changes.  
**Verified previous SHA:** `6099bfa8c9bff2150caadc7dbf89f332752a1a42`: Windows Release build GREEN, 125/125 Redis GA targeted tests GREEN, full xUnit 9,870/9,870 GREEN. **No Windows build or tests have been run for this new GA.**  
**Branch:** the existing `feature/carthago-reliability-hardening` only; no new branch, rules or runtime-mode promotions.

## Why a relay instead of a direct Redis TCP listener?

Redis Software's **official** command auditing uses asynchronous **plain TCP** notifications to an externally configured audit sink. It does **not** guarantee receipt at the consumer and it may drop audit events. Carthago must not label raw TCP JSON as cryptographically authenticated simply because a Redis audit field says `id` or carries a server IP. Redis Software itself does not use this new receiver's mTLS protocol.

This GA defines a **separate explicit transport boundary** for an *operator-managed relay* that has independently received and framed vendor events. An operator must configure, authenticate and maintain that forwarding relay separately. No external collector has been deployed, no socket is bound automatically, and Redis Software is **not** silently reconfigured.

### Architecture

```text
Redis Software server (original audit feed, best-effort plain TCP)
        |
        | operator-provisioned source protection / trusted on-host relay
        | full-event boundaries and audit_sink_* monitoring REQUIRED
        v
Operator-controlled relay (NOT deployed by this GA)
        |
        | mutual TLS 1.2/1.3; complete client cert SHA-256 pinned by Carthago
        | certificate must be valid and explicitly clientAuth EKU
        | 4-byte big-endian length + 1..16384 bytes JSON per event
        | same-machine 127.0.0.1 or ::1 only
        v
RedisAuditMutualTlsRelayReceiver.AcceptOneAsync (explicit opt-in)
        |
        | bounded authenticated relay ID + decrypted ephemeral frame
        v
RedisAuditMutualTlsDiagnosticBridge.AcceptOneAsync
        |
        | parse complete notification / find capture-only reply metadata
        v
Existing RedisSoftwareAuditDiagnosticIntake
        |
        | per-source+worker audit_seq tracker + 4-tuple/status/UTC diagnostics
        v
Explicit diagnostic statuses ONLY. R437 alert admission remains CLOSED.
```

**Trust distinction:** authenticating the relay's X.509 client certificate does **not** authenticate the original Redis daemon, the proxy's connection ID, the Redis ACL user or the `CONFIG SET` subcommand. A compromised but correctly pinned relay can forward fraudulent JSON, so original-source provenance is still needed.

## Implemented code

### `Carthago/Services/TrustedAudit/RedisAuditMutualTlsRelayReceiver.cs`

- Requires an operator-provided server certificate **with private key**, valid at construction; **does not** create, export or store keys or a default trust store.
- Requires an operator-provided source identifier (3–64 ASCII letters/digits/dot/underscore/hyphen) and **exact 64-character lowercase SHA-256 hash of the complete client certificate DER**.
- Validates peer time validity, explicit X.509 clientAuth EKU (`1.3.6.1.5.5.7.3.2`) and the pinned full-certificate hash using constant-time equality. It deliberately rejects unrelated CA-issued certificates, cert-name matches, expired certificates, unknown peers and server-only EKU. Pinned self-signed certs are supported; revocation checking is disabled because the operator's specific pinned leaf and manual rotation/revocation are the trust policy.
- Requires the **already-started** listener to bind IPv4/IPv6 loopback, otherwise rejects before accepting any connection. The receiver never opens a listening socket on its own.
- Uses `SslStream.AuthenticateAsServerAsync`, requires a client certificate, and limits negotiation to TLS 1.2 and TLS 1.3.
- Accepts one connection at a time, performs synchronous-in-order backpressure through awaited callbacks; no unbounded queue or retained command JSON.
- Reads a **fully bounded length-prefixed** message format: 4-byte network-order signed length (positive 1–16,384) then exactly that many bytes. The relay **must** implement this framing; it is **not** claimed to be Redis Software's native framing.
- Closes/rejects zero/oversized, truncated, invalid frames or handler exceptions without leaking command contents into diagnostics. Limits authenticated sessions to 512 frames and per-frame or handshake deadline to 15 seconds, with caller cancellation.
- Zeroes the decrypted byte buffer once the handler returns. Handlers must parse during the callback, must not retain `ReadOnlyMemory<byte>` or underlying bytes, and must not expose payloads as errors/logs.
- Returns only `RedisAuditRelaySessionResult` with fixed `RedisServerAuthenticated=false`, `ConfigSetVerified=false`, `AlertPermitted=false`.

### `Carthago/Services/TrustedAudit/RedisAuditMutualTlsDiagnosticBridge.cs`

- Reuses the previous GA's `RedisSoftwareAuditNotificationParser` and `RedisSoftwareAuditDiagnosticIntake` instead of creating an independent inspector/rule.
- Receives the **pinned relay ID** from the TLS receiver, not from untrusted JSON.
- Uses a caller-provided capture-only lookup to obtain a `PacketHandler` reply observation and its UTC capture timestamp; **does not forge flags or claim unique transaction causality**.
- Emits only the existing sanitized `RedisSoftwareWireCorrelationAssessment`, no Redis keys/values, no private audit messages or claim signing.
- Rejects and closes the authenticated session for malformed JSON or broken audit sequence rather than silently dropping an event and continuing.
- No live app startup, CI, task automation, signing-key provisioning, R437 registration, Redis Software connection settings or runtime alert pathway is changed.

### `Carthago/Services/TrustedAudit/RedisAuditSinkMetricsHealth.cs`

- Accepts explicitly operator-sourced **typed metric snapshots**, not raw, unauthenticated Redis JSON or made-up counters.
- Tracks `audit_sink_sent_messages`, `audit_sink_dropped_messages`, `audit_sink_disconnect_loss_events`, `audit_sink_reconnect_attempts_exhausted`, and `audit_sink_pending_bytes`.
- Caps 64 configured sources; requires UTC timestamps no older than 2 minutes nor more than 30 seconds in the future, nonnegative counters and monotonic observation order.
- Distinguishes baseline, no observed loss **delta**, pending backlog, loss increases and counter resets/reorders; loss/reset is sticky until operator review. Backlog can drain, but that never proves historical completeness.
- Returns `AuditDeliveryAuthenticated=false`, `CompleteCommandAuditProven=false`, `AlertPermitted=false` in **all** cases because scraping itself is not authenticated here. A counter indicating "sent" does not guarantee the remote consumer actually received the corresponding audit event.

### Tests authored — not executed

- `Carthago.Tests/RedisAuditMutualTlsRelayReceiverTests.cs`: ephemeral RSA test certificates, pinned client certificate validity/EKU/thumbprint, self-contained loopback TLS sessions, exact length framing and two vendor events, wrong peer refusal before event processing, 0/oversized frame refusal, malformed event session closure, bridge-to-existing-Redis-intake integration and no external binds.
- `Carthago.Tests/RedisAuditSinkMetricsHealthTests.cs`: counter baseline/monotonic/drops, sticky disconnect loss/reset, pending backlog, stale/non-UTC samples and bounded source cardinality.

These are **synthetic tests only**. No Redis server, real audit producer, certificate secret, capture service or external monitoring system is used.

## Operator setup prerequisites (not performed in this GA)

1. Provision a Redis Software audit sink using the official Redis configuration and enable `connection_and_crud` for the relevant database. **Do not point Redis Software's native plain TCP sink directly at Carthago's mTLS receiver.**
2. Deploy an operator-managed relay receiving the actual Redis Software sink with strictly verified full-event framing, access-controlled same-host/protected transport, audit source/certificate provenance and explicit loss/backpressure monitoring. This relay is **not included** in the current GA.
3. On the Carthago machine, provision and protect a TLS **server** certificate with private key in OS-managed storage; provision a dedicated short-lived, distinct TLS clientAuth certificate in the relay's secure store.
4. Obtain the relay's **full certificate DER SHA-256** hash (lowercase 64 hex digits) out-of-band and pin it to an explicit local `RedisAuditPinnedRelay` identifier. Do not pin the Redis Software JSON `srcip` or `trgip` as a TLS identity.
5. Create a `TcpListener(IPAddress.Loopback, port)` explicitly and call `RedisAuditMutualTlsDiagnosticBridge.AcceptOneAsync(...)`, with a capture-only lookup and a sanitized diagnostic sink. The source ID must come solely from the pinned relay identity. Keep this off by default until operator security review.
6. Have the relay connect to loopback using **mutual TLS**, a pinned receiver certificate, and the agreed 4-byte big-endian **length** followed by complete vendor JSON bytes; send all audit event types in original per-worker order. The same machine/local relay requirement is deliberate and is **not** an instruction to expose the listener over public interfaces.
7. Source Redis Software `audit_sink_*` metrics through a separately authenticated monitoring endpoint and feed typed snapshots to the metric monitor. The monitor does not authenticate scrape transport. Independently review and reset sticky loss states only with evidence.
8. Never submit an R437 signed `RedisConfigSetCommandSucceeded` claim from generic `CONFIG` command metadata, a pinned relay alone or a four-tuple/time match. For positive alerts, separately prove exact subcommand, authenticated Redis server and ACL authorization, unique command-to-capture binding and independently labeled TP/FP/FN/TN metrics.

## Owner exact-SHA Windows build and test gates (NOT RUN)

The existing `scripts/verify-redis-software-audit-ga.ps1` now includes targeted `RedisAuditMutualTlsRelayReceiverTests` and `RedisAuditSinkMetricsHealthTests`, plus the previous Redis audit, capture, signed-claim, R561 and R562 tests. When the owner explicitly authorizes test time, run on a clean `feature/carthago-reliability-hardening` working tree:

```powershell
& .\scripts\verify-redis-software-audit-ga.ps1
```

This script fast-forwards, prints exact SHA, Release-builds first, runs targeted Redis tests with unique TRX and then full xUnit Release with separate TRX; aborts on failure. Verify genuine test host status, never use old `--no-build` outputs after failed compilation, and record exact SHA and counts in `docs/DEVELOPMENT_VALIDATION_LEDGER.md`.

**Frozen/quality constraints untouched:** frozen V1 holdout historical FAILED 4/6 and immutable, V2 PENDING_EXTERNAL_CAPTURE_AND_REVIEW / zero approved, R102 80%, R118 86%, R163 84%, R437 82%, R561 86%, R562 88%, R561/R562 Candidate Shadow and R437 non-alerting. No replay labels were altered.

## External references

- Redis Software: audit event fields, delivery semantics, `connection_and_crud`, `audit_seq`, audit_sink_* metrics: https://redis.io/docs/latest/operate/rs/security/audit-events/
- Microsoft .NET: TLS server authentication with `SslStream.AuthenticateAsServerAsync`: https://learn.microsoft.com/en-us/dotnet/api/system.net.security.sslstream.authenticateasserverasync
- Microsoft .NET: cancellable `TcpListener.AcceptTcpClientAsync`: https://learn.microsoft.com/en-us/dotnet/api/system.net.sockets.tcplistener.accepttcpclientasync
