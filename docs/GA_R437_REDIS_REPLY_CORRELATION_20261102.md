# GA R437 — Bounded Redis CONFIG SET reply correlation and admin policy

**Status:** SOURCE CANDIDATE — UNVERIFIED. Authored source and tests; no Windows build, unit tests, benchmark replay, real capture, or holdout run.  
**Branch:** existing `feature/carthago-reliability-hardening` only.  
**Owner-proven baseline:** `e73650fc594179d6c7c1db5d5b933a8eff4bd082`: Release build with zero warnings; 9,762/9,762 full xUnit tests passing. Later changes do not inherit this approval.

## Scope

This GA extends the previously connected `Resp2CommandInspector` on **the same** packet handler and bounded TCP flow state. It observes one complete `CONFIG SET` array request and *one* subsequent complete Redis simple-string status or error reply, then evaluates the client address against the existing `Approved.AdminHosts` configuration. It does **not** introduce a parallel sensor, new detection rule ID, unrestricted packet replay promotion, credential capture, generalized TCP reassembly, trust in request text, or an Alert-mode change.

### Live evidence chain

1. `PacketHandler` observes a TCP client SYN for a canonical flow and a matching reverse-direction SYN-ACK, assigning each direction a verified initial TCP sequence. A reused 5-tuple's previous server SYN-ACK state is reset when a new client SYN arrives.
2. The **first client TCP payload** must arrive on the contiguous next sequence, carry ACK without SYN, target TCP/6379, be inspected as cleartext RESP2 and contain **exactly one** complete `CONFIG SET` command. The existing `Resp2CommandInspector` verifies bounded RESP2 array/bulk-string structure and complete parameter/value pairs. It produces a Boolean only, never parameter names, configuration values, credentials, or bytes of the command.
3. The existing per-flow `TcpStreamState`, capped by `MaxTrackedFlows=16384` and `FlowIdleTimeout=5min`, holds **one pending Boolean** plus a UTC request timestamp, not captured request content. A maximum **30-second reply window** applies. Additional client payloads, retransmitted segments, TCP gaps, FIN/RST, new handshake, exhaustion or unexpected framing invalidate/expire the candidate.
4. Only the **first SYN-anchored, sequence-contiguous server payload** from the same reverse 5-tuple and TCP/6379, carrying ACK, can consume this pending command. The new `Resp2SimpleReplyInspector` accepts **exact** `+OK\r\n` or a bounded, complete printable single-line RESP2 error. It rejects other reply types, truncated, extra/coalesced, oversized, control-character or ambiguous frames. No error text or payload is retained.
5. The server-direction `TrafficRecord` exposes only internal-set `RedisRespConfigSetReplyOkObserved` or `RedisRespConfigSetReplyErrorObserved`. A parsed client request only exposes `RedisRespConfigSetRequestObserved`. These are capture-path signals, not authenticated server identity or proof of a configuration change.

### Policy and existing R437 behavior

`ApprovedAssetRegistry` exposes the presence of the existing `Approved.AdminHosts` allowlist and its already-present `IsAdminHost` matching; **no new global settings service** is created. R437 uses a pure, testable `AssessCorrelatedClient(record, registry)` helper and emits an explicit **NoMatch** diagnostic:

| Correlated evidence and policy state | Diagnostic | Alert |
| --- | --- | --- |
| RESP2 error, not OK | `REDIS_CONFIG_SET_SERVER_REJECTED` | Never |
| Missing TCP server endpoint/direction | `REDIS_CONFIG_SET_CORRELATED_ENDPOINTS_UNAVAILABLE` | Never |
| `Approved.AdminHosts` empty/unconfigured | `REDIS_CONFIG_SET_ADMIN_CLIENT_POLICY_UNCONFIGURED` | Never |
| Correlated client on configured allowlist | `REDIS_CONFIG_SET_APPROVED_ADMIN_CLIENT` | Never |
| Client absent from non-empty allowlist | `REDIS_CONFIG_SET_UNAPPROVED_CLIENT_REQUIRES_SERVER_IDENTITY` | Never |
| Request-only, port/name/Info/spoofed data | Existing `REDIS_RESP_CONFIG_SET_UNAVAILABLE` from `ServiceExposureEvidenceBoundary` | Never |

The default R437 minimum confidence **82**, runtime mode, evidence profile, original scenario labels, replay missed-positive counts, and detection-environment approvals remain unchanged. **This does not convert an unauthenticated TCP response into a trusted security incident.** Legitimate administrators can run CONFIG SET; a plain network `+OK` is not verified client identity, Redis server identity, ACL authorization or a persistent configuration change. An empty allowlist must not be equated to an explicitly disallowed client.

### Files changed

- `Carthago/Services/ProtocolIntelligence/Resp2SimpleReplyInspector.cs`: new bounded non-retaining Redis reply-shape classifier; existing `Resp2CommandInspector.cs` remains the request parser.
- `Carthago/Services/PacketHandler.cs`: uses the existing flow lock and sequence tracking, one outstanding Boolean/request timestamp, server SYN-ACK and ACK gates, explicit 30-second age, retransmission/gap/FIN/RST invalidation, 5-tuple reuse reset and reply flag emission.
- `Carthago/Models/TrafficRecord.cs`: two internal-set wire-observed reply flags; no raw payload, config key/value, credentials, server error text or new persistent queue.
- `Carthago/Services/Environment/ApprovedAssetRegistry.cs`: `HasApprovedAdminHosts` over the existing configuration; no file format or defaults changed.
- `Carthago/Engine/Rules/Expansion/R437_RedisCONFIGSETIndicatorRule.cs`: fail-closed correlated-reply diagnostics and isolated admin-client policy assessment; no Alert emission.
- `Carthago/Engine/Rules/Expansion/ServiceExposureEvidenceBoundary.cs`: corrected missing-producer explanation to distinguish wire replies from authenticated evidence.
- `Carthago.Tests/ProtocolIntelligence/Resp2SimpleReplyInspectorTests.cs`: authored accepted/rejected, malformed/coalesced, bounded input, privacy tests.
- `Carthago.Tests/RedisRespCaptureIntegrationTests.cs`: authored raw synthetic TCP handshake/request/reply, server error, missing SYN-ACK, sequence gap, retransmit, pipelining, FIN/RST, old 5-tuple, 30-second window, JSON import forgery, isolated allowlist policy, R437 fail-closed tests.

## Unresolved limitations

- **Coverage:** first complete plaintext CONFIG SET request only, not Redis AUTH/HELLO preceding it, a general TCP stream, TLS, split commands/replies, pipelining, late join, proxy or NAT association, RESP3, asynchronous messages or cluster command redirects. Failure to observe a flag cannot be interpreted as absence of attack.
- **Trust:** server reply and host-address association remain network observations. They do not authenticate Redis daemon identity, local process, client user, ACL, official audit outcome, or change persistence. **No R437 positive case is promoted.**
- **Concurrency/time:** the flow state and its bounds exist but independent arrival-order stress and capture loss have not been measured in this GA. The 30-second UTC acceptance window is a conservative cap, not a calibrated dataset threshold.
- **Other rules:** R485 BACnet WriteProperty, R508 rclone transfer and R516 Cloudflared authenticated connector still lack their dedicated trusted producers. Do not relabel their malicious holdout/replay cases.

## Next exact-SHA verification gate (only when owner authorizes test time)

1. On Windows, record clean `git status`, fast-forward the same feature branch and `git rev-parse HEAD`.
2. Run `dotnet build -c Release` and inspect new compiler/analyzer warnings.
3. Run targeted `dotnet test Carthago.Tests/Carthago.Tests.csproj -c Release --no-build --filter "FullyQualifiedName~Resp2CommandInspectorTests|FullyQualifiedName~Resp2SimpleReplyInspectorTests|FullyQualifiedName~RedisRespCaptureIntegrationTests|FullyQualifiedName~NetworkBatch431440AccuracyTests|FullyQualifiedName~TuningBenchmarkTests"` with a TRX logger.
4. After the targeted gate is GREEN, execute and preserve the full `Carthago.Tests` Release xUnit suite with TRX. Record the exact SHA and pass/fail/skip count. A green suite proves internal test contracts, **not real capture or detection accuracy**.
5. Separately profile source-producer coverage, accepted/missed positives, benign-admin false positives, server identity proof, packet loss, fragmentation, retransmissions and policy under independent capture. The `redis-config-set` malicious label remains an intentionally **missed** positive in replay until those conditions are actually met.

**Unchanged owner constraints:** immutable frozen holdout V1 (historical FAILED 4/6), V2 PENDING_EXTERNAL_CAPTURE_AND_REVIEW (0 approved), confidence floors R102 80%, R118 86%, R163 84%, current candidate/Shadow modes, documentation discipline and single existing branch.

## Protocol references

- Redis RESP protocol, simple string and error types: https://redis.io/docs/latest/reference/protocol-spec/
- Redis CONFIG SET syntax and response: https://redis.io/docs/latest/commands/config-set/
