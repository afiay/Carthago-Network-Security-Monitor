# R343 - isolated authenticated-peer telemetry IPC contract (V1)

**Implementation status: in-process protocol gate and offline xUnit tests only.** No Windows service, helper process, named pipe, TCP/HTTP socket, operating-system peer authenticator, signing key, signed audit producer, R343 alert integration or Windows audit-policy change exists in this increment. The contract requires an already authenticated transport peer; it **does not authenticate Windows peers itself**. Tests use an internal, synthetic transport identity explicitly and do not establish real authentication.

## Files

- `Carthago/Services/TrustedAudit/WinRmTelemetryIpcContract.cs`: internal immutable transport identity, opaque session, fail-closed consumer gate, framed metadata decoder, replay and authorization policy.
- `Carthago.Tests/WinRmTelemetryIpcContractTests.cs`: offline positive and negative tests (no Security log access).
- `docs/development/R343_AUTHENTICATED_PRODUCER_BOUNDARY_20261029.md`: higher-level signer, WinRM authority and least-privilege design.

## Authentication boundary (critical)

The future **OS-authenticated transport adapter** must first authenticate the connecting OS token and derive a peer SID, process ID, machine and per-connection channel-binding identifier from trusted Windows APIs or access-controlled transport state. No such adapter is implemented or automatically connected yet. In particular, **never deserialize these identity fields from the IPC payload** or trust a caller-supplied `Authenticated=true` field. The internal `WinRmTelemetryTransportPeer` constructor is accessible to other code in the Carthago assembly and friend tests, so it is an *adapter interface contract, not an independently unforgeable capability*. Only after an actual transport implementation and security review can the connection be described as authenticated end-to-end.

The consumer `WinRmTelemetryIpcContract` is configured with an **operator-pinned allowed Windows SID and machine name**; a matching transport-sourced identity, positive process ID and nonempty connection binding are prerequisites to opening an in-process `WinRmTelemetryIpcSession`. **Every accepted frame also requires a fresh transport-verified peer descriptor matching the opened session's SID, machine, process ID and channel binding.** A retained session by itself does not authorize a frame. It allows at most 64 simultaneously open sessions. Channel bindings cannot be reused during a gate instance's lifetime (up to 4096 distinct bindings); rotate the instance under operator policy before these bounded caches saturate.

An opaque session has a generated GUID, an owning gate instance, creation time and monotonic sequence. No remote/client JSON can instantiate a session or claim an arbitrary SID. The session GUID is a non-secret correlation value and **is not a bearer credential or proof of identity**. The internal session object is an in-process capability; future adapters must keep it private to its authenticated connection, and must obtain a new OS peer descriptor for every message rather than copying identity from the session. The future local IPC transport must provide its own OS-enforced access control, integrity and per-connection identity; if those checks cannot be implemented, the producer must remain disconnected.

## Wire format

Frame: four unsigned octets encoding a **signed 32-bit big-endian payload byte length**, followed by exactly that number of bytes containing strict UTF-8 JSON. The *entire frame* must be between 6 and 4096 bytes; no trailing bytes, truncated messages, BOM, comments, extra JSON fields, duplicate fields or alternative message formats are accepted. JSON depth is limited to 2 and all field names are case-sensitive.

Only the following **exact 13 fields** are allowed:

| Field | Type / requirement |
| --- | --- |
| `Version` | JSON integer `1` |
| `Kind` | literal string `UnsignedWinRmCandidate` |
| `SessionId` | canonical `D`-format nonempty GUID from the active gate session |
| `CorrelationId` | nonempty `D`-format GUID, not previously accepted by this gate |
| `Sequence` | JSON int64 starting at 1, exactly incrementing per accepted frame |
| `Machine` | bounded local machine name matching the pinned peer machine |
| `RemoteIp` | valid non-loopback, non-unspecified IP address |
| `LogonId` | nonzero unsigned 64-bit JSON integer |
| `LogonRecordId` | positive int64 |
| `ProcessRecordId` | int64 greater than logon record ID |
| `ProcessId` | nonzero uint32 |
| `ParentProcessId` | nonzero uint32, different from `ProcessId` |
| `ProcessTimeUtc` | round-trip ISO-8601 string (`O`), explicitly zero UTC offset |

Candidate observation age must be no more than two minutes; future skew is bounded to 30 seconds. An authenticated-peer session expires after 15 minutes, closes explicitly, and cannot be used with a different gate. The gate accepts at most 4096 unique correlation IDs without eviction; saturation fails closed and requires a new instance under operator-controlled configuration.

Messages are **unsigned candidates only**. They must not include command lines, tokens, private keys, base64 payloads, signatures, arbitrary host outcomes, `Authorized`, `Authenticated`, `Verified`, or rule promotion flags. The parser rejects every unknown field, and no resulting `WinRmTelemetryIpcCandidate` exposes those properties.

## Rejection / adversarial matrix

| Threat or failure | Enforced outcome |
| --- | --- |
| Unauthenticated, wrong SID, wrong machine, invalid PID or empty binding | Session opening denied |
| Reused channel binding or more than 64 concurrent sessions | No new session |
| Foreign gate session, closed session or session older than 15 minutes | Frame rejected |
| Per-frame OS peer descriptor missing or SID/PID/machine/channel changed | Frame rejected without advancing sequence |
| Framing truncation, trailing bytes, mismatched length, over 4096 bytes | Frame rejected before JSON parse |
| Invalid UTF-8, BOM, trailing commas, comments, invalid JSON/depth | Frame rejected |
| Duplicate property, unexpected property, spoofed authentication/secret claims | Frame rejected |
| Invalid version, kind, session ID, event identity or non-UTC timestamp | Frame rejected |
| Loopback/unspecified/invalid remote IP, impossible process IDs/record ordering | Frame rejected |
| Duplicate correlation GUID, sequence skip/backtrack or replay across sessions | Frame rejected |
| Future/stale event or replay cache saturation | Frame rejected |
| Valid candidate without separate authenticated WinRM outcome | **No signed receipt, no alert** |

Rejected frames do not consume session sequence numbers. Raw frames and command-line payloads are never returned, printed or persisted by the gate. The implementation never queries Windows Security, enables audit policy, creates an endpoint or signs metadata. All test peer identities are synthetic.

## Important residual risks and next prerequisites

1. **Transport peer authentication not implemented.** An actual Windows adapter must enforce OS token/SID verification, authorize image/process provenance using trusted OS APIs, protect against PID reuse, pin the local IPC endpoint ACL, and generate a channel binding never derived from caller bytes.
2. **Transport confidentiality and integrity not implemented.** The versioned JSON format is not encrypted or MACed and must only travel over a separately authenticated, access-controlled OS transport. Do not expose it on TCP, HTTP or a publicly accessible pipe. Replay history is only in-memory for one gate lifetime; a future restart/reconnect policy must provide stronger source-level record-id provenance and durable or bounded replay handling before promoting evidence.
3. **Source event authenticity not implemented.** Even from an authenticated producer, sender-supplied event metadata may be misleading. It must be independently reconciled against trusted local Security EventRecord metadata and a verified WinRM operation/outcome and authorization context before considering a signed claim.
4. **No signed receipt or alert integration.** `TrustedAuditReceiptVerifier` and `TrustedAuditReceiptCorrelation` remain separate; this contract must not create a `VerifiedAuditReceipt`. The R343 rule continues to return `WINRM_COMMAND_AUDIT_UNAVAILABLE`.
5. **Windows security configuration unchanged.** CARTHAGE Stage 1 testing was completed and restored to `No Auditing`; command-line auditing remains disabled. No elevated Carthago UI is required.

## Build / test checkpoint

Changes are published on `feature/carthago-reliability-hardening` but **not compiled or executed on CARTHAGE yet**. They must pass focused `WinRmTelemetryIpcContractTests` together with existing `WinRmSecurityAuditIntakeTests` before broader verification. No full .NET pass or replay-gate certification is claimed. The last reported full xUnit baseline remains 4,851 passing tests at commit `290a327`, with R343/R295/R275/R163 replay expectations still blocked.

```powershell
git switch feature/carthago-reliability-hardening
git pull --ff-only
dotnet test .\Carthago.Tests\Carthago.Tests.csproj -c Release --filter "FullyQualifiedName~WinRmTelemetryIpcContractTests|FullyQualifiedName~WinRmSecurityAuditIntakeTests"
```
