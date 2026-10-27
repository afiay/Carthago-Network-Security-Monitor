# Rule accuracy batch 16 — R076–R080

**Status: CANDIDATE — UNVERIFIED.** Seven advanced xUnit cases per rule (**35 new facts**). No build, xUnit, replay, benchmark, frozen holdout, Windows runner or automated test has been executed.

## Code and evidence assessment

| Rule | Original weakness | Candidate evidence / state | Advanced facts |
| --- | --- | --- | ---: |
| R076 — SMB Admin Share Access Pattern | TCP/445 and free-text `admin$`, `c$`, `ipc$`, or five targets could trigger, including ordinary shares or scanning; alerts could embed packet `Info`. | Requires internal TCP data, explicit `ApplicationProtocol=SMB` and `ApplicationService=ADMIN_SHARE`; two distinct request records within 120 seconds on one source/target pair. | 7 |
| R077 — RPC Service Control Pattern | Free-text `svcctl` or count of port-135/445 targets was equated to service control. | Requires internal TCP data to 135/445 with classified `DCE/RPC` + `SVCCTL`, two distinct request IDs in 120 seconds per client/target. | 7 |
| R078 — PsExec-Like Network Behavior | One SMB/445 free-text token (`psexec`, `admin$`, `svcctl`, etc.) immediately generated a critical claim. | Requires ordered, separately classified SMB admin-share activity followed by DCE/RPC service control for the **same** internal source and destination within 120 seconds; does not claim PsExec executable identity. | 7 |
| R079 — LDAP Enumeration Spike | Any LDAP string such as `objectClass` caused immediate detection; plain port-389/636 traffic counted toward threshold. | Requires classified `LDAP/SEARCH_REQUEST` over an internal TCP data-bearing session to a known directory port. Forty distinct request records to one client/target/port within 60 seconds by default. | 7 |
| R080 — Kerberos TGS Request Spike | Any text resembling TGS or generic port-88 traffic immediately triggered; AS requests could be counted. | Requires classified `KERBEROS/TGS_REQ` over internal TCP or UDP to port 88. Sixty distinct request IDs per source and KDC in 60 seconds by default. | 7 |

Threshold/window overrides for R076, R077, R079 and R080 are retrieved via the existing `RuleEngine.GetRuleIntSetting` mechanism. R078 reads the configured correlation window. Default thresholds were explicitly established for the stricter typed requests; no production `rules.json` or security confidence floor was edited.

## Shared behavior

`NetworkBatch076080Evidence.cs` validates IPv4 RFC1918 endpoints, ports, transport consistency, TCP data flags, source/destination attribution, nonempty unique record identity, and future observations. `NetworkBatch071075Window` provides bounded, per-instance, thread-safe request counting and nonrepeat alert episodes. `NetworkBatch076080Sequence` records an ordered two-stage remote execution *pattern* with bounded flow state and expiration; its result does not establish executable identity, privilege or authorization.

The returned event uses existing rule intelligence and confidence computation; no event copies the raw `Info`, LDAP search values, Kerberos principal/service name, or credential material into the summary, description or evidence. It is an observed network pattern, not a claim of malicious intent.

The typed `ApplicationProtocol` and `ApplicationService` combinations are **proposed adapter contracts**, not proof that an existing capture provider currently populates those fields. A supported live parser must independently attest their provenance; otherwise these candidates intentionally return NoMatch. **This is a possible recall regression and a mandatory capture-integration investigation during later acceptance.** In particular, SMB named-pipe service-control, LDAP request boundaries and Kerberos TGS message parsing need validated capture-path support. Replaying manually populated `TrafficRecord` objects does not prove that support.

An `Info` string containing `psexec`, `admin$`, `CreateService`, `objectClass`, or `tgs-req` **never** substitutes for captured structured protocol classification. Conversely, legitimate remote administration, backup and directory sync may still produce correctly classified events; later policy/asset attribution is required to determine intent.

## Scenario matrix

Each new `RNNNAdvancedAccuracyBatchTests.cs` contains seven separate xUnit facts, covering: a positive threshold/sequence, realistic benign lookalikes, text-only evasion, invalid or contradictory transport, independent source/target separation, repeated/reordered/stale observations, and cancellation/redaction. R079 and R080 also assert that just-below-threshold observations cannot trigger. No synthetic replay fixtures were added because present development traffic-only JSON cannot faithfully represent a parsed LDAP SearchRequest, Kerberos TGS_REQ, SMB tree connect, or RPC service-control operation. Do not manufacture positive replay metrics.

## Preserved safety and operational constraints

Existing descriptors and enabled defaults, runtime policy, Shadow/Disabled modes, R102=80%, R118=86%, R163=84% confidence floors, baseline readiness, IoT asset approvals, frozen holdout and all unrelated detection rules remain unchanged. Per-instance in-memory windows are not restart-durable. Future timestamp gating depends on the host clock. Strict data-bearing TCP validation and typed field requirements may affect field recall.

**Windows acceptance is explicitly deferred.** Keep this batch **CANDIDATE — UNVERIFIED** until the owner says **“now it's test time”** and the single local `scripts/verify-all-rule-batches.ps1` run has been reviewed.

**Next batch to author: R081–R085.**
