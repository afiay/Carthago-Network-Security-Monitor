# R336–R340 — AD replication, Kerberos, SMB signing and Remote Registry provenance

**CANDIDATE — UNVERIFIED.** Five consecutive rules, **70 advanced xUnit cases authored (14 per rule), ZERO executed**. Static source inspection only. No authenticated AD/RPC/KDC/SMB negotiation/registry operation audit producer is connected to the inspected TrafficRecord/PacketHandler path. No positive operation, attack or identity event is invented.

Source: `Carthago/Engine/Rules/Expansion/R336_DRSUAPIReplicationAttemptRule.cs`, `R337_KerberosS4UDelegationAbuseIndicatorRule.cs`, `R338_KerberosRC4DowngradeIndicatorRule.cs`, `R339_SMBSigningDisabledSensitiveHostRule.cs`, `R340_RemoteRegistryServiceAccessRule.cs` (same directory). Tests: `Carthago.Tests/R336AdvancedAccuracyBatchTests.cs` through `R340AdvancedAccuracyBatchTests.cs`, reusing `Carthago.Tests/NetworkBatch321325Context.cs`.

**R336 (14 unexecuted cases):** `DRSUAPI_REPLICATION_AUDIT_UNAVAILABLE`. DRSUAPI strings and RPC ports do not prove a replication request or unauthorized DCSync. Require parsed RPC interface and operation, authenticated principal, domain controller identity and outcome.

**R337 (14 unexecuted cases):** `KERBEROS_S4U_AUDIT_UNAVAILABLE`. Kerberos port and S4U vocabulary do not prove delegation abuse. Require validated KDC S4U2Self/S4U2Proxy exchanges, principal, service, ticket outcome and approved delegation policy.

**R338 (14 unexecuted cases):** `KERBEROS_ETYPE_AUDIT_UNAVAILABLE`. RC4 or etype 23 text does not prove negotiated Kerberos encryption downgrade. Require parsed KDC ticket encryption type, client/service support and approved baseline.

**R339 (14 unexecuted cases):** `SMB_SIGNING_NEGOTIATION_UNAVAILABLE`. SMB port and signing-disabled text do not prove negotiated signing state or sensitive host role. Require validated SMB negotiation/session flags and approved asset classification.

**R340 (14 unexecuted cases):** `REMOTE_REGISTRY_AUDIT_UNAVAILABLE`. Remote Registry or winreg strings do not prove authenticated service access. Require trusted RPC interface/bind, registry operation outcome, principal and asset approval.

Each rule has six behavior-specific negative theory cases plus eight invariants: Info spoof, duplicate, out-of-order, independent source, missing source, contradictory transport, secret non-emission and original confidence/threshold/Alert profile. All **authored, NOT executed**. No passing regression, field precision or emitted-alert recall claimed. Kerberos port 88 does not establish S4U/etype; SMB port 445 does not establish signing negotiation; generic RPC/SMB strings do not establish authenticated DRSUAPI, registry or named-pipe operations. No TLS decryption or full TCP stream reassembly.

No builds, dotnet, xUnit, replay, benchmark, frozen holdout, CI, GitHub Actions or Windows runner. Single deferred verifier `scripts/verify-all-rule-batches.ps1` unchanged; PowerShell 5.1-safe. Confidence floors, thresholds, modes, approvals, baseline readiness, privacy and frozen evidence preserved. R102 frozen V1 **FAILED 4/6**, immutable; V2 pending independent licensed PCAP and analyst approval. R275 legacy synthetic conflict unchanged.

**R331–R340 total 140 authored unexecuted advanced cases. Next R341–R345 then R346–R350.**
