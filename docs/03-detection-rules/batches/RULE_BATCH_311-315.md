# R311–R315 — workload metadata, network policy and mail authentication provenance

**CANDIDATE / UNVERIFIED.** Five consecutive rules authored, 70 advanced xUnit facts (14 per rule), **ZERO executed**. Static source inspection only. All five deliberately fail closed with `NoMatch/InsufficientEvidence` until trusted producer evidence is available. No positive attack/identity/transfer event was invented.

Source: `Carthago/Engine/Rules/Expansion/R311_CloudWorkloadMetadataTokenRequestRule.cs`, `R312_KubernetesNetworkPolicyBypassIndicatorRule.cs`, `R313_DirectSMTPToMXFromWorkstationRule.cs`, `R314_SMTPAuthenticationFailureBurstRule.cs`, `R315_IMAPLoginFailureSprayRule.cs` (same directory).
Tests: `Carthago.Tests/NetworkBatch311315Context.cs` and `Carthago.Tests/R311AdvancedAccuracyBatchTests.cs` through `R315AdvancedAccuracyBatchTests.cs`.

**R311 (14 unexecuted facts):** `CLOUD_WORKLOAD_IDENTITY_AND_TOKEN_RESPONSE_UNAVAILABLE`. A captured request to AWS/GCP/Azure metadata endpoints is not proof of cloud-workload identity, token issuance or credential compromise. Require trusted workload identity/asset inventory and metadata service response audit. Metadata hostnames, URL paths, headers, process labels and Info alone are insufficient.

**R312 (14 unexecuted facts):** `K8S_POLICY_ENFORCEMENT_AUDIT_UNAVAILABLE`. Pod-IP traffic, different /24 addresses or CNI labels do not establish an effective Kubernetes NetworkPolicy, enforced deny decision or observed bypass. Require versioned policy, endpoint/namespace inventory and authenticated CNI enforcement/flow outcomes.

**R313 (14 unexecuted facts):** `WORKSTATION_ROLE_AND_MX_DESTINATION_UNVERIFIED`. TCP/25, SMTP labels, MX queries and unverified process names do not establish approved workstation role, MX answer mapping, external direct-to-MX delivery or relay bypass. Require approved asset roles and resolver/server attribution; distinguish sanctioned SMTP relays and mail migrations.

**R314 (14 unexecuted facts):** `SMTP_AUTH_FAILURE_OUTCOMES_UNAVAILABLE`. AUTH commands, ports 25/465/587, Info strings or 535 text cannot establish server-authenticated login failures. Require parsed server responses and account-scoped, duplicate-resistant audit. SMTP over TLS is not decrypted.

**R315 (14 unexecuted facts):** `IMAP_ACCOUNT_FAILURE_AUDIT_UNAVAILABLE`. Ports 143/993, LOGIN text and claimed account counts do not prove failed authentication across distinct principals. Require verified server outcomes, account privacy and source/window correlation. IMAPS is not decrypted.

Each rule has six behavior-specific close-benign/unsupported-evidence scenarios and eight invariant cases: descriptor Info spoof, duplicate, out-of-order, independent source, missing source, contradictory UDP/HTTP, secret non-emission, and unchanged confidence/threshold/Alert profile. **All 70 authored; ZERO executed.** Fail-closed tests are not positive detection coverage, passing regressions, field precision or recall.

No builds, dotnet, xUnit, replay, benchmark, frozen holdout, CI, GitHub Actions or Windows runner. `scripts/verify-all-rule-batches.ps1` remains the single deferred Windows verifier (PowerShell 5.1-safe). PacketHandler does not populate trusted cloud workload identity, Kubernetes policy decision, workstation role, MX answer attribution, SMTP/IMAP server login outcomes or principal identities; no full TCP reassembly or HTTPS/TLS decryption. Preserve original confidence floors, thresholds, modes, asset approvals, baseline readiness, privacy and architecture. Frozen R102 V1 **FAILED 4/6**, immutable; V2 pending independent licensed PCAP and analyst approval. Existing R275 legacy synthetic conflict unchanged.

**Next R316–R320, then R321–R325.**
