# R321–R325 — mail operation and sender provenance

**CANDIDATE / UNVERIFIED.** Five consecutive precision candidates; **70 advanced xUnit facts authored (14 each), ZERO executed**. Static source inspection only. Each rule intentionally returns `NoMatch/InsufficientEvidence` until trusted mail operation, validated content, or sender-identity evidence is integrated. No positive attack or identity outcome invented.

Source: `Carthago/Engine/Rules/Expansion/R321_GmailAPIBulkMessageReadRule.cs`, `R322_MailForwardingRuleCreationIndicatorRule.cs`, `R323_SuspiciousAttachmentDownloadBurstRule.cs`, `R324_PhishingKitURIPatternRule.cs`, `R325_LookalikeSenderDomainContactRule.cs` (same directory).
Tests: `Carthago.Tests/NetworkBatch321325Context.cs` and `Carthago.Tests/R321AdvancedAccuracyBatchTests.cs` through `R325AdvancedAccuracyBatchTests.cs`.

**R321 (14 unexecuted facts):** `GMAIL_READ_AUDIT_UNAVAILABLE`. Gmail API paths and hostnames do not prove authenticated reads or bulk message results.

**R322 (14 unexecuted facts):** `MAIL_FORWARDING_AUDIT_UNAVAILABLE`. Forwarding paths and HTTP POST do not prove successful authenticated rule creation.

**R323 (14 unexecuted facts):** `ATTACHMENT_RESULT_AUDIT_UNAVAILABLE`. Attachment paths and repeated requests do not prove successful downloads or bytes transferred.

**R324 (14 unexecuted facts):** `VALIDATED_KIT_SIGNATURE_UNAVAILABLE`. Generic login and verification paths do not prove a phishing kit.

**R325 (14 unexecuted facts):** `SENDER_IDENTITY_AUDIT_UNAVAILABLE`. DNS and SNI contacts do not establish authenticated sender identity or protected-domain similarity.

Per rule: six behavior-specific apparent-positive cases plus eight invariants (Info spoof, duplicate, out-of-order, independent source, missing source, contradictory UDP/HTTP, secret non-emission, and original confidence/threshold/Alert profile). These are authored **but NOT executed**. No passing regression, field precision or emitted-alert recall claimed. The capture pipeline has no authenticated Gmail API, mail-forwarding, attachment download or sender identity audit, no verified kit signature, no HTTPS decryption and no complete TCP reassembly.

No builds, xUnit, replay, benchmark, frozen holdout, CI, GitHub Actions or runner. The single deferred verifier `scripts/verify-all-rule-batches.ps1` is unchanged and PowerShell 5.1-safe. Preserve existing confidence floors, thresholds, modes, approvals, baseline readiness, privacy and frozen evidence. Frozen R102 V1 **FAILED 4/6** immutable; V2 independent reviewed PCAP and analyst approval pending. R275 legacy synthetic conflict unchanged.

**Next R326–R330 then R331–R335.**
