# R326–R330 — DNS mail policy and collaboration outcome provenance

**CANDIDATE / UNVERIFIED.** Five consecutive conservative precision changes; **70 advanced xUnit cases authored (14 per rule), ZERO executed**. Static inspection only. Each rule intentionally returns `NoMatch/InsufficientEvidence` until authenticated producer and outcome evidence is available. No positive event invented.

Source: `Carthago/Engine/Rules/Expansion/R326_DMARCSPFDKIMReconQueryBurstRule.cs`, `R327_SlackOAuthAppInstallCallbackRule.cs`, `R328_TeamsWebhookAbuseIndicatorRule.cs`, `R329_SharePointBulkDownloadPatternRule.cs`, `R330_OneDriveAnonymousShareLinkMassAccessRule.cs` (same directory).
Tests: `Carthago.Tests/R326AdvancedAccuracyBatchTests.cs` through `R330AdvancedAccuracyBatchTests.cs`, reusing `Carthago.Tests/NetworkBatch321325Context.cs`.

**R326 (14 unexecuted cases):** `DNS_MAIL_POLICY_AUDIT_UNAVAILABLE`. DMARC/SPF/DKIM DNS lookups are legitimate and do not independently establish unauthorized reconnaissance.

**R327 (14 unexecuted cases):** `SLACK_INSTALL_AUDIT_UNAVAILABLE`. OAuth paths and callbacks do not prove successful Slack app installation or workspace consent.

**R328 (14 unexecuted cases):** `TEAMS_WEBHOOK_AUDIT_UNAVAILABLE`. Webhook POST requests do not establish accepted messages, connector identity or unauthorized activity.

**R329 (14 unexecuted cases):** `SHAREPOINT_DOWNLOAD_AUDIT_UNAVAILABLE`. SharePoint GET paths do not prove authenticated bulk downloads or transferred bytes.

**R330 (14 unexecuted cases):** `ONEDRIVE_SHARE_AUDIT_UNAVAILABLE`. Anonymous share-link paths and authkey parameters do not establish actual anonymous permissions or successful file access.

Each rule has six behavior-specific negative theory cases plus eight negative/policy invariants: descriptor Info spoof, duplicate, out-of-order, independent source, missing source, contradictory UDP/HTTP, sensitive query/header non-emission, and original confidence/threshold/Alert profile. All cases **authored, NOT executed**. No passing regression, field precision or emitted-alert recall claimed. No full TCP reassembly or HTTPS decryption. No trusted Slack, Teams, SharePoint or OneDrive authenticated outcome producer connected; DNS policy queries alone cannot prove intent.

No builds, dotnet, xUnit, replay, benchmark, frozen holdout, CI, GitHub Actions or Windows runner. `scripts/verify-all-rule-batches.ps1` remains the single deferred verifier, PowerShell 5.1-safe. Existing confidence floors, thresholds, modes, approvals, baseline readiness, privacy and frozen evidence preserved. Frozen R102 V1 **FAILED 4/6**, immutable; V2 pending independent licensed PCAP and analyst approval. R275 legacy synthetic conflict unchanged.

**R321–R330 total 140 authored unexecuted advanced cases. Next R331–R335 then R336–R340.**
