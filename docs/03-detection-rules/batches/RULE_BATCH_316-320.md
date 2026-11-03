# R316–R320 — POP3, Exchange and Microsoft Graph mail audit provenance

**CANDIDATE / UNVERIFIED.** Five consecutive rules authored, 70 advanced xUnit facts (14 per rule), **ZERO executed**. Static source inspection only. All five deliberately fail closed with `NoMatch/InsufficientEvidence` until trusted producer evidence is available. No positive credential, login, mailbox access or export outcome invented.

Source: `Carthago/Engine/Rules/Expansion/R316_POP3CleartextCredentialExposureRule.cs`, `R317_ExchangeAutodiscoverExternalSprayRule.cs`, `R318_EWSEnumerationBurstRule.cs`, `R319_OWAAdminOrECPProbeRule.cs`, `R320_M365GraphMailExportPatternRule.cs` (same directory).
Tests: `Carthago.Tests/NetworkBatch316320Context.cs` and `Carthago.Tests/R316AdvancedAccuracyBatchTests.cs` through `R320AdvancedAccuracyBatchTests.cs`.

**R316 (14 unexecuted facts):** `POP3_CREDENTIAL_PAYLOAD_PARSER_UNAVAILABLE`. TCP/110, POP3 labels and USER/PASS strings in `Info` cannot establish captured cleartext credential bytes. POP3S/995 is encrypted; no bounded POP3 payload parser or verified redacted credential evidence exists. Require an explicitly bounded parser, TLS state and secret non-retention before any positive.

**R317 (14 unexecuted facts):** `AUTODISCOVER_ENDPOINT_AND_AUTH_AUDIT_UNAVAILABLE`. Requests to `/autodiscover/autodiscover.xml` or `/autodiscover/`, external source IP, and repeated request counts cannot prove verified Exchange endpoint identity, distinct account attempts or failed authentication. Require trusted Exchange endpoint inventory and authenticated per-account outcomes.

**R318 (14 unexecuted facts):** `EWS_OPERATION_RESPONSE_AUDIT_UNAVAILABLE`. EWS paths, FindItem/GetFolder strings, repeated requests or port 443 cannot establish parsed SOAP operation, mailbox scope, authorization or successful enumeration. Require trusted EWS operation/response audit and approved migration exclusions.

**R319 (14 unexecuted facts):** `EXCHANGE_ADMIN_ENDPOINT_IDENTITY_UNAVAILABLE`. `/owa`, `/ecp` and `/ecp/default.aspx` are path indicators, not proof of a verified Exchange admin listener or unauthorized response. Require endpoint identity and authenticated request/response evidence; avoid conflating ordinary OWA use with ECP probing.

**R320 (14 unexecuted facts):** `GRAPH_MAIL_EXPORT_AUDIT_UNAVAILABLE`. `graph.microsoft.com` SNI/host, `/v1.0/me/messages`, mailFolders, delta URLs, or repeated requests cannot establish authenticated Graph export or delivered mailbox data. HTTPS is not decrypted. Require trusted Microsoft Graph audit, principal and approved mail-export scope; Content-Length, if present, is declared not transferred.

Each rule has six behavior-specific unsupported-evidence scenarios and eight invariant cases: descriptor Info spoof, duplicate, out-of-order, independent source, missing source, contradictory UDP/HTTP, secret non-emission, and unchanged confidence/threshold/Alert profile. **All 70 authored; ZERO executed.** No positive event, passing regression, field precision or emitted-alert recall claimed.

No builds, dotnet, xUnit, replay, benchmark, frozen holdout, CI, GitHub Actions or Windows runner. `scripts/verify-all-rule-batches.ps1` remains the single deferred Windows verifier, PowerShell 5.1-safe. PacketHandler does not parse POP3 credentials, SMTP/IMAP auth outcomes, authenticated Exchange/EWS responses or Microsoft Graph export audit; no full TCP reassembly or HTTPS/TLS decryption. Preserve original floors, thresholds, modes, asset approvals, baseline readiness, privacy and architecture. Frozen R102 V1 **FAILED 4/6**, immutable; V2 pending independent licensed PCAP and analyst approval. R275 legacy synthetic conflict unchanged.

**R311–R320 combined: 140 advanced xUnit facts authored, ZERO executed. Next R321–R325 then R326–R330.**
