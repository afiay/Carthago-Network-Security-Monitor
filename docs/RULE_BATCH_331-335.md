# R331–R335 — Calendar, mail archive and SMB/RPC provenance

**CANDIDATE — UNVERIFIED.** Five consecutive rules, **70 advanced xUnit cases authored (14 per rule), ZERO executed**. Static source inspection only. No authenticated calendar/mail/SMB session or RPC operation-outcome producer is available through the inspected TrafficRecord/PacketHandler path. No positive outcome or attack event is invented.

Source: `Carthago/Engine/Rules/Expansion/R331_CalendarInvitePhishingLinkPatternRule.cs` through `R335_LSARPCSAMREnumerationPatternRule.cs` (five actual files). Tests: `Carthago.Tests/R331AdvancedAccuracyBatchTests.cs` through `R335AdvancedAccuracyBatchTests.cs`, reusing `Carthago.Tests/NetworkBatch321325Context.cs`.

**R331 (14 unexecuted cases):** `CALENDAR_INVITE_AUDIT_UNAVAILABLE`. A calendar URL or ICS-looking request does not prove an invitation was delivered or that its link is phishing. Require authenticated calendar message, recipient and validated destination evidence.

**R332 (14 unexecuted cases):** `MAIL_EXPORT_RESULT_UNAVAILABLE`. Archive-looking URLs and HTTP GET requests do not establish an authenticated mail export, successful download, or transferred bytes. Require trusted mail export audit and delivery outcome.

**R333 (14 unexecuted cases):** `SMB_SESSION_AUTH_AUDIT_UNAVAILABLE`. SMB port and IPC$ vocabulary do not prove anonymous SMB authentication or enumeration. Require validated SMB session identity, tree connect and enumeration outcome.

**R334 (14 unexecuted cases):** `SMB_PIPE_OPEN_AUDIT_UNAVAILABLE`. Named-pipe strings and SMB traffic do not establish successful pipe opens or enumeration bursts. Require trusted per-session pipe-open results and distinct bounded operations.

**R335 (14 unexecuted cases):** `RPC_ENUMERATION_AUDIT_UNAVAILABLE`. SAMR or LSARPC text and SMB port do not prove an authenticated RPC bind or enumeration result. Require validated RPC interface, operation, identity and outcome.

Each rule has six behavior-specific negative theory cases plus eight independent invariants: Info spoof, duplicate, out-of-order, independent source, missing source, contradictory transport, secret non-emission, and original confidence/threshold/Alert profile. These tests are **authored, NOT executed**, and no compile or accuracy claim is made. PacketHandler does not decode authenticated calendar events, completed mail downloads, SMB anonymous session outcomes, named-pipe opens or SAMR/LSARPC enumeration outcomes. SMB ports, IPC$ strings and HTTP paths cannot prove these behaviors. No TLS decryption or full TCP stream reassembly.

No builds, dotnet, xUnit, replay, benchmark, frozen holdout, CI, GitHub Actions or Windows runner. Single deferred verifier `scripts/verify-all-rule-batches.ps1` unchanged; PowerShell 5.1-safe. Confidence floors, thresholds, modes, approvals, baseline readiness, privacy and frozen evidence preserved. R102 frozen V1 **FAILED 4/6**, immutable; V2 pending independent licensed PCAP and analyst approval. R275 legacy synthetic conflict unchanged.

**Next R336–R340, then R341–R345.**
