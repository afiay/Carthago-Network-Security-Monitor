# R276–R280 — fail-closed OAuth, legacy authentication, spraying, stuffing and session replay

**CANDIDATE — UNVERIFIED.** Authored 2026-10-28 on existing `feature/carthago-reliability-hardening`. **55 advanced xUnit facts authored (11 per rule), ZERO executed.** No build, xUnit, replay, benchmark, V1/V2 holdout, CI, GitHub Actions or Windows runner. Static source/diff inspection only.

## Commits and exact paths

- Source: `27ba609074a0c271904b9ff5fe0f3310e982d094`. Five production files in `Carthago/Engine/Rules/Expansion/`: `R276_OAuthConsentGrantAbuseIndicatorRule.cs`, `R277_LegacyProtocolAuthenticationAttemptRule.cs`, `R278_PasswordSprayLowAndSlowAcrossAccountsRule.cs`, `R279_CredentialStuffingRotatingUserAgentRule.cs`, `R280_SessionTokenReplayAcrossGeographiesRule.cs`.
- Tests: `eb116e0c0862ac68f53e17216eba9982ec37a2ad`. Fixture: `Carthago.Tests/NetworkBatch276280Context.cs`; five classes `Carthago.Tests/R276AdvancedAccuracyBatchTests.cs` through `R280AdvancedAccuracyBatchTests.cs`, 11 facts each.
- Progress ledger: `docs/RULE_HARDENING_PROGRESS.md`; this document: `docs/RULE_BATCH_276-280.md`. Single deferred Windows verifier `scripts/verify-all-rule-batches.ps1` unchanged and **not executed**.

## Observable contracts and authored test cases

**R276 (11, fail-closed):** Consent endpoint paths, `offline_access` or `Mail.Read` scopes and OAuth text cannot prove a grant. A trustworthy IdP audit must identify tenant, app, actor, granted scopes and outcome. Tests cover admin-consent URI, scope query, Info spoof, Graph host, process spoof, duplicate, out-of-order, missing actor, contradictory transport, secret non-emission and 78/1/Alert profile preservation. **No authenticated grant event producer is connected. No positive grant was invented.**

**R277 (11, fail-closed):** IMAP/POP3/SMTP ports, banners, Info text and HTTP Basic headers do not establish legacy-protocol authentication attempts. Requires a bounded parsed protocol AUTH command with direction/provenance or a trusted server-side authentication event. Tests cover IMAPS, POP3, SMTP submission, Info spoof, protocol label, HTTP Basic mismatch, duplicate, out-of-order, missing destination, contradictory transport and 74/1/Alert preservation. **No POP/IMAP/SMTP AUTH captured-byte adapter was found. No positive authentication event was invented.**

**R278 (11, fail-closed):** Packet requests cannot establish failed logins across distinct accounts without trusted account identifiers, outcome and source. Tests cover failure-text spoof, six HTTP requests, user query, changing destinations, many-users Info spoof, duplicate, out-of-order, missing source, UDP/HTTP contradiction, private account non-emission and 78/5/Alert preservation. **No positive spray was invented.**

**R279 (11, fail-closed):** Login paths and rotating HTTP User-Agent strings are not credential-stuffing evidence without independently verified authentication failures and account correlation. Tests cover login+UA, six rotating UAs, Info spoof, HTTP 403 ambiguity, UA alone, duplicate, out-of-order, independent sources, contradictory transport, UA non-emission and 78/5/Alert preservation. **No positive credential-stuffing event was invented.**

**R280 (11, fail-closed):** Raw cookies, packet GeoIP and SNI do not establish reuse of the same authenticated session. Requires an IdP/session audit with privacy-preserving token fingerprint, account, source, time and location. Tests cover cookie text, two countries, SNI+GeoIP, Info spoof, raw cookie header, duplicate, out-of-order, missing source, contradictory transport, secret non-emission and 78/2/Alert preservation. **No raw session token is stored or emitted; no positive replay event was invented.**

## State, privacy, approvals and known gaps

All five candidates return `NoMatch` with explicit `InsufficientEvidence` reason codes until real authenticated producers exist. This avoids building global counters on packet descriptions, false account cardinality, fake MFA/consent outcomes or fabricated token replay. No new state, unsafe PII retention or external network calls were added. Existing default Alert modes and confidence/threshold declarations remain unchanged; **the declared profile does not make an alert reachable** without trusted telemetry.

`TrafficRecord` does not contain authenticated IdP grant, account failure, MFA, or session reuse events. `PacketHandler` cannot decrypt HTTPS or reconstruct full TCP streams; typed HTTP URI/headers alone do not establish server authentication outcomes. Existing `R275` legacy synthetic positive and paired replay conflict with the preceding fail-closed batch and remain **unmodified and unexecuted**. No frozen V1/V2 evidence, replay labels, baseline readiness, asset approvals or policy floors were changed.

Frozen R102 V1 **FAILED 4/6** immutable; V2 independent licensed PCAP and analyst approval **PENDING**. Earlier user-run R001–R125 and synthetic 48/48 do not validate these rules or emitted-alert recall. Other known gaps remain: no `DnsTtl`/`DnsAnswers` in live capture, R262 IPv4 fragment contract-only, R227 Profinet L2 contract-only, R228 OPC UA parser absent, process enrichment unverified, Content-Length declared not delivered, /24 not an approved segmentation boundary.

**R271–R280 combined: 10 consecutive rules, 115 advanced xUnit facts authored, ZERO executed; CANDIDATE/UNVERIFIED. Next R281–R285 then R286–R290** unless live branch/ledger advanced. Owner must explicitly say "now it's test time" before any automated verification.
