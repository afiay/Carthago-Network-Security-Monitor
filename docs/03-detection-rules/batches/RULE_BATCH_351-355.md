# R351–R355 — provenance-aware candidate hardening

**Status: CANDIDATE — UNVERIFIED.** Authored 2026-10-28 on
`feature/carthago-reliability-hardening`. No build, xUnit, replay,
benchmark, holdout, CI, runner or production capture was executed for this
batch. All scenario counts below are authored, not passed.

## Source and capability dispositions

| Rule | Disposition | Evidence required and behavior | Live reachability / limitation |
| --- | --- | --- | --- |
| R351 — NTLM authentication to external host | **BLOCKED — trusted NTLM producer absent**; typed unit candidate | Exactly one TCP transport, application-level NTLM/NTLMSSP attribution, internal-to-external boundary and existing two-signal profile. Reject SMB, HTTP, TCP or free-form Info as authentication proof. | `PacketHandler` does not currently parse NTLM challenge/response. Synthetic typed positives are not field observations; a validated NTLM parser or trusted authentication source is required. |
| R352 — LLMNR/NBNS Responder/Inveigh | **BLOCKED — correlated process producer absent**; typed unit candidate | Exact Responder/Inveigh executable basename, typed LLMNR/NBNS application and a single attributed TCP/UDP transport. Reject normal name queries and lookalike executable names. | `PacketHandler` does not establish the remote process responsible for name-service replies. Process and protocol test fixtures are contract-only. Tool attribution is not proof of poisoning success. |
| R353 — GitHub PAT in traffic | **CONDITIONAL — observable cleartext HTTP** | Parser-owned `HttpGitHubTokenPatternObserved` from client-to-server HTTP payload, parsed method/target, TCP/HTTP provenance and existing signal/confidence gates. | `PacketHandler` sets the flag from `HttpLight` on parsed client-to-server payloads. TLS/SNI, host, token words and Info do not expose PAT bytes. Unit positives inject the parser flag reflectively and are NOT real captures. |
| R354 — GitLab private token in traffic | **CONDITIONAL — observable cleartext HTTP** | Parser-owned `HttpGitLabTokenPatternObserved`, parsed method/target and TCP/HTTP provenance. Generic Authorization headers and provider names alone fail closed. | Same parser/HTTPS limitation as R353; synthetic parser flags are contract tests, not observed credentials. |
| R355 — Jenkins script-console probe | **OPERATIONAL — observable HTTP request shape, conditional attribution** | Parsed TCP/HTTP GET or POST to an origin-form `/script` or `/scriptText` terminal path (including a context prefix), plus existing inbound-external and signal gates. | `PacketHandler` parses cleartext HTTP request lines. Endpoint probing does not establish Jenkins server identity, authorization, script execution or successful exploitation; HTTPS without decryption is invisible. |

The above are *development* dispositions. A rule's configured `Alert` mode is
not a claim that it is presently capable of emitting a live alert. No default
mode, approval, suppression, threshold or confidence floor was changed.

## Authored xUnit scenarios (55 total; 0 executed)

- **R351: 10** — typed NTLM/TCP external candidate; three normal
  SMB/HTTP/TCP application controls; spoofed transport protocol label; UDP
  and contradictory flags; internal destination; missing source; unchanged
  confidence/threshold/mode contract.
- **R352: 11** — typed LLMNR/Responder and NBNS/Inveigh candidates;
  four executable-name lookalikes; missing process; missing typed
  application; absent and contradictory transport; unchanged profile.
- **R353: 10** — parser-flag synthetic candidate, untrusted Info token,
  cross-provider flag, TLS-only, missing method/target, UDP contradiction,
  token reaching a non-provider host, query secret redaction across event
  projections and unchanged profile.
- **R354: 10** — same independent GitLab cases with GitLab flag, GitHub
  cross-provider control and private-token-shaped query redaction.
- **R355: 14** — GET and POST console candidates; four lookalike paths;
  unsupported method; TLS-only; missing URI; absolute/authority-relative
  and backslash targets; internal-only boundary; unchanged profile.

Files:
`Carthago.Tests/NetworkBatch351355Context.cs`,
`Carthago.Tests/R351AdvancedAccuracyBatchTests.cs` through
`Carthago.Tests/R355AdvancedAccuracyBatchTests.cs`.
The existing `R351R355ProvenanceGuardTests.cs` remains in place.

## Precision and privacy constraints

- Token flags are parser-owned; tests use reflection solely to emulate the
  parser output and must never be described as capture-backed positives.
- `CloudDevPrecisionDetectionRuleBase` now redacts `http.path` from
  R353–R355 event evidence so request-target query secrets do not appear in
  structured/legacy projections. The underlying record remains unchanged.
- R351/R352 intentionally do not gain synthetic live producer support;
  process name, protocol strings and free-form Info cannot independently
  prove credential exchange, spoofing or poisoning.
- R355 rejects ambiguous absolute/authority-relative request targets; an
  exact terminal console path is a probe-shaped observation only.
- Preserve R102 80%, R118 86%, R163 84%, all existing modes, approvals,
  baseline readiness and privacy boundaries. Frozen R102 holdout V1 remains
  **FAILED 4/6**. V2 remains **PENDING_EXTERNAL_CAPTURE_AND_REVIEW**.
- The 2026-10-28 pre-repair local verification had **4,675/4,733 xUnit
  passed**, 58 failed and replay expectations failed; its results do not
  verify this batch or subsequent repairs. See
  `docs/VERIFICATION_TRIAGE_20261028.md`.

## Publication and verification

Source commit: `12cd46a31df25c54070a6b541ed9418ea92576aa`.
Test commit: `ad3882f7e389cc2d77a6f2dc076475e43fa32ecd`.
Docs/ledger commit: the commit containing this document.

All commits must be published together via a single expected-HEAD
`update_ref` lease. If the lease fails, this batch is **NOT published**;
inspect the new remote HEAD rather than force-updating or advancing the ledger.

**Next sequential batch after safe publication: R356–R360.**
