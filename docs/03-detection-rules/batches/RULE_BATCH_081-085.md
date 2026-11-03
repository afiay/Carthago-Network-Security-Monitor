# Rule hardening batch 17 — R081–R085

**CANDIDATE — UNVERIFIED.** Five rule adapters, one shared typed-evidence component, five advanced xUnit classes (**35 facts, seven per rule**), one typed test-record factory and two benign-only development replay controls. No build, xUnit, benchmark, replay, holdout, Windows runner or other automated test was executed.

## Code audit and changes

| Rule | Legacy detector weakness | Candidate requirement and state | Advanced xUnit facts |
| --- | --- | --- | ---: |
| **R081 — AS-REP Roasting Heuristic** | Any text mentioning AS-REQ, AS-REP, etype 23 or no preauthentication on destination port 88 could trigger. That port is the request direction, not an AS-REP reply. | Parsed `KERBEROS/AS_REP_NO_PREAUTH` **reply** from internal KDC source port 88 to an internal client. Three distinct records from one KDC to one client in a 60-second default window. No user principal is stored. | 7 |
| **R082 — NTLM Relay Suspicion** | A text token `NTLMSSP` or `relay` alone triggered, while ordinary traffic fan-out to eight hosts was treated as possible relay. | Independently classified `NTLM/RELAY_CORROBORATED` on an internal TCP session to 80/135/139/445/5985/5986. **Eight** distinct observations per source/target within 120 seconds by default, retaining the previous fan-out count of eight as a conservative threshold. Ordinary negotiate/challenge/authenticate are excluded. | 7 |
| **R083 — LLMNR/NBNS Poisoning Attempt** | Any name-service response or prose mentioning poisoning could trigger, even when benign. | Parsed `LLMNR` or `NBNS` `CONFLICTING_RESPONSE`, UDP source port 5355/137, actual response bit, valid question and answer, attributed private responder, private/multicast/broadcast destination. Two distinct observations per responder/peer/service in 60 seconds by default. | 7 |
| **R084 — Log4Shell/JNDI Injection Pattern** | Generic payload normalizer combined unrelated record fields and emitted original and normalized payload snippets, including possible secrets. | Attributable HTTP request with valid method, transport, host and URI; well-formed complete headers if present. Bounded two-pass percent-decoding of URI, parsed User-Agent and headers; JNDI lookup with recognized scheme. Raw payload and host names are excluded from alert evidence. Repeated record IDs are suppressed. | 7 |
| **R085 — SQL Injection Pattern** | Generic payload matching could flag benign SQL vocabulary and copy sensitive normalized/original payload into evidence. | Attributable HTTP request; narrowly scoped boolean-tautology with comment, quoted UNION SELECT FROM in query, or delay-probe expressions. Bounded decoding and regex timeouts, no raw query/credentials in alert, repeated record IDs suppressed. | 7 |

The R081/R082/R083 count and time-window overrides use `RuleEngine.GetRuleIntSetting`. No production rules.json, existing configured overrides, confidence floors, rule enablement defaults or runtime policy were edited. R084/R085 retain one-observation matching for strongly structured attack patterns rather than weakening confidence requirements.

## Advanced coverage and replay

Each rule has seven separate `[Fact]` tests in `Carthago.Tests/RNNNAdvancedAccuracyBatchTests.cs`:

- R081: repeated preauthless AS-REP positive; ordinary AS-REP/TGS negatives; wrong direction/port/transport; KDC/client isolation; replay and out-of-order handling; window expiry; cancellation, future time and redaction.
- R082: eight classified observations positive; benign NTLM authentication; fan-out without relay classification; wrong transport/public target; source/target isolation and expiry; replay/out-of-order; cancellation and redaction.
- R083: LLMNR conflict positive; NBNS broadcast conflict positive; ordinary responses/prose negatives; incomplete answers and wrong port; responder/service isolation; replay/expiry/transport contradiction; cancellation and DNS-answer redaction.
- R084: direct JNDI lookup; twice-percent-encoded lookup; interpolated JNDI and header request; benign documentation/Info-only; wrong transport, method, host and truncated headers; duplicate-record handling; cancellation and privacy.
- R085: quoted boolean tautology; encoded UNION SELECT; SQL delay expression; benign SQL vocabulary/Info-only; contradictory transport/method/host; duplicate-record handling; cancellation and query redaction.

Two new **benign-only** development replay fixtures assert R084/R085 nonmatches for documentation/search requests. They are not malicious labels, do not assert a precision percentage and do not change the frozen holdout. No positive replay fixture was manufactured for R081–R083 because the current replay schema cannot attest to actual AS-REP preauthentication state, NTLM relay correlation or conflicting LLMNR/NBNS responses.

## Precision, privacy and integration limitations

**The required typed service classifications are proposed capture-adapter contracts, not verified live parser output.** Existing capture may not populate `KERBEROS/AS_REP_NO_PREAUTH`, `NTLM/RELAY_CORROBORATED` or `LLMNR|NBNS/CONFLICTING_RESPONSE`. These rules fail closed in that case, risking recall loss. A service classification must not be synthesized from `TrafficRecord.Info` or port alone. A later integration audit must verify actual wire-protocol parsing and trusted provenance before promotion.

R081's repeated replies cannot prove credential cracking or that the same account is involved; no principal is retained. R082's classification must be independently supported by cross-flow correlation, not inferred from a routine NTLM handshake. R083's conflict label must be established against actual competing responses or an approved baseline; legitimate multi-homed responses can resemble conflicts.

R084/R085 do not inspect HTTP bodies, TLS ciphertext, non-HTTP protocols or more than two percent-decoding layers. HTTP header completeness and host consistency are mandatory if headers are present; this can reduce recall. R084 supports the direct `${jndi:...}` and `${${lower:j}ndi:...}` forms; other nested interpolation or non-URL schemes are not yet covered. R085 patterns intentionally omit generic `SELECT`, `OR`, `UNION` and equality keywords, trading recall for precision. Regex matching is bounded with a timeout and fails closed. Legitimate security scans can still produce true pattern matches without malicious intent.

Bounded observation windows and duplicate state are per rule instance and are not persisted across restarts. Packet IDs must be unique per observation. Clock and adapter provenance require later validation.

## Deferred acceptance

**Do not execute any build or test yet.** `scripts/verify-all-rule-batches.ps1` remains the sole deferred local Windows verification entry point and discovers all five new advanced test classes by filename. The 35 authored facts and two benign replay controls are **UNVERIFIED**. The existing R102=80%, R118=86%, R163=84% confidence floors, baseline-readiness and asset-approval safeguards, Shadow/Disabled policies and frozen holdout are untouched.

**Next batch to author: R086–R090.**
