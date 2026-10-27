# Rule accuracy batch 04 — R016–R020

**Status: CANDIDATE — UNVERIFIED.** Source, xUnit and development replay fixture authoring only. No build, xUnit, replay, holdout or Windows verification has been executed. The 43 new xUnit facts are assertions awaiting execution, not passed tests. The five new replay controls are benign and must not be represented as field-labeled malicious cases.

## Detector review and candidate evidence boundaries

| Rule | Evidence and precision changes | New advanced xUnit facts |
| --- | --- | ---: |
| R016 — Reputation / AbuseIPDB | Validate source IP and publicly routable destination, score within 0–100, reject explicitly benign classification and nonpositive report counts, reject enrichment timestamps >5 min in the future or >30 days stale. Preserve score-only legacy observations if optional metadata is missing. Retain Balanced score threshold 75 and Critical at 90. Only corroborated malicious classification with positive reports can penalize a learned service; an uncorroborated score still produces a review candidate without poisoning the learner. | 8 |
| R017 — Internal Host Sweep | Require valid distinct private source and destination, positive-length TCP initial SYN or UDP observation, valid destination port, and per-source/per-port/per-transport distinct destination counting. Remove stale/future observations before counting, bound state per key, and clear the window even when an event is suppressed. Preserve configured 10 hosts / 30 seconds at Balanced. | 8 |
| R018 — HTTP to IP Literal Without Host | Require valid source/destination IPs, observed cleartext HTTP/1.1 request evidence and a complete header block or explicitly captured structured headers. Reject HTTP responses, HTTP/1.0 (Host optional), HTTP/2 pseudo-header traffic, incomplete header captures, conflicting method/URI fields, and explicit Host or :authority evidence. Keep URI/header content out of event descriptions. | 9 |
| R019 — Encoded / Long URI | Inspect the observed HTTP request-target, preferring structured HttpUri and requiring consistency with any captured raw request line. Ignore response headers and unanchored HTTP-looking prose; exclude encrypted/QUIC and unattributed flows. Preserve configured URI length 2000, chunk length 80 and entropy 4.0 at Balanced. Bound parsed request lines to 64 KiB and never emit URI/token content. | 9 |
| R020 — Outbound SMTP Direct to Internet | Require a private source, publicly routable destination, TCP/25 and an initial SYN or explicit observed SMTP service classification. Reject UDP, reverse SYN-ACK, unrelated established TCP, private/loopback/documentation destinations, and missing attribution. Preserve the configured SMTP source allowlist including 10.0.0.10 and existing High severity. | 9 |

**Total newly authored xUnit facts: 43** (8+8+9+9+9). The existing rule descriptors, config thresholds, runtime policy, confidence floors and frozen holdout are unchanged.

## Labeled development replay controls

- r016-contradictory-benign-reputation.json: explicitly benign classification must override a high score for R016.
- r017-ack-only-not-host-sweep.json: a TCP ACK is not a new scan probe for R017.
- r018-host-present-not-hostless.json: a complete HTTP/1.1 request with Host is a negative for R018.
- r019-long-header-short-uri.json: long header text is not a long request URI for R019.
- r020-udp-port25-not-smtp-egress.json: UDP destination port 25 is not direct outbound SMTP for R020.

These controls intentionally use expectedMatches: [] and explicit expectedNonMatches for their own rule. No synthetic malicious truth labels are invented for activity whose authorization is unknown. The consolidated Windows verifier at scripts/verify-all-rule-batches.ps1 already discovers the new R016–R020 advanced classes, requires contiguous coverage and five passing cases per rule, and saves a complete TXT plus stage logs when testing is explicitly authorized.

## Remaining uncertainty and safety constraints

- R016: Reputation is third-party enrichment, not proof of a malicious flow; old-but-relevant scores and stale source metadata can reduce recall. Missing optional metadata is accepted to preserve legacy observations. Explicitly malicious flags and report counts are still provider claims, not independent validation.
- R017: Legitimate asset inventory, vulnerability scans and patch orchestration can look like a sweep. A UDP datagram to a new destination is weaker evidence than a completed connection. The in-memory state is per sensor and does not establish host intent.
- R018: Captured HTTP headers may be truncated or normalized by proxies; structured HttpRequestHeaders is trusted as a complete observed header set only when provided. HTTP/1.0 and HTTP/2 require different Host/authority semantics. This rule detects a protocol anomaly, not an attack.
- R019: Long legitimate URLs, signed download URLs and authentication redirects can be flagged. High entropy is heuristic. The 64 KiB guard excludes exceptionally large request lines; raw path content is deliberately not logged.
- R020: Approved mail servers absent from the configured allowlist can be flagged. TCP SYN or SMTP classification does not establish successful mail delivery or abuse. The allowlist remains an exact-IP configuration, not a dynamic baseline.
- Shared legacy detector state is reset by replay-oriented xUnit fixtures; the new tests use the same xUnit collection as Batch 03 to serialize those two batches, but other existing collections may still run concurrently. If nondeterminism appears at the deferred full-suite gate, address collection isolation without weakening detection assertions.
- No configured thresholds, R102 ≥ 80%, R118 ≥ 86%, R163 ≥ 84%, Shadow/Disabled modes, IoT asset approvals, baseline-readiness controls, frozen holdout files or data-privacy protections were weakened.

## Deferred acceptance

Do not run a build or any tests until the project owner explicitly says "now it's test time". Then freeze the exact branch SHA and execute the single Windows verification entry point, inspect all TRX, development replay, holdout and complete TXT evidence, and fix failures without lowering thresholds to satisfy fixtures. Synthetic recognition is not independently labeled field precision or operational alert recall.
