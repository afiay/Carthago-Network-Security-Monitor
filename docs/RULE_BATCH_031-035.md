# Rule accuracy batch 07 — R031–R035

**Status: CANDIDATE — UNVERIFIED.** Authored 30 advanced xUnit facts (six per rule) and five benign development replay controls. No builds, xUnit, development replay, holdout or Windows runner executed.

| Rule | Precision and evidence boundary | Advanced facts |
| --- | --- | ---: |
| R031 DNS TXT spike | Preserve 15 distinct-timestamp query observations per client/resolver within 60 seconds. Reject responses, non-TXT, wrong ports, invalid IPs, contradictory service and incomplete queries. Clear suppressed windows. | 6 |
| R032 HTTP User-Agent | Require attributable HTTP requests with a structured method. Reject protocol-only or contradictory metadata and sanitize the untrusted User-Agent from alerts. | 6 |
| R033 ICMP oversized echo | Preserve 1000-byte threshold, require ICMP echo request/reply type and valid endpoints. Exclude ICMP errors and untyped observations. | 6 |
| R034 DNS-over-HTTPS | Require structured GET with a DNS query parameter or POST with DNS message content type on /dns-query; no raw request text in alerts. | 6 |
| R035 Rare SSH fingerprint | Require attributable SSH observation and valid fingerprint. Preserve first-three rarity semantics, bound state, ignore duplicate timestamps, decay novelty after 60 minutes, never log fingerprint. | 6 |

**Development replay negatives**: R031 DNS response; R032 HTTP response-like metadata; R033 ICMP error; R034 HTTP health endpoint with DoH prose; R035 HTTP traffic with SSH fingerprint field. Each has an explicit expectedNonMatches assertion. These are synthetic labels, not field precision.

## Residual risks

- R031 same-timestamp genuine TXT queries are deduplicated; high-rate captures with coarse timestamps may lose recall. Authorized DNS TXT-heavy workloads can still match.
- R032 legitimate curl/automation traffic can match; no asset-specific approval inventory exists here. Encrypted HTTP without parsed method is not assessed.
- R033 headerless ICMP captures no longer qualify, trading recall for protection against ICMP errors and other non-echo traffic. Length includes headers rather than verified payload bytes.
- R034 alternate DoH paths, opaque HTTPS and HTTP/3 may evade this narrowly scoped rule. Shared R038 DoH helper was intentionally not changed.
- R035 rarity is a global in-memory heuristic; an uncommon SSH client is not necessarily malicious. Duplicate timestamps across distinct clients are conservatively deduplicated, and 60-minute inactivity resets novelty.
- R102 80%, R118 86%, R163 84% confidence floors, Shadow/Disabled policy, approval gates, baseline readiness and frozen holdout are unchanged. No promotion or field precision claim is made.

## Deferred acceptance

The existing `scripts/verify-all-rule-batches.ps1` discovers the five new advanced classes, requires at least five passing cases per rule, and performs one full Windows regression, one development replay and one frozen holdout. Do not execute until the owner explicitly says **now it's test time**.
