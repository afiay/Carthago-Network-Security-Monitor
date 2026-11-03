# R131-R135 HTTP authentication and credential exposure hardening

**CANDIDATE - UNVERIFIED.** 40 new advanced xUnit facts (eight per rule) authored;
no compilation, tests, replay, holdout, benchmark or Windows runner execution.

| Rule | Narrow production change | Eight authored advanced cases |
| --- | --- | --- |
| R131 | Parser-attributed HTTP auth failures; no URI status-only promotion; bounded instance-owned duplicate-resistant burst; per-source/host/path-fingerprint isolation. | 15 independent failures, duplicate ID, generic 403, query-only 401, UDP/missing TCP, expiry, host isolation, secret path/Shadow. |
| R132 | Attributed HTTP login, valid source ISO-2 code and stable extracted identity; instance-owned distinct-country window; hashed identity evidence and state key. | Three countries, same country, replayed ID, missing/invalid geo, identity/host isolation, expiry, missing identity/transport, pseudonymization/Shadow. |
| R133 | Require attributed cleartext HTTP and actual parsed Authorization/Proxy-Authorization Basic header; validate Base64-decoded username:password shape; zero temporary decoded bytes. | Cleartext positive, HTTPS negative, UDP/port-only, Info spoof, malformed/noncredential Basic, proxy auth, TLS contradiction, privacy/Alert. |
| R134 | Require captured HTTP URI with a named sensitive query parameter and opaque non-placeholder value; reject fragments, benign state/CSRF/pagination and host contradictions. | Query positive, benign parameters, fragment, weak placeholder, encoded value, transport/host, redaction/Alert, Info-only negative. |
| R135 | Require attributed cleartext HTTP and actual parsed Authorization/Proxy-Authorization Bearer header; reject TLS contradictions and weak placeholders. | Cleartext positive, HTTPS negative, Info spoof, UDP/missing TCP, weak token, proxy auth, TLS contradiction, privacy/Alert. |

Shared `NetworkBatch131135Evidence` uses the previously authored
`NetworkBatch126130Evidence.HttpRequest` transport/endpoint contract and
`NetworkBatch126130Window` bounded observation state (256 keys / 512
observations per key, chronological pruning, duplicate record-ID resistance).
The capture-adapter's HTTP request and header provenance is a prerequisite;
port, packet Info and URL keywords alone are not sufficient.

**Privacy:** For R131-R135, `MatchIdentityAccess` no longer auto-emits
raw HTTP paths. Each rule emits a fixed route category and uses a path
fingerprint in cooldown/window keys instead of persisting path segments.
R132 emits a truncated SHA-256 identity fingerprint rather than the raw
email/username. R133/R135 never persist header values; R134 never persists
query values or attacker-chosen parameter names. Base64 Basic material is
decoded only for validation and the temporary byte array is zeroed.

**Preserved:** Existing rule IDs, categories, severity, minimum-confidence
floors (R131=72%, R132=72%, R133=86%, R134=86%, R135=88%),
thresholds, windows, cooldowns, Shadow/Alert defaults, baseline/asset
approval and runtime Disabled policy. The unrelated R102=80%, R118=86%,
R163=84% floors remain untouched. Frozen V1 holdout stays FAILED 4/6;
V2 requires independently reviewed typed PCAP evidence and approval.

**Unverified risks:** HTTP parser fields may be unavailable after capture
redaction, especially Authorization headers. A packet-level monitor cannot
infer a server's response status from an outgoing request alone; R131's
Info failure marker needs adapter provenance. R132's GeoIP is not an
independent login event and can drift even for a stable source IP;
the old synthetic three-country example does not prove impossible travel.
Requiring ISO-2, typed HTTP and valid Base64 may reduce recall in incomplete
captures; this is intentional until evidence supports alternatives.
The shared bounded window drops oldest keys at capacity; concurrency,
out-of-order traffic, policy emission and precision remain unverified.

The existing one-run Windows entry point
`scripts/verify-all-rule-batches.ps1` automatically discovers the five
new advanced test files. **Do not execute** until the user explicitly says
"now it's test time". The 40 cases are authored, not passing evidence.

**Next contiguous batch: R136-R140.**
