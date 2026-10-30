# GA R511–R520 — data-loss staging and evasion-tunnel evidence boundaries

**SOURCE CANDIDATE — UNVERIFIED · 2026-10-30.** Existing branch: `feature/carthago-reliability-hardening`. Inspected live base HEAD `0e03f6975501c4cad08d13b21968b5f2bf245f32` (UI-16 and prior R501–R510 already present). Source commit `234011f1e7cad94932b7f9f5b82c7b3000c75c5e`; authored-test commit `fec253da34e2c17dc9aaaa80d518de7bfddcb789`. The final atomic publication SHA is the resulting documentation-descendant branch HEAD; a commit cannot embed its own SHA. **250 xUnit invocations AUTHORED, 0 EXECUTED.** No build, test, replay, holdout, CI, runner, benchmark or production capture was executed.

## Evidence-first review and ten-rule dispositions

[TrafficRecord](../Carthago/Models/TrafficRecord.cs) contains packet/flow, process-name enrichment, bounded HTTP request metadata, SSH fingerprint/banner-derived fields, QUIC version/optional ALPN and DNS fields. [PacketHandler](../Carthago/Services/PacketHandler.cs) recognizes some SSH banners and QUIC long headers but does not observe SSH forwarding arguments or socket listeners, authenticate tunnel-agent sessions, decode HTTP/3 CONNECT-UDP, decrypt QUIC application data, or provide approved resolver/agent inventory. QUIC version is not proof of DoQ; a client-controlled URI, SNI, Info or HTTP header is not trusted audit. ProcessName is not attested command-line execution. No connected producer correlates database export to file creation and outbound upload or authenticates personal-email delivery.

| Original rule | Required evidence / stable missing-producer reason | Original default (severity; mode; floor; threshold; window; cooldown) | Disposition / legitimate-traffic risk |
| --- | --- | --- | --- |
| R511 DB Client Export Then HTTP Upload | `DB_EXPORT_PROCESS_FILE_AND_UPLOAD_CORRELATION_UNAVAILABLE` — Trusted DB-client export/file provenance + completed correlated HTTP upload | Critical; Alert; 84%; 1; 20m; 35m | **BLOCKED** — Approved database backups, ETL, ticket attachments |
| R512 Sensitive Filename To Personal Email | `SENSITIVE_FILE_PERSONAL_EMAIL_DELIVERY_PROVENANCE_UNAVAILABLE` — Privacy-safe file classification + authenticated recipient and mail-delivery audit | Critical; Alert; 84%; 1; 20m; 35m | **BLOCKED** — Personal mail use, approved support and DLP exercises |
| R513 SSH Dynamic SOCKS Proxy Use | `SSH_DYNAMIC_FORWARD_COMMAND_AND_SOCKET_PROVENANCE_UNAVAILABLE` — Trusted SSH -D command, local SOCKS listener and session correlation | High; Alert; 84%; 1; 20m; 35m | **BLOCKED** — Approved SSH administration and developer forwarding |
| R514 Chisel Tunnel Handshake | `CHISEL_AUTHENTICATED_HANDSHAKE_PROVENANCE_UNAVAILABLE` — Authenticated Chisel agent handshake and session identity | High; Alert; 84%; 1; 20m; 35m | **BLOCKED** — Authorized lab, red-team and remote-support tunnels |
| R515 FRP Tunnel Handshake | `FRP_AUTHENTICATED_HANDSHAKE_PROVENANCE_UNAVAILABLE` — Authenticated frpc/frps registration and tunnel identity | High; Alert; 84%; 1; 20m; 35m | **BLOCKED** — Managed FRP infrastructure and developer access |
| R516 Cloudflared Tunnel Handshake | `CLOUDFLARED_TUNNEL_SESSION_PROVENANCE_UNAVAILABLE` — Authenticated Cloudflare Tunnel connector identity and session outcome | High; Alert; 84%; 1; 20m; 35m | **BLOCKED** — Approved Zero Trust connectors and production tunnels |
| R517 Ngrok Tunnel Handshake V2 | `NGROK_AGENT_TUNNEL_SESSION_PROVENANCE_UNAVAILABLE` — Authenticated ngrok agent v2 session/handshake | High; Alert; 84%; 1; 20m; 35m | **BLOCKED** — Authorized demos, webhooks and development endpoints |
| R518 Reverse SSH Tunnel Pattern | `SSH_REVERSE_FORWARD_COMMAND_AND_LISTENER_PROVENANCE_UNAVAILABLE` — Trusted SSH -R command and remote listener/session association | High; Alert; 84%; 1; 20m; 35m | **BLOCKED** — Approved reverse administration and support |
| R519 DNS Over QUIC Unapproved Resolver | `DOQ_ALPN_RESOLVER_IDENTITY_AND_APPROVAL_UNAVAILABLE` — Observed DoQ ALPN doq, resolver identity and trusted approval policy | High; Alert; 84%; 1; 20m; 35m | **BLOCKED** — Enterprise secure DNS, approved DoQ clients |
| R520 MASQUE CONNECT UDP Proxy Use | `MASQUE_CONNECT_UDP_HTTP3_SESSION_PROVENANCE_UNAVAILABLE` — Decoded HTTP/3 extended CONNECT-UDP and correlated proxy response | Medium; Alert; 84%; 1; 20m; 35m | **BLOCKED** — Managed privacy proxies, VPN and enterprise MASQUE |

**All ten BLOCKED for their named behavior:** the currently connected producers cannot establish the required positive predicates. Generic traffic hints can support investigation but not these specific 84%-floor operational alerts. This is not a validated false-positive or recall result; it is an evidence-reachability decision.

## Source scope, original contracts and divergence review

- Added [DataLossStagingEvidenceBoundary](../Carthago/Engine/Rules/Expansion/DataLossStagingEvidenceBoundary.cs) for R511–R512 and [EvasionTunnelEvidenceBoundary](../Carthago/Engine/Rules/Expansion/EvasionTunnelEvidenceBoundary.cs) for R513–R520. Both are stateless, constant-reason, fail-closed contracts; no payload capture, credentials, flags or shared APIs were added.
- Updated the [existing shared evaluator](../Carthago/Engine/Rules/Expansion/EvidenceDrivenPrecisionRuleBase.cs) to check these boundaries **after core telemetry validation but before RequireHttp/RequireDns, generic scoring, threshold windows, cooldown state or event construction**. The early guard intentionally avoids false positive alerts from spoofed network hints. It does not imply a future trusted producer can be enabled by setting a text field.
- Authored [NetworkBatch511520AccuracyTests](../Carthago.Tests/NetworkBatch511520AccuracyTests.cs); **UNEXECUTED**. Documentation is this batch and [progress ledger](RULE_HARDENING_PROGRESS.md). No UI, capture, service, model, runner, workflow, prior rule or shared schema files changed.
- All ten existing rules remain **Alert**, minimum confidence **84%**, threshold **1**, observation window **20 minutes**, cooldown **35 minutes**, original severities, RequiredTelemetry, RequiredFields, ports, HTTP/DNS applicability, boundary flags, approvals, baseline and privacy policies. No threshold was lowered; R511 retains 5 MiB packet minimum and R520 retains RequireHttp. No operational positives are claimed.
- **Original contract mismatches remain documented, not migrated:** R511's HTTP/5 MiB packet requirement does not prove a database export or completed upload. R513/R518 include generic HTTP/DNS clues despite SSH forwarding being encrypted and configuration-dependent. R519 requires DNS context even though DoQ DNS messages are carried within encrypted QUIC streams; its ports include UDP/53 although RFC 9250 prohibits DoQ on that port. R520's HTTP request metadata is not an HTTP/3 extended CONNECT-UDP decoder. R516's port 7844/443 and R517's provider hostname are not authenticated tunnel sessions.
- **Pre-change review:** R501–R510 was the latest completed source-only batch, all ten original R511–R520 classes existed, no R511–R520 missing-producer contract or authored batch tests existed, and UI-16 changed only UI/design paths. **Pre-publication review:** compare owned paths and unchanged profiles against the live branch, recheck the remote SHA, and use one non-forced expected-HEAD update; no source-only review establishes compilation or correctness.

## Exact authored scenario inventory — 0 executed

A parameterized xUnit theory enumerates **24 distinct cases per rule**, with assertions for no alert and the rule's exact missing-producer code except the two missing-core-telemetry variants. A second theory enumerates one original Alert-mode/profile invariant per rule. All fixtures use deterministic documentation-range addresses and synthetic placeholders, never real credentials or live captures.

| ID | Scenario | Intended evidence boundary |
| --- | --- | --- |
| 01 | `plausible` | Rule-specific network clue without authenticated outcome |
| 02 | `descriptor-spoof` | Rule ID and verified-success words inserted into Info |
| 03 | `approved-admin` | Authorized maintenance, backup and developer traffic |
| 04 | `forged-audit` | Spoofed tunnel, upload and resolver-approval HTTP headers |
| 05 | `tls-only` | Encrypted TLS observation without decoded request |
| 06 | `missing-source` | Missing source must return MISSING_CORE_TELEMETRY |
| 07 | `missing-destination` | Missing destination and host must return MISSING_CORE_TELEMETRY |
| 08 | `malformed-target` | Malformed URL escaping, truncated byte counts |
| 09 | `synthetic-secret` | Redacted credential placeholders, no real secrets |
| 10 | `inbound` | Reverse network direction cannot manufacture evidence |
| 11 | `wrong-protocol` | TCP/UDP classification mismatch |
| 12 | `threshold-burst` | Six distinct observations cannot create producer evidence |
| 13 | `claimed-success` | Fabricated HTTP 201 / tunnel-established Info |
| 14 | `duplicate-id` | Repeated identical record ID cannot create proof |
| 15 | `spoofed-process` | Forged trusted process and agent labels |
| 16 | `ssh-banner-only` | SSH banner/fingerprint and claimed -D/-R arguments |
| 17 | `quic-version-only` | QUIC version with no verified DoQ ALPN |
| 18 | `after-cooldown` | Repeat across 40-minute cooldown remains insufficient |
| 19 | `provider-lookalike` | Lookalike ngrok/Cloudflare/FRP host |
| 20 | `request-only` | HTTP CONNECT without correlated response |
| 21 | `response-only` | HTTP 200 text without correlated request |
| 22 | `fake-masque` | Spoofed :protocol connect-udp and Capsule header |
| 23 | `out-of-order` | Out-of-order event timestamps without trust producer |
| 24 | `sensitive-uri` | Synthetic filename/recipient in untrusted request URI |
| 25 | `OriginalProfiles` | One invariant per rule: Alert, 84% floor, threshold 1, 20m window, 35m cooldown |

**Concrete invocations:** 24 × 10 = 240 adversarial/benign/boundary cases + 10 profile invariants = **250 AUTHORED; 0 EXECUTED**. No trustworthy positive is representable with current producers; a future integration must author positive/benign paired evidence with provenance, authorization, malformed/out-of-order, threshold/cooldown and privacy controls before changing a disposition.

## Open quality GAs and integration proposals

1. **GA local staging/mail provenance:** bounded signed endpoint file/process event correlator, DB export transaction and completed HTTP upload; for R512, privacy-preserving sensitive-file classification, authenticated personal-mail recipient policy and delivery outcome. Do not retain raw file paths, mail content or credentials by default.
2. **GA SSH/agent provenance:** trusted SSH command/socket listener correlation for dynamic -D versus reverse -R forwarding; signed Chisel/FRP/cloudflared/ngrok agent/session identity, authorization and handshake outcome. No assertion from banner, process name or port alone.
3. **GA DoQ/MASQUE:** verified DoQ ALPN `doq` and approved resolver inventory; protocol-aware HTTP/3 extended CONNECT-UDP request/response correlation for MASQUE, without assuming passive HTTPS/QUIC decryption. Prefer explicit trusted endpoint telemetry if decryption is unavailable.
4. **GA privacy and validation:** inspect HTTP URI/header token retention separately; verify synthetic redaction, consent, resource bounds and approved-source policy. Windows compilation, 250 authored xUnit invocations, replay/holdout, field precision/recall and runtime reliability remain **NOT EXECUTED / NOT MEASURED**. Historical 4,940/4,940 predates this candidate. Frozen R102 V1 FAILED 4/6, V2 0/4 approved external sources, and R343/R295/R275/R163 replay obligations are independent.

**Next consecutive detection GA: R521–R530**, whose ten original classes were observed in the live tree. The UI automation is independent and untouched.

## Authoritative technical references

- [RFC 9250 §4.1 — DoQ ALPN `doq`, dedicated UDP/853 and no UDP/53](https://www.rfc-editor.org/rfc/rfc9250#section-4.1).
- [RFC 9298 §3.4–3.5 — HTTP/2 and HTTP/3 CONNECT-UDP and response requirements](https://www.rfc-editor.org/rfc/rfc9298#section-3.4).
- [OpenSSH ssh(1) manual — dynamic `-D` and remote `-R` forwarding](https://man.openbsd.org/ssh).
- [Microsoft — C# naming conventions](https://learn.microsoft.com/en-us/dotnet/csharp/fundamentals/coding-style/identifier-names).
