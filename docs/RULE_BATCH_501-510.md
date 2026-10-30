# GA R501–R510 — outbound data-loss and provider upload provenance

**SOURCE CANDIDATE — UNVERIFIED · 2026-10-30.** Branch: `feature/carthago-reliability-hardening`. Inspected live base HEAD `fd8d2e3d11bfefa9f076f6f86607231ebadee235`. Source commit \`adb218809c7a23d058e04ea4c1d584ba1426a4ea\`; authored-test commit \`539346a00e9b1449ebe7d9d915cdd48eb3995fae\`; final atomic publication is the documentation-descendant remote branch HEAD (a commit cannot embed its own SHA). **230 concrete xUnit invocations AUTHORED, 0 EXECUTED.** No build, test, replay, holdout, CI, runner, benchmark or production capture.

## Evidence-first review and ten-rule dispositions

The live [TrafficRecord](../Carthago/Models/TrafficRecord.cs) contains packet/flow, process-name, HTTP request-line/header, TLS and host metadata, not a trustworthy upload-body identity, multipart part filename, complete transfer byte count, correlated response, local process execution attestation or approved endpoint inventory. The existing [HTTP parser](../Carthago/Services/PacketHandler.cs) reads a bounded request line and headers; it does **not** parse multipart body parts, validate data-URI body content, or establish provider upload success. It retains some HTTP request-target and non-sensitive header text: privacy of those fields remains a separate review. TLS payloads are not decrypted. `Length`/`L4Len` are packet-local measurements, not a verified completed upload volume. Client User-Agent, process labels, URI strings, `Info` and forged audit headers are not authenticated evidence.

| Rule / original name | Missing producer or predicate | Original Alert profile (severity; floor; threshold; window; cooldown; min bytes) | Disposition / legitimate-traffic false-positive risk |
| --- | --- | --- | --- |
| R501 Multipart Form Data High Entropy Filename | `MULTIPART_PART_FILENAME_ENTROPY_AND_UPLOAD_CORRELATION_UNAVAILABLE` — HTTP request headers do not contain multipart part filenames; no bounded, privacy-safe multipart part parser, filename entropy classification, body association or upload outcome is connected. | High; 84%; 4; 10m; 35m; 524288 B | **BLOCKED** · Ticket attachments, approved DLP drills and application form uploads |
| R502 Data URI Base64 POST Large | `DATA_URI_REQUEST_BODY_AND_UPLOAD_VOLUME_UNAVAILABLE` — An HTTP request target mentioning data: or base64 is not an observed POST body; no bounded data-URI body classifier or correlated transmitted byte count is available. | High; 84%; 1; 20m; 35m; 5242880 B | **BLOCKED** · Browser form submissions, data-URI tests and authorized API clients |
| R503 Pastebin Raw POST Bulk | `PASTEBIN_POST_RESPONSE_AND_DISTINCT_BULK_UNAVAILABLE` — Paste service host/path and POST method do not establish distinct completed raw posts, correlated responses, or calibrated bulk upload behavior. | High; 84%; 4; 10m; 35m; 5242880 B | **BLOCKED** · Authorized paste-service sharing, support workflows and test automation |
| R504 GitHub Gist Secret Post | `GIST_SECRET_CONTENT_AND_CREATE_OUTCOME_UNAVAILABLE` — GitHub host and Gist API request shape cannot establish that secret content was sent, that a Gist was created, or that a sensitive file was exposed. | Critical; 84%; 1; 20m; 35m; 524288 B | **BLOCKED** · Approved developer snippets, incident reproduction and credential-redaction tests |
| R505 Discord Attachment Upload Burst | `DISCORD_ATTACHMENT_UPLOAD_AND_BURST_CORRELATION_UNAVAILABLE` — Discord host, CDN retrieval and HTTP request labels do not prove distinct attachment upload operations, message outcomes, or a calibrated burst. | High; 84%; 4; 10m; 35m; 5242880 B | **BLOCKED** · Team attachments, bot integrations and approved support uploads |
| R506 Telegram Document Exfil Burst | `TELEGRAM_DOCUMENT_UPLOAD_AND_BURST_CORRELATION_UNAVAILABLE` — Telegram API host, bot method text or encrypted traffic cannot attest sendDocument content, upload outcomes, or distinct document burst events. | High; 84%; 4; 10m; 35m; 5242880 B | **BLOCKED** · Authorized bot document delivery and monitoring notifications |
| R507 Mega NZ Upload Pattern | `MEGA_UPLOAD_TRANSACTION_AND_OUTCOME_UNAVAILABLE` — MEGA hostnames and HTTP method/packet sizes do not identify a completed upload transaction or distinguish approved synchronization. | High; 84%; 1; 20m; 35m; 5242880 B | **BLOCKED** · Approved MEGA backup, file synchronization and migration |
| R508 Rclone UserAgent Egress | `RCLONE_PROCESS_USERAGENT_AND_EGRESS_PROVENANCE_UNAVAILABLE` — A client-supplied User-Agent and process-name enrichment do not authenticate rclone execution or correlate an outbound file transfer; a UA match alone is not exfiltration. | High; 84%; 1; 20m; 35m; 0 B | **BLOCKED** · Approved rclone backup, cloud migration and scripted synchronization |
| R509 Rsync External Push | `RSYNC_PUSH_DIRECTION_AND_REMOTE_OUTCOME_UNAVAILABLE` — TCP/873, SSH/22, rsync process text or CONNECT cannot establish native rsync sender/receiver direction, remote file write, or completed external push. | High; 84%; 1; 20m; 35m; 0 B | **BLOCKED** · Approved rsync backups, deployments and remote administration |
| R510 S3 Compatible Unknown Endpoint Upload | `S3_COMPATIBLE_ENDPOINT_IDENTITY_AND_UPLOAD_OUTCOME_UNAVAILABLE` — An S3-looking hostname, SigV4-shaped request or generic PUT does not establish an unknown/unapproved endpoint, authenticated object write, or correlated response. | High; 84%; 1; 20m; 35m; 5242880 B | **BLOCKED** · Approved S3-compatible object stores, backups and internal gateways |

**All ten BLOCKED:** current telemetry cannot supply a validated positive for the exact claimed behaviors. A generic request or tool name may still be a useful *investigation clue*, but cannot justify these specific 84%-floor alerts. No new telemetry producer, body capture, credential retention, severity change or speculative detection was introduced. R508 specifically describes a User-Agent indicator, but a client-supplied `rclone` UA does not authenticate process execution or a completed file transfer; its original 84% confidence contract cannot be justified as an operational exfiltration alert by this source alone.

## Source scope and pre/post divergence review

- Added [DataLossUploadEvidenceBoundary](../Carthago/Engine/Rules/Expansion/DataLossUploadEvidenceBoundary.cs) with ten explicit, stable missing-producer reason codes and no state, allocations per packet beyond the returned constant strings, new event fields or payload retention.
- Updated only the [existing shared evaluator](../Carthago/Engine/Rules/Expansion/EvidenceDrivenPrecisionRuleBase.cs) to return `InsufficientEvidence` after core telemetry validation but before `RequireHttp`, generic signal scoring, burst windows, cooldowns or event construction. Existing rule classes, public IDs and profiles are untouched.
- Added [NetworkBatch501510AccuracyTests](../Carthago.Tests/NetworkBatch501510AccuracyTests.cs), authored but **UNEXECUTED**. Updated this document and the [progress ledger](RULE_HARDENING_PROGRESS.md). UI-owned paths, workflows, services, models, shared APIs and all other detection batches unchanged.
- Original Alert modes, all severities, **84%** confidence floors, thresholds (R501/R503/R505/R506=4, other six=1), windows (10m for four burst rules, 20m otherwise), 35m cooldowns, 0/512 KiB/5 MiB packet minimums, approvals, journal, baseline readiness, R102/R118/R163 floors and frozen evidence remain unchanged.
- Existing specification mismatches are **documented, not silently migrated**: R501's `filename=` lives in multipart part headers rather than ordinary HTTP headers; R506 has no HTTP requirement despite its document-upload name; R508/R509 use generic process/UA text, and R509 includes `CONNECT` despite native rsync/SSH semantics; R510's known S3 provider hosts cannot establish that an endpoint is unknown or unapproved. Several 5 MiB thresholds can miss smaller sensitive transfers; no threshold was lowered.
- Pre-change divergence: R491–R500 is the latest published batch, ten R501–R510 rule classes exist, and no R501–R510 boundary or batch test existed at the inspected live base. Pre-publication static review checks only owned paths, unchanged profiles and privacy, and an expected-HEAD non-forced update; it is **not** compilation or execution evidence.

## Exact authored scenario inventory (0 executed)

`[Theory]` / `[MemberData]` enumerates **22 distinct cases per rule**, all requiring no alert and the exact missing-producer reason (except missing-core-telemetry variants). Each scenario uses deterministic synthetic `TrafficRecord` fields, never real credentials, cloud content or actual production traffic.

| Scenario ID | Scenario / intended assertion |
| --- | --- |
| 01 | `plausible` — plausible rule-specific host, method and request path without authenticated outcome |
| 02 | `descriptor-spoof` — spoofed rule ID and exfiltration claim in Info |
| 03 | `approved-workflow` — authorized backup/helpdesk/developer workflow |
| 04 | `forged-audit` — forged upload/agent/object-write audit headers |
| 05 | `tls-only` — TLS-only flow without decrypted HTTP request |
| 06 | `missing-source` — absent source, expect MISSING_CORE_TELEMETRY |
| 07 | `missing-destination` — absent destination/host, expect MISSING_CORE_TELEMETRY |
| 08 | `malformed-target` — malformed percent-encoded target and truncated bytes |
| 09 | `synthetic-secret` — synthetic redacted credential placeholder; no real secret |
| 10 | `inbound` — inbound direction instead of outbound |
| 11 | `wrong-protocol` — UDP misclassification despite HTTP-like labels |
| 12 | `threshold-burst` — six distinct repeated observations cannot fill evidence gap |
| 13 | `claimed-success` — fabricated HTTP success and upload claim |
| 14 | `duplicate-id` — duplicate record identity cannot manufacture provenance |
| 15 | `spoofed-process` — spoofed trusted rclone/process identity |
| 16 | `truncated-body` — truncated packet and multipart header claim |
| 17 | `after-cooldown` — observations across cooldown do not create alert |
| 18 | `provider-lookalike` — provider-lookalike host spoofing |
| 19 | `request-only` — request-only operation without correlated response |
| 20 | `response-only` — response-only label without correlated request |
| 21 | `multipart-header-only` — multipart content-type/part header text without parsed body |
| 22 | `oversized-packet` — large packet Length does not prove upload volume |
| 23 | `OriginalProfiles` — per-rule Alert mode, confidence, threshold, window and cooldown invariant |

**Concrete invocations:** 22 × 10 = 220 evidence-boundary cases, plus 10 profile invariants = **230**. Two xUnit theory methods; no assertion has been executed. Positive operational tests are **not representable** without trustworthy producers; future producer integration must add positive, benign, malformed, privacy, duplicate/out-of-order, threshold/cooldown and response-correlation tests before unblocking.

## Quality GAs and integration proposals

1. **GA producer contracts:** privacy-preserving bounded multipart part metadata (not filenames or content by default), request-body data-URI classification without retaining bytes, authenticated provider API/agent outcomes and distinct transfer identities; correlation must be direction-aware and replay-deterministic. No HTTPS decryption is implied.
2. **GA trusted endpoint/process provenance:** validated local rclone/rsync process identity and transfer direction, approved cloud/service inventory, signed agent audit for S3-compatible writes and response correlation. Explicitly distinguish observed request from completed transfer.
3. **GA privacy:** audit `HttpUri` and non-sensitive retained header values for secret-bearing query strings and attacker-controlled header content; design minimal redaction and tests without logging raw tokens. Do not change shared capture code as part of this batch.
4. **GA validation:** Windows compilation, 230 authored scenarios, realistic positive/benign paired cases when producers exist, field precision/recall, memory/capture footprint and long-running reliability remain **NOT EXECUTED / NOT MEASURED**. Historical 4,940/4,940 predates this candidate; R102 V1 FAILED 4/6, V2 0/4 approved sources and R343/R295/R275/R163 replay obligations remain separate.

**Next consecutive detection GA: R511–R520**, conditional on fresh live HEAD/source/ledger inspection. The independent UI GA is untouched.

## Protocol/vendor references

- [RFC 7578 §4.2 — multipart Content-Disposition in each body part](https://www.rfc-editor.org/rfc/rfc7578#section-4.2).
- [RFC 2397 — data URL scheme](https://www.rfc-editor.org/rfc/rfc2397).
- [GitHub REST — Gists creation and responses](https://docs.github.com/en/rest/gists/gists#create-a-gist).
- [Discord developer reference — file uploads](https://discord.com/developers/docs/reference#uploading-files).
- [Telegram Bot API — sendDocument](https://core.telegram.org/bots/api#senddocument).
- [Amazon S3 — PutObject API](https://docs.aws.amazon.com/AmazonS3/latest/API/API_PutObject.html).
- [rclone official documentation](https://rclone.org/docs/) and [rsync manual](https://download.samba.org/pub/rsync/rsync.1).
