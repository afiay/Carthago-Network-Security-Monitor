# GA R371–R380 — AWS and supply-chain provenance

**SOURCE CANDIDATE — UNVERIFIED · 2026-10-30.** Branch:
`feature/carthago-reliability-hardening`. Base HEAD after the author-only
history rewrite: `4dd73f3f6de2c0c6b9a6fd299d0c306ebcc3a9cc`.
Unpublished source candidate `9042faabf0edb93bb8a196f58e585cca24f34760`;
authored-test candidate `29ad9d1c84975e217178914b498daa443260a890`.
Publication is the descendant documentation commit referenced by the live
feature branch after an expected-HEAD non-forced update. Historical SHA
references in older GAs belong to the pre-rewrite lineage.

## Evidence and rule dispositions

The only existing applicable producer is
[`PacketHandler`](../Carthago/Services/PacketHandler.cs) calling the bounded
`HttpLight.TryParseHttp` for **visible cleartext TCP HTTP requests**.
[`TrafficRecord`](../Carthago/Models/TrafficRecord.cs) contains HTTP method,
origin-form target and client-supplied Host; it does **not** provide
authenticated AWS audit, decrypted TLS, validated authorization, request-body
AWS action decoding, server responses, request/response byte correlation,
private package namespace inventory or authenticated GuardDuty findings.
Do not upgrade a synthetic fixture or Info text to independent evidence.

| ID / existing rule | Producer and required evidence | Disposition / supported behavior | Original profile: mode, severity, confidence; threshold / window / cooldown | False-positive / blind spot |
| --- | --- | --- | --- | --- |
| R371 Maven Repository Credential Use | HTTP Host/path exists, but no parser-owned credential-use attestation | **BLOCKED**; no claimed credential use | Alert, High, 78; 1 / 20m / 20m | Ordinary CI package fetch/deploy; no credential proof |
| R372 Dependency Confusion Package Name Pattern | No private namespace allowlist, trusted package resolution or registry provenance | **BLOCKED**; package name alone cannot establish confusion | Alert, Medium, 74; 2 / 30m / 20m | Public package collisions and legitimate scoped packages |
| R373 AWS STS AssumeRole Burst | AWS Query API action is in request body or authenticated CloudTrail; neither available | **BLOCKED**; no fabricated AssumeRole operation | Alert, High, 82; 4 / 10m / 30m | Normal CI role assumption; TLS opaque |
| R374 AWS IAM AccessKey In URL | No safe parser-owned query classification/redaction for this rule | **BLOCKED**; raw key-shaped URL must not be emitted | Alert, Critical, 82; 1 / 15m / 30m | Presigned URLs, public examples, accidental sensitive retention |
| R375 AWS S3 ListBuckets External | Cleartext GET exactly `/`, Host exactly `s3.amazonaws.com`, original cross-boundary gate | **CONDITIONAL** — ListBuckets **request shape only**, not authorized access or bucket inventory | Alert, Medium, 82; 1 / 15m / 30m | Routine inventory; paginated/regional queries deliberately excluded; spoofed Host |
| R376 AWS S3 GetObject Bulk Download | No request-to-response object byte correlation or completed transfer evidence | **BLOCKED**; packet byte length cannot prove bulk GetObject | Alert, High, 82; 4 / 10m / 30m | Backups, distribution, cache; TLS opaque |
| R377 AWS EC2 UserData Metadata Probe | Link-local metadata request is representable in cleartext, but original cross-boundary gate conflicts with link-local traffic | **BLOCKED** pending explicit boundary-contract GA; no silent gate relaxation | Alert, Critical, 82; 1 / 15m / 30m | EC2 boot agents legitimately fetch user-data |
| R378 AWS Lambda Invoke Burst | Cleartext POST, regional `lambda.<region>.amazonaws.com` Host and exact `/2015-03-31/functions/<name>/invocations`; distinct record IDs, monotonic time, original cross-boundary gate | **CONDITIONAL** — four **request shapes** in 10m, not executed Lambda invocations | Alert, Medium, 82; 4 / 10m / 30m | CI/deploy/retries; query Qualifier, encoded ARN and alternate endpoints excluded |
| R379 AWS CloudTrail StopLogging Indicator | No authenticated CloudTrail event outcome or complete API action producer | **BLOCKED**; generic CloudTrail vocabulary is not StopLogging | Alert, Critical, 82; 1 / 15m / 30m | Authorized trail maintenance; failed requests |
| R380 AWS GuardDuty Finding Exfil Indicator | No trusted GuardDuty finding ID/type/identity or audit ingestion | **BLOCKED**; no finding/exfiltration claim | Alert, High, 82; 1 / 15m / 30m | Simulated reports, security dashboards, unrelated API calls |

**All ten existing severities, thresholds, confidence floors, runtime modes,
windows, cooldowns, approvals and configuration keys remain unchanged.**
The two eligible rules use existing `EvaluateSpec` for profile enforcement;
R375/R378 discard broad generic AWS/process/token indicators before scoring.
R375 now requires HTTP explicitly. No rule infers a successful AWS operation,
authorization, download, credential validity, or security incident.

## Source changes and safety boundary

- Ten existing rule classes:
  [R371](../Carthago/Engine/Rules/Expansion/R371_MavenRepositoryCredentialUseRule.cs),
  [R372](../Carthago/Engine/Rules/Expansion/R372_DependencyConfusionPackageNamePatternRule.cs),
  [R373](../Carthago/Engine/Rules/Expansion/R373_AWSSTSAssumeRoleBurstRule.cs),
  [R374](../Carthago/Engine/Rules/Expansion/R374_AWSIAMAccessKeyInURLRule.cs),
  [R375](../Carthago/Engine/Rules/Expansion/R375_AWSS3ListBucketsExternalRule.cs),
  [R376](../Carthago/Engine/Rules/Expansion/R376_AWSS3GetObjectBulkDownloadRule.cs),
  [R377](../Carthago/Engine/Rules/Expansion/R377_AWSEC2UserDataMetadataProbeRule.cs),
  [R378](../Carthago/Engine/Rules/Expansion/R378_AWSLambdaInvokeBurstRule.cs),
  [R379](../Carthago/Engine/Rules/Expansion/R379_AWSCloudTrailStopLoggingIndicatorRule.cs),
  [R380](../Carthago/Engine/Rules/Expansion/R380_AWSGuardDutyFindingExfilIndicatorRule.cs).
- New [`CloudRequestPrecisionEvidence`](../Carthago/Engine/Rules/Expansion/CloudRequestPrecisionEvidence.cs)
  reuses [`DevOpsHttpEvidence`](../Carthago/Engine/Rules/Expansion/DevOpsHttpEvidence.cs)
  origin-form, cleartext and Host checks. Non-origin targets, encoded paths,
  ambiguous escapes and **all query strings** fail closed. This deliberately
  excludes signed requests and legitimate pagination/Qualifier query variants.
- Reuses bounded packet-ID, per-source/destination/Host duplicate and
  out-of-order protection from
  [`DevOpsRequestPrecisionEvidence`](../Carthago/Engine/Rules/Expansion/DevOpsRequestPrecisionEvidence.cs)
  for R378. This is packet-ID uniqueness, **not** HTTP transaction dedup.
  Existing four-in-ten-minute scoring remains in the original precision base.
- Extends [`CloudDevPrecisionDetectionRuleBase`](../Carthago/Engine/Rules/Expansion/CloudDevPrecisionDetectionRuleBase.cs)
  event `http.path` redaction to R371–R380, avoiding propagation of resource
  identifiers or sensitive request targets through this event evidence field.
  This does **not** assert that all upstream packet/Info/diagnostic paths are
  free of secrets; further capture-path privacy review is required.
- No WPF/UI, runner, CI workflow, holdout, settings, journal, approval or
  frozen evidence files changed. No new external dependencies.

## Authored scenario inventory — NOT EXECUTED

Source: [`NetworkBatch371380AccuracyTests.cs`](../Carthago.Tests/NetworkBatch371380AccuracyTests.cs).
Counts are concrete xUnit invocations (including theory data rows), not test
results.

| Rule | Authored invocations | Exact scenarios |
| --- | ---: | --- |
| R371 | 7 | plausible Maven fetch; descriptor spoof; TLS-only; wrong host; missing source; token-query privacy; profile invariants |
| R372 | 7 | plausible public registry package; fake private-namespace claim; TLS-only; wrong host; missing source; token-query privacy; profile |
| R373 | 7 | STS query-shaped request; fabricated successful audit; TLS-only; wrong host; missing source; token-query privacy; profile |
| R374 | 7 | key-shaped URL; fabricated confirmed leak; TLS-only; wrong host; missing source; token-query privacy; profile |
| R375 | 11 | exact GET / request; ListObjectsV2 query; bucket path; spoofed Host; TLS-only; missing method; UDP contradiction; absolute target; signed query; Info spoof; profile |
| R376 | 7 | GetObject-shaped request; fabricated transfer success; TLS-only; wrong host; missing source; token-query privacy; profile |
| R377 | 7 | link-local user-data path; fabricated compromise; TLS-only; wrong host; missing source; token-query privacy; profile |
| R378 | 11 | 3-below/4th-at-threshold; duplicate ID; out-of-order replay; wrong method; wrong route; spoofed Host; TLS-only; signed query; absolute URL; UDP; profile |
| R379 | 7 | CloudTrail-shaped request; fabricated StopLogging success; TLS-only; wrong host; missing source; token-query privacy; profile |
| R380 | 7 | GuardDuty-shaped request; fabricated exfil finding; TLS-only; wrong host; missing source; token-query privacy; profile |
| **Total** | **78** | **78 AUTHORED, 0 EXECUTED** |

No `dotnet build`, `dotnet test`, xUnit, replay, holdout, benchmark, GitHub
Actions, Windows runner or live capture was executed for this GA. The prior
4,940/4,940 full xUnit checkpoint **predates** these source changes. No
compile/test/accuracy/certification/field success is claimed.

## Static divergence review and outstanding quality GAs

Pre-change: live rewritten HEAD and R361–R370 ledger checked; all ten R371–R380
classes existed as generic rule shells; parser produces HTTP request fields,
not cloud audit. The source candidate changes only detection-owned files and
authored tests; no duplicate parser, public API rename, new credential
retention or policy threshold change. Final static review must recheck live
HEAD and changed paths before publication.

1. **GA build/test:** owner-authorized pinned-SHA Windows build and full xUnit,
   including these 78 invocations, plus packet-level cleartext producer tests.
2. **GA HTTP provenance:** client-to-server request attribution, retransmission
   dedup, time-window expiration, bounded-state eviction and source/IP spoof
   robustness; synthetic record tests are not capture proof.
3. **GA AWS audit:** trusted CloudTrail/GuardDuty ingest, IAM identities,
   operation success/error and request/response attribution; signed HTTPS is
   opaque to current packet capture.
4. **GA metadata:** review R377 link-local boundary and EC2 user-data privacy
   with an explicitly approved contract change, not a silent policy bypass.
5. **GA precision:** legitimate S3 inventory and Lambda CI bursts require
   allowlist/behavioral baselines, field precision/recall and cooldown review.
6. **Independent existing GAs:** R343/R295/R275/R163 replay expectations;
   frozen R102 V1 FAILED 4/6, V2 0/4 independently approved external
   sources. Preserve floors R102 80%, R118 86%, R163 84%, external R102 0.75.

**Next sequential source-development batch after publication: R381–R390.**

## Authoritative protocol references

- [AWS S3 ListBuckets API](https://docs.aws.amazon.com/AmazonS3/latest/API/API_ListBuckets.html)
  — GET root, paginated query variants and permission requirement.
- [AWS Lambda Invoke API](https://docs.aws.amazon.com/lambda/latest/api/API_Invoke.html)
  — POST function invocation route, optional Qualifier and response semantics.
- [AWS STS AssumeRole API](https://docs.aws.amazon.com/STS/latest/APIReference/API_AssumeRole.html)
  — action parameters are not inferred from an unrelated Host header.
- [AWS CloudTrail StopLogging API](https://docs.aws.amazon.com/awscloudtrail/latest/APIReference/API_StopLogging.html)
  — request does not establish a successful stop.
- [AWS GuardDuty findings](https://docs.aws.amazon.com/guardduty/latest/ug/guardduty_findings.html)
  — findings require trusted provenance.
- [Carthago GA documentation contract](rules/RULE_DOCUMENTATION_STANDARD.md).
