# R118 and R163: evidence contracts and replay matrix

Status (26 October 2026): **92 labeled replay fixtures (49 benign, 43 malicious); promotion HOLD**.
The last supplied Windows verification covers the **80-fixture** revision:
958/958 xUnit tests passed and its replay benchmark completed with no benign
simulated alerts. This is a historical baseline only. The subsequent 84-, 88-,
and current 92-fixture revisions have **not** been verified by a Windows build,
xUnit run, or replay benchmark in this environment. Four new 92-fixture controls
were independently JSON-parsed and committed, but their detector expectations
remain unexecuted. No updated precision, recall, or F1 values are claimed.
R118, R163 and R102 promotion remains blocked pending fresh evidence.

## Non-negotiable gates

| Rule | Minimum confidence | What is currently observed | What must not be inferred |
| --- | ---: | --- | --- |
| R118 | 86% | Wire-derived HTTP Basic default-pair indicator, or a recognizable Telnet login transcript, with IoT target context | Successful authentication, unauthorized access, or consent status from the credential pair alone |
| R163 | 84% | Provider-validated metadata socket IP, Host authority, credential path, method and process context | SSRF causality from a metadata request, an IMDSv2 token header, an inbound URL parameter, or temporal proximity alone |
| R102 | 80% | DNS tunneling candidate with baseline and independent precision requirements | Alert promotion from a raw match without the existing baseline/precision gates |

**Do not lower confidence floors or change rule modes to improve recall.**
A replay may be malicious by scenario label while a detector correctly emits
only a Shadow match because the evidence does not meet the alert standard.

## Newly added labeled fixtures

| Fixture | Label | R118 raw match | R163 raw match | Expected alert behavior |
| --- | --- | --- | --- | --- |
| `r118-bearer-token-looks-like-default-basic` | Benign | No | No | TLS-protected Bearer request: neither R118 nor cleartext-token R135 should match |
| `r118-ubiquiti-default-basic-observed` | Malicious | Yes | No | R118 stays below 86% pending additional evidence |
| `r163-paired-unrelated-gcp-agent` | Benign | No | No | Known GCP guest agent does not become SSRF because an unrelated inbound URL exists |
| `r163-paired-gcp-unattributed-fetch-candidate` | Malicious | No | Yes | R163 stays below 84%; an inbound fetch and outbound metadata request do not establish verified causality |

The benign R118 Bearer control must use HTTPS/TLS. A Bearer authorization header sent over cleartext HTTP is a separate security exposure and may correctly trigger R135; labeling that traffic benign and expecting zero alerts would invalidate the precision test. The encrypted control instead isolates the HTTP authentication scheme distinction (Bearer versus Basic).

All examples use documentation IP blocks and synthetic credentials. The R118
fixture contains a synthetic Base64 Basic value for legacy offline replay;
**live capture must retain only the trusted derived boolean and redact
Authorization bytes**. Never persist HTTP Authorization, IMDSv2 session tokens,
credential responses, or decoded passwords in evidence, logs, replay reports,
or benchmark artifacts.

## Additional precision controls: ambiguous authentication and URI normalization

This R118/R163 paired batch adds four fixtures on top of the verified 52.
Two additional R102 fixtures were committed independently in the same branch,
so the combined candidate dataset contains 58 JSON files:

| Fixture | Label | Rule under test | Expected raw match | Alert eligibility |
| --- | --- | --- | --- | --- |
| `r118-duplicate-authorization-ambiguous` | Benign | R118 | No | No |
| `r118-unauthorized-router-root-basic` | Malicious | R118 | Yes | Below 86%; Shadow |
| `r163-encoded-dot-segment-metadata-decoy` | Benign | R163 | No | No |
| `r163-gcp-ipv6-credential-fetch-unattributed` | Malicious | R163 | Yes | Below 84%; Shadow |

**R118:** The wire parser and legacy/replay contract now require exactly one
origin `Authorization` field before deriving a default-pair observation.
Duplicate headers are ambiguous across HTTP intermediaries and device
implementations. The wire-derived flag also requires a **complete HTTP
header section** (the terminating empty CRLF line), so a partial TCP
segment cannot be misclassified before a later duplicate field arrives.
The parser continues to redact *all* credential-bearing header values,
and neither the token nor the decoded password enters the detection event. The known default-pair set and R118's 86% confidence floor
are unchanged. A valid singleton remains detectable; duplicate headers do
not establish which credentials a device accepted.

**R163:** Provider credential paths must remain credential paths after
canonicalization. Reject literal `.`/`..` segments and ambiguous encoded
dot/separator forms before `Uri.TryCreate` can normalize absolute-form
request targets. This is a **false-positive prevention** measure, not SSRF
causal proof. A valid Google IPv6 metadata service-account token path
remains a raw match; a validated ingress-to-egress trace is still absent.
Azure's documented `?api-version=` token-query form remains supported.

The new fixtures are synthetic and use documentation IP ranges and
redacted/fictional credentials only. These fixtures **do not** measure
real-world prevalence or authorize raising confidence. No R118/R163/R102
mode or floor has changed.

## HTTP Host authority ambiguity controls (63-fixture candidate)

RFC 9112 §3.2 requires HTTP/1.1 servers to reject a request with duplicate
`Host` fields, even if the values are identical. The R163 metadata evidence
contract now checks any captured `Host` lines against the validated
`HttpHost` and numeric destination. Duplicate, conflicting, and comma-joined
authorities cannot establish a metadata credential read. If no header lines
are available (for example, normalized HTTP/2 `:authority` telemetry), the
existing strict parsed-authority/socket validation still applies. This
changes **raw recognition only** for ambiguous requests, never alert floors,
mode defaults, or independent SSRF causality requirements.

| Fixture | Label | Rule | Expected raw match | Why |
| --- | --- | --- | --- | --- |
| `r163-duplicate-host-metadata-decoy` | Benign control | R163 | No | Two conflicting Host lines |
| `r163-parsed-host-header-disagreement` | Benign control | R163 | No | Parsed authority disagrees with observed Host |
| `r163-azure-single-host-credential-probe` | Malicious scenario | R163 | Yes, Shadow | Single matching authority, Azure token path; SSRF causal chain not independently established |
| `r118-default-basic-unrelated-https-host` | Benign control | R118 | No | Synthetic decrypted HTTPS Basic credential, but no IoT device target |
| `r118-router-lowercase-single-basic` | Malicious scenario | R118 | Yes, Shadow | Unambiguous lowercase origin Authorization on router target; no login outcome proven |

All credential strings in these fixtures are **synthetic test tokens**, not
captured production secrets. The HTTP parser's existing redaction path must
remain enabled; never log Basic credentials, bearer tokens, IMDSv2 tokens,
or metadata response bodies. The new Host guard does not use credentials.

The new unit tests cover duplicate Host (identical and conflicting),
comma-joined Host, mismatched parsed/captured authority, a valid singleton,
and the expected replay modes for both R118 and R163. These tests are
**committed but not yet executed on Windows**. A malicious scenario label
is not a claim that the engine has proved unauthorized access or SSRF.

## Derived authentication provenance and GCP token-vs-identity controls (67 fixtures)

The R118 legacy/replay contract previously accepted
`HttpBasicDefaultCredentialObserved=true` before inspecting a concurrently
provided `HttpRequestHeaders` field. This could let an imported or
inconsistent record claim a trusted derived indicator despite duplicate
Authorization fields or a contradictory Bearer/non-default Basic header.
The detector now rejects duplicate origin Authorization lines even when
the derived flag is set. If a singleton header value is present, it must
be the privacy-safe `[REDACTED]` placeholder or a known synthetic default
Basic pair; a conflicting explicit scheme or value cannot be overridden.
A derived flag without retained header lines remains supported for
privacy-minimized capture sources. No credential bytes are added to
events or logs.

Four additional labeled controls were committed:

| Fixture | Label | Expected raw match | Evidence distinction |
| --- | --- | --- | --- |
| `r118-iot-x-authorization-lookalike` | Benign | No R118 | TLS-protected custom `X-Authorization` is not origin `Authorization` |
| `r118-camera-support-default-basic-attempt` | Malicious | R118, Shadow | Synthetic default `support:support` Basic credential aimed at a camera; no authentication outcome |
| `r163-gcp-service-account-email-not-token` | Benign | No R163 | GCP service-account email endpoint is not the token endpoint |
| `r163-gcp-service-account-token-direct-shadow` | Malicious | R163, Shadow | Token endpoint accessed by an unapproved workload, but no independent SSRF causal trace |

Six parameterized R118 cases cover redacted singleton, known default,
Bearer contradiction, non-default Basic contradiction, and two forms of
duplicate Authorization. The paired benchmark regression checks the
four new fixtures and the unchanged 86% R118 and 84% R163 floors in
each replay profile. The R102 80% floor is unchanged.

**Verification boundary:** all four fixture files were retrieved and
JSON-parsed; the feature-branch tree contained 35 benign and 32 malicious
JSON samples. These static checks do not establish detector behavior.
No updated Windows test results or 67-fixture TP/FP/FN metrics are
available. Preserve Shadow decisions and report `N/A` for precision
when a rule has no alert-level positive predictions. Do not present
raw recognition as alert recall.

The provenance distinction follows RFC 9110 field-line semantics and
the practice of minimizing sensitive HTTP header retention (compare
Zeek's default HTTP telemetry with optional full-header logging).
The GCP control follows the provider's distinction between
service-account identity and access-token endpoints. An observed
metadata token request alone is not SSRF causality.

## Device-host specificity and guest-agent executable-path controls (74-fixture candidate)

A current R118 raw match requires a recognizable origin Basic default pair or
Telnet login transcript **and** a likely IoT device target. A keyword buried
inside an unrelated hostname is not device inventory evidence. The HTTP host
contract now recognizes labels such as `camera-office`, `router02`, and
`ubiquiti-router`, but rejects `cameradeals.example.invalid`. A numeric
HTTP Host port is accepted only when it agrees with the observed destination
port; ambiguous userinfo or URL-like authorities are rejected. This reduces
false positives; it does **not** verify device ownership or prove login success.
An inventory mapping and authenticated outcome telemetry are still needed for
an 86%-eligible R118 alert.

R163 previously suppressed known guest-agent **basenames** even when the
captured process path pointed to a common user-writable directory. A request
from `C:\\Users\\Public\\cloud-init.exe` or `/tmp/google-guest-agent` now
remains a raw metadata candidate instead of being silently discarded. Ordinary
installation paths such as `/usr/bin/cloud-init` retain the prior benign
suppression. This is a narrow spoofing defense, not signed-binary validation:
basename-only records and unknown writable paths remain a residual limitation.

| Fixture | Label | Expected raw result | Alert decision |
| --- | --- | --- | --- |
| `r118-camera-marketing-host-substring` | Benign | No R118 | No R118 alert |
| `r118-router02-inventory-label-default-basic` | Malicious scenario | R118 match | Shadow; below 86% |
| `r163-approved-cloud-init-install-path` | Benign | No R163 | No R163 alert |
| `r163-cloud-init-writable-path-spoof` | Malicious scenario | R163 match | Shadow; below 84%; **SSRF not causally proven** |

The four fixtures use documentation IP ranges, fictional roles, synthetic
Basic tokens, and a redacted IMDSv2 header. They never establish successful
authentication, credential disclosure, or SSRF causality. Their expected
results are **assertions to execute**, not observed xUnit or benchmark passes.

**Telemetry next step:** collect signed process-image identity and stable
process-to-socket attribution (for example, Sysmon process-creation event 1
and network event 3 with `ProcessGuid`) before considering trusted agent
allowlisting. To prove R163 causality, a collector-assigned ingress request
identity must also be connected to the outbound metadata socket through
application tracing. Matching host/process and timestamps alone is not enough.
See Microsoft's Sysmon documentation:
https://learn.microsoft.com/sysinternals/downloads/sysmon and Zeek's HTTP
connection fields: https://docs.zeek.org/en/current/reference/logs/http.html .

**Verification:** `verify-local.ps1` now fails when the benchmark sample
count differs from the number of checked-out JSON fixtures, rather than
accepting an outdated fixed minimum. It also reports TP/FP/FN and alert-level
precision/recall/F1 for all six profiles and R118/R163/R102 separately.
These measurements remain **pending Windows execution**. With no alerts,
precision is `N/A`, not 100%. Never treat raw matches as alert-level TP.

## Fourth paired batch: redacted ONVIF Basic and GCP guest-agent provenance (78 fixtures)

| Fixture | Label | Expected raw match | What it establishes |
| --- | --- | --- | --- |
| `r118-onvif-unknown-basic-redacted` | Benign | No R118 | A redacted Authorization field with a **false** capture-time default-pair indicator is not evidence of default credentials. |
| `r118-onvif-default-basic-redacted` | Malicious scenario | R118 | The **true** trusted capture-time default-pair indicator plus an NVR/ONVIF device target preserves raw recognition without storing a Basic token or password. |
| `r163-gcp-guest-agent-installed-path` | Benign | No R163 | A normal installed Google guest agent requesting a documented token path is not evidence of SSRF. |
| `r163-gcp-user-writable-agent-spoof` | Malicious scenario | R163 | A user-writable executable using a familiar agent basename must not be suppressed; the request is a **raw candidate**, not causally proven SSRF. |

The R118 pair uses identical redacted Authorization headers and differs in
the **trusted parser-derived boolean**, making it a privacy-safe replay
contract test. This boolean must be derived from complete, unambiguous
wire data by the capture parser; it must never be trusted merely because
an untrusted external record asserts it. These synthetic replays exercise
the current contract, **not provenance authentication of imported records**.

The R163 pair uses the GCP metadata alias at its documented IPv4 endpoint
and the service-account token path. The Google metadata protocol header is
ordinary provider mechanics and contributes **no independent SSRF causality**.
The spoofed-path case must remain below R163's 84% alert threshold. The
installed-path case must not match R163. The ONVIF case must remain below
R118's 86% alert threshold. R102 remains at 80%.

A fourth paired-batch xUnit assertion was added, but **no Windows tests or
78-fixture benchmark have been run and verified** in this environment.

### Latest observed Windows baseline and known blocker

The latest user-provided 74-fixture Windows output showed successful restore,
build, and benchmark stages, but **failed xUnit tests**. Its labeled
*rule-level alert* metrics were:

| Profile | TP | FP | FN | Precision | Recall | F1 |
| --- | ---: | ---: | ---: | ---: | ---: | ---: |
| Enterprise | 5 | 3 | 29 | 62.5% | 14.7% | 23.8% |
| HomeLab | 1 | 0 | 33 | 100.0% | 2.9% | 5.7% |
| IoTHeavy | 1 | 0 | 33 | 100.0% | 2.9% | 5.7% |
| OTSegment | 6 | 0 | 28 | 100.0% | 17.6% | 30.0% |
| Research | 8 | 3 | 26 | 72.7% | 23.5% | 35.6% |
| SmallBusiness | 4 | 0 | 30 | 100.0% | 11.8% | 21.1% |

These numbers are **historical** (74 samples, not the 78-fixture branch),
and count unique alerted rule IDs against labeled expected matches. They
are not the same as sample-level TP/FP/FN and do not estimate live
production prevalence. The benign
`r163-approved-cloud-init-install-path` fixture produced **three critical
alert-rule IDs** in Enterprise and Research. R163 itself was explicitly
expected not to match; determine the offending rule IDs before changing
any detector. The 74-fixture report also showed only nine rules with
paired synthetic controls among 544 registered rules.

The manually dispatched Windows quality workflow now verifies that the
benchmark sample count equals the checked-out JSON inventory and reports
sample-level alert precision, recall and F1 for all six profiles. It fails
on any benign alert. It has **not been executed** for this revision, and
the repository's Actions billing/storage restrictions remain a blocker.
The local `verify-local.ps1` also prints per-rule alert-level metrics.

**Promotion decision: HOLD.** Preserve the 86%/84%/80% floors and
privacy redaction. Obtain the failing xUnit assertion names and benign
alert rule IDs, fix the actual causes, and rerun the complete Windows
verification before considering promotion.

## What independent R163 corroboration would require

A future promotion path must be based on **trusted provenance** rather than
strings supplied by an HTTP client:

1. A trusted ingress observation identifies the attacker-controlled request
   and the application that accepted it, with a collector-assigned request ID.
2. An independently observed process/network trace links that exact request
   execution to the outbound metadata socket, not merely the same host or
   a nearby timestamp. A Zeek connection UID links records for a connection;
   by itself it does **not** prove an inbound-to-outbound application causal chain.
3. The socket destination and HTTP authority agree on a provider-specific
   metadata endpoint; the path requests credentials, not generic instance data.
4. Trusted process identity (path, signer, workload/container identity) is
   evaluated against an explicit approval inventory. Process basename alone
   is insufficient to establish authorization.
5. Where observable and authorized, response status, metadata credential
   exposure, or a controlled canary supplies corroboration. No secret body
   or token value is stored; use bounded non-sensitive status/evidence fields.
6. Confidence and independent runtime precision checks must still meet 84%.
   Absence of a trace or provenance keeps the event in Shadow.

These are design requirements, **not claims that the current engine already
implements cross-connection causality**.

## Verification and release decision

From a Windows PowerShell checkout of the feature branch:

```powershell
git fetch origin feature/carthago-reliability-hardening
git merge --ff-only FETCH_HEAD
.\verify-local.ps1 -Details
Get-Content .\build-verify\local-logs\tests.log -Tail 60
Get-Content .\build-verify\local-logs\benchmark.log -Tail 60
```

Inspect `build-verify/tuning-benchmark.json` and
`build-verify/tuning-benchmark.md`. Compare **alert-level** TP/FP/FN,
precision, recall, and F1 for every profile against the prior 48-sample
baseline. The expanded dataset changes the denominator, so do not describe
a change in recall as an improvement unless the corresponding matched
malicious alerts and benign false positives support it. Also inspect
`RecallGaps` to distinguish missing telemetry, raw detector nonmatches,
and deliberate policy/precision Shadow decisions. A zero-FP result on
synthetic samples is not production precision.

If tests or replay expectations fail, retain the previous policy and
diagnose the failing fixture; do not promote R118, R163 or R102.

## 80-fixture candidate: parser-negative Basic and IMDSv2 HEAD probe (2026-10-26)

| Fixture | Label | Expected raw rule result | Alert decision |
| --- | --- | --- | --- |
| `r118-onvif-nondefault-basic-wire-redacted` | Benign | No R118 | No benign alert in any profile |
| `r163-unapproved-aws-imdsv2-head-credential-probe` | Malicious unauthorized probe | R163 candidate | Shadow; a HEAD request is not proof of credential retrieval or SSRF |

The R118 negative control supplies a **test-only** synthetic Basic header
(`admin:strong-pass`) through `rawHttpRequestsByRecordIndex`. The
benchmark uses the production `HttpLight` parser to derive the credential
indicator and replace the header with `[REDACTED]` before detection. A
non-default pair must not be promoted into a default-credential observation.
The synthetic Base64 value must not appear in the serialized benchmark report.
This fixture complements the positive parser-derived ONVIF case, rather than
trusting a replay JSON boolean with an internal setter.

The R163 probe uses a valid EC2 IMDS credential path, an observed metadata
socket destination, a matching Host, and a non-agent process. Its IMDSv2 token
header is redacted and supplies **no** confidence bonus. The method is HEAD:
this tests suspicious endpoint probing, not successful credential extraction.
Without independent inbound-request-to-process-to-egress attribution, the
candidate must remain non-paging below R163's 84% floor. R118 remains at 86%
and R102 at 80%; no thresholds or default modes were changed.

A paired xUnit regression was added to the existing replay test method to
avoid another full benchmark execution per test. It asserts classifications,
raw matches, no benign alerts, redaction, and per-profile Shadow decisions.
**It has not yet been executed on Windows.**

### Last supplied local verification (78 fixtures; not a passing baseline)

The Windows output supplied on 2026-10-26 showed successful restore and
benchmark execution, but **build-tests failed**, **tests failed**, and one
R118 ONVIF replay expectation failed (0.68 observed versus 0.75 expected).
Seven failing xUnit test cases were reported by the local diagnosis script.
A subsequent branch change routed synthetic ONVIF HTTP through the real parser;
this fix has not yet been validated by a fresh Windows run. Do not use stale
`--no-build` test binaries as evidence that the updated source passed.

| Profile | 78-fixture alert TP/FP/FN | Precision | Recall | F1 |
| --- | --- | ---: | ---: | ---: |
| Enterprise | 5/0/31 | 100.0% | 13.9% | 24.4% |
| HomeLab | 1/0/35 | 100.0% | 2.8% | 5.4% |
| IoTHeavy | 1/0/35 | 100.0% | 2.8% | 5.4% |
| OTSegment | 6/0/30 | 100.0% | 16.7% | 28.6% |
| Research | 8/0/28 | 100.0% | 22.2% | 36.4% |
| SmallBusiness | 4/0/32 | 100.0% | 11.1% | 20.0% |

These are **historical, incomplete-quality-gate, labeled offline alert-rule
metrics**, not results for the current 80-fixture branch and not production
prevalence. Raw recognition and Shadow decisions are not counted as alerts.
Recompute TP/FP/FN, precision, recall and F1 for all six profiles after a
successful Windows build, xUnit run and replay-expectation gate.

## 84-fixture candidate: authority provenance and IMDSv2 method pair (2026-10-26)

| Fixture | Label | Expected raw result | Alert expectation |
| --- | --- | --- | --- |
| `r118-forwarded-camera-host-unrelated-https` | Benign | No R118 | No alerts |
| `r118-camera-default-basic-wire-probe` | Malicious scenario | R118 | Shadow, no authentication outcome |
| `r163-approved-imdsv2-session-put` | Benign | No R163 | No alerts |
| `r163-unapproved-imdsv2-get-credential-path` | Malicious scenario | R163 | Shadow, no SSRF causal proof |

The forwarded-Host fixture uses a real HTTP `Host` value for an unrelated
HTTPS portal and a client-controlled `X-Forwarded-Host` naming a camera.
Forwarded request fields are not authoritative device-inventory evidence.
The positive R118 fixture feeds a complete synthetic Basic request through
the production parser, which must redact the credential before reporting;
no authentication success is claimed. The AWS pair distinguishes a routine
IMDSv2 session-token `PUT /latest/api/token` by an installed agent from a
suspicious `GET /latest/meta-data/iam/security-credentials/...` by an
unapproved application. Even the latter does not prove that an inbound
attacker-controlled request caused the outbound metadata request. Never
persist an IMDSv2 session token or credential response body.

The benchmark's advisory `RulesRecommendedForAlert` heuristic previously
used a generic 75% match threshold. It now also enforces the **rule-specific
minimum confidence** before suggesting a rule for review. This is a
recommendation guard, not a rule-mode or runtime detection change. A
recommendation is never authorization to page; independent evidence and
profile-policy gates still apply. New xUnit assertions cover both pairs,
redaction expectations, profile alert decisions, and sub-floor recommendation
behavior. They have **not been run on Windows** for the 84-fixture revision.

### Verified 80-fixture Windows baseline (user-supplied output)

The supplied local log reports **958 passed, 0 failed, 0 skipped** tests,
`PASS: benchmark`, 80 samples (43 benign, 37 malicious), no benign
simulated alerts, no missing expected malicious raw matches, and
`PASS: local build, tests and replay validation.` The historical
**alert-rule-level** counts below are distinct from sample-level metrics:

| Profile | TP / FP / FN | Precision | Recall | F1 |
| --- | --- | ---: | ---: | ---: |
| Enterprise | 5 / 0 / 32 | 100.0% | 13.5% | 23.8% |
| HomeLab | 1 / 0 / 36 | 100.0% | 2.7% | 5.3% |
| IoTHeavy | 1 / 0 / 36 | 100.0% | 2.7% | 5.3% |
| OTSegment | 6 / 0 / 31 | 100.0% | 16.2% | 27.9% |
| Research | 8 / 0 / 29 | 100.0% | 21.6% | 35.6% |
| SmallBusiness | 4 / 0 / 33 | 100.0% | 10.8% | 19.5% |

R118, R163 and R102 each had **zero actual alerts** in all six profiles:
precision **N/A**, alert recall **0%**, F1 **0%** on this labeled corpus.
That is deliberate gating, not evidence of production accuracy. The
84-fixture revision needs a fresh Windows run to compare TP/FP/FN and
precision/recall/F1 for all profiles and these three rules.

Official references: [RFC 9110 Authorization and authority](https://www.rfc-editor.org/rfc/rfc9110.html),
[RFC 9112 Host requirements](https://www.rfc-editor.org/rfc/rfc9112.html#section-3.2),
[AWS IMDSv2 protocol](https://docs.aws.amazon.com/AWSEC2/latest/UserGuide/configuring-instance-metadata-service.html).

## References

- RFC 9112 §3.2 (HTTP/1.1 Host and duplicate fields): https://www.rfc-editor.org/rfc/rfc9112.html#section-3.2
- RFC 9110 §5.3 on ambiguous repeated HTTP field lines: https://www.rfc-editor.org/rfc/rfc9110.html#section-5.3
- RFC 7617 on HTTP Basic authentication and Base64 credentials: https://www.rfc-editor.org/rfc/rfc7617.html
- Zeek HTTP logging (connection UID and password-capture defaults): https://docs.zeek.org/en/current/scripts/base/protocols/http/main.zeek.html
- AWS EC2 IMDSv2 request semantics: https://docs.aws.amazon.com/AWSEC2/latest/UserGuide/configuring-instance-metadata-service.html
- Google Cloud metadata HTTP headers: https://docs.cloud.google.com/compute/docs/metadata/querying-metadata
- OWASP SSRF Prevention Cheat Sheet: https://cheatsheetseries.owasp.org/cheatsheets/Server_Side_Request_Forgery_Prevention_Cheat_Sheet.html
- MITRE ATT&CK T1078.001 default accounts: https://attack.mitre.org/techniques/T1078/001/
- Zeek open-source HTTP connection UID and 4-tuple schema: https://docs.zeek.org/en/lts/scripts/base/protocols/http/main.zeek.html

- RFC 9110 §5.3 on duplicate field lines: https://www.rfc-editor.org/rfc/rfc9110.html#section-5.3
- Zeek optional full-header logging (privacy caution): https://github.com/sethhall/zeek-log-all-http-headers


## 92-fixture candidate: Digest authentication and ECS task-role paths (26 October 2026)

Four new synthetic, paired replays distinguish **authentication scheme** from
device login evidence, and **ECS task metadata** from ECS credential access:

| Fixture | Label | Expected R118 | Expected R163 | Why |
| --- | --- | --- | --- | --- |
| `r118-digest-camera-auth-not-basic` | Benign | No match | No match | Digest `username=admin` is not Basic default-pair evidence; wire parser must redact Authorization |
| `r118-ubiquiti-basic-https-wire-probe` | Malicious scenario | Raw match, non-paging | No match | Synthetic HTTPS Basic default pair on an IoT gateway; no login outcome |
| `r163-ecs-task-metadata-not-credentials` | Benign | No match | No match | ECS v2 `/v2/metadata` is a task metadata lookup |
| `r163-ecs-unapproved-task-credential-probe` | Malicious scenario | No match | Raw match, non-paging | ECS `/v2/credentials/<synthetic-id>` from an unapproved caller; no inbound-to-egress causal proof |

AWS documents the ECS v2 task metadata endpoint separately from the task-role
credential URI supplied through `AWS_CONTAINER_CREDENTIALS_RELATIVE_URI`.
The v2 task metadata endpoint is legacy; v4 is recommended for new ECS deployments.
These controls are intended to validate the current R163 contract, not to assert
that an ECS metadata request proves SSRF or credential theft.

The R118 wire fixtures contain **synthetic** authorization values only in the
private replay inputs; exported benchmark records must contain redacted
Authorization fields. The regression test checks that synthetic Basic/Digest
values are absent from the serialized report. Never log real authorization
headers, IMDSv2 session tokens, or credential response bodies.

A new **privacy-minimizing report comparator** can be run after a fresh Windows
verification. It recomputes confusion matrices from alert decisions, compares
both the full datasets and the **shared fixture cohort** (avoiding artificial
recall drops from added malicious samples), and shows explicitly labeled
R118/R163/R102 rule-level opportunities. A rule with zero alerts has precision
**N/A**, not 100%.

```powershell
# Preserve a locally verified historical report before running verification.
Copy-Item build-verify/tuning-benchmark.json build-verify/baseline-verified.json
.\verify-local.ps1 -Details
python scripts/compare-replay-quality.py --baseline build-verify/baseline-verified.json --candidate build-verify/tuning-benchmark.json --strict
```

The comparator was syntax-checked and exercised against synthetic passing and
false-positive reports on Linux. That is **not** .NET or Windows verification.
It intentionally prints only aggregate metrics, not fixture contents or secrets.
If a previously verified baseline JSON was not saved, do not fabricate one from
a historical table; the full shared-cohort comparison must remain pending.

Sources:
- [AWS ECS task metadata v2](https://docs.aws.amazon.com/AmazonECS/latest/developerguide/task-metadata-endpoint-v2.html)
- [AWS ECS task IAM roles and credential URI](https://docs.aws.amazon.com/AmazonECS/latest/developerguide/task-iam-roles.html)
- [RFC 7617 Basic authentication](https://www.rfc-editor.org/rfc/rfc7617.html)
- [RFC 7616 Digest authentication](https://www.rfc-editor.org/rfc/rfc7616.html)
- [Microsoft Sysmon process/connection telemetry](https://learn.microsoft.com/sysinternals/downloads/sysmon)


## 96-fixture candidate: authority-port integrity and Azure IMDS (26 October 2026)

This paired batch adds **two benign controls and two malicious-scenario controls**
to the 92-fixture corpus (now 51 benign / 45 malicious). The samples are
synthetic, and malicious labels describe ground-truth scenario intent rather
than proven authentication success or SSRF exploitation.

| Fixture | Label | Expected result | Independent-evidence boundary |
| --- | --- | --- | --- |
| `r118-router-authority-port-mismatch` | Benign control | R118 no match | HTTP Host declares `:9443`, observed destination socket is `:8443`; the capture parser still redacts the synthetic Basic value |
| `r118-router-authority-port-match` | Malicious scenario | R118 raw match, non-paging | The same synthetic default Basic attempt has a matching Host/socket port; no login outcome telemetry |
| `r163-azure-instance-metadata-agent` | Benign control | R163 no match | Approved Azure guest agent requests `/metadata/instance`, not a credential endpoint |
| `r163-azure-vault-token-unapproved` | Malicious scenario | R163 raw match, non-paging | Unapproved application requests `/metadata/identity/oauth2/token` for a Key Vault audience; no response token or independently attributed inbound trigger |

HTTP/1.1 Host includes an optional port and cannot override the independently
observed destination socket. The R118 pair specifically exercises the live
HTTP parser, which derives a capture-time default-Basic indicator and replaces
the Authorization value with `[REDACTED]`. Azure IMDS requires the
`Metadata: true` header for both ordinary metadata and managed-identity token
requests; that header is a protocol requirement, **not** evidence of SSRF.
A token-endpoint request without trusted ingress-to-egress attribution remains
investigative evidence only.

Added `Carthago.Tests/R118R163AuthorityAndAzureReplayTests.cs` to assert the
four classifications, raw matches/nonmatches, exported Basic-token redaction,
all six profile gates, and unchanged minimum confidence floors
(R118 86%, R163 84%, R102 80%). The new fixtures were retrieved and
successfully parsed as JSON, and all five corresponding GitHub commits were
checked to modify one file each. **The new xUnit test and 96-fixture benchmark
have not been executed on Windows; no updated precision, recall, or F1 values
are available.** Do not promote either rule.

Next: execute `./verify-local.ps1 -Details` in Windows PowerShell, retain
the verified JSON report, and use
`scripts/compare-replay-quality.py --baseline <verified-old.json> --candidate <verified-new.json> --strict`
to compare full and shared cohorts. Report both sample-level and alert-rule-level
confusion matrices, and treat zero-alert precision as N/A.

References:
- [RFC 9112 HTTP/1.1 Host authority](https://www.rfc-editor.org/rfc/rfc9112.html#section-3.2)
- [Azure VM instance metadata](https://learn.microsoft.com/en-us/azure/virtual-machines/instance-metadata-service)
- [Microsoft managed identity token request](https://learn.microsoft.com/en-us/entra/identity/managed-identities-azure-resources/how-to-use-vm-token)
- [Azure SDK for .NET managed identity implementation guidance](https://github.com/Azure/azure-sdk-for-net/blob/main/sdk/identity/Azure.Identity/TROUBLESHOOTING.md)

## 100-fixture candidate: NVR redaction and EC2 IMDS IPv6 attribution (26 October 2026)

Four synthetic paired replay scenarios extend the corpus to **53 benign and
47 malicious-scenario fixtures**. The labels are independent test-ground-truth
descriptions; they are not conclusions established by network telemetry alone.

| Fixture | Label | Expected raw detection | Why this matters |
| --- | --- | --- | --- |
| `r118-nvr-nondefault-redacted-basic` | Benign | R118 no match | The live HTTP parser redacts a synthetic non-default Basic credential and must not infer a default pair from an Authorization field alone. |
| `r118-nvr-default-redacted-basic` | Malicious scenario | R118 match; non-paging | The same NVR and HTTPS authority receives a synthetic default Basic pair; parser-derived evidence must be used without storing the credential or claiming login success. |
| `r163-imdsv6-approved-ssm-credential-read` | Benign | R163 no match | An installed, recognized EC2 guest agent accesses a role-credential path over the documented IPv6 IMDS endpoint. |
| `r163-imdsv6-unapproved-credential-read` | Malicious scenario | R163 match; non-paging | An unapproved application accesses the same IPv6 credential path, but no ingress request, response contents, or independent SSRF causal chain is supplied. |

Both NVR fixtures pass **synthetic** raw HTTP requests through the production
`HttpLight` parser; their records contain only redacted Authorization headers.
The JSON fixtures do not set `HttpBasicDefaultCredentialObserved`: the replay
loader requires that flag to originate from the parser, not from arbitrary JSON.
The paired IMDSv6 records contain neither session tokens nor credential response
bodies. IMDSv2 protocol headers alone must not increase SSRF confidence.

The added `Carthago.Tests/R118R163NvrAndImdsV6ReplayTests.cs` asserts
classifications, expected matches, exported-credential redaction, all six
profile decisions, and unchanged rule floors: **R118 86%, R163 84%, R102 80%**.
These are regression **assertions**, not evidence that the test has passed.

**Verification boundary:** the four JSON files were structurally checked and
the repository inventory confirmed 100 fixtures. Windows compilation, xUnit,
and the 100-fixture benchmark have **not** been executed for this revision.
Alert-level TP/FP/FN and precision/recall/F1 by profile are therefore pending.
Do not promote R118 or R163 based on these additions.

EC2 IMDS IPv6 `fd00:ec2::254` is available only when explicitly enabled on
supported Nitro instances and IPv6-capable subnets. A metadata credential-path
request can be legitimate for an authorized agent; a nonstandard caller is a
candidate for investigation, not proof of SSRF. Trusted process GUID/socket
attribution and a request-level ingress-to-egress causal chain are required
before stronger SSRF claims. Sysmon Event ID 3 and Zeek HTTP/connection UIDs
provide useful attribution components, not causality by themselves.

References:
- [AWS EC2 instance metadata retrieval and IPv6](https://docs.aws.amazon.com/AWSEC2/latest/UserGuide/instancedata-data-retrieval.html)
- [AWS EC2 IAM role credential metadata](https://docs.aws.amazon.com/AWSEC2/latest/UserGuide/instance-metadata-security-credentials.html)
- [RFC 7617 HTTP Basic authentication](https://www.rfc-editor.org/rfc/rfc7617.html)
- [Microsoft Sysmon process GUID and network connection telemetry](https://learn.microsoft.com/sysinternals/downloads/sysmon)
- [Zeek HTTP log UID correlation](https://docs.zeek.org/en/current/reference/logs/http.html)
