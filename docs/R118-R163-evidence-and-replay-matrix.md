# R118 and R163: evidence contracts and replay matrix

Status: **validation candidate**, not a rule-promotion request. The
feature-branch tree currently contains **74 JSON replay fixtures (40 benign,
34 malicious)**, including four new controls for IoT hostname specificity
and cloud-agent executable-path spoofing. Earlier sections document historical
52/58/63/67-fixture milestones, not the current inventory. All four newly
added JSON files were retrieved and parsed successfully. This is structural
verification only, **not** a 74-sample benchmark PASS. Windows compilation,
xUnit tests, and updated per-profile alert-level precision/recall/F1 remain
unverified. Do not promote any rule until those checks and policy-accounting
gates pass.

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
