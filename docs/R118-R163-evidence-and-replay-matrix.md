# R118 and R163: evidence contracts and replay matrix

Status: **validation candidate**, not a rule-promotion request. The user
confirmed a Windows PASS for the 52-sample benchmark at commit `4617691`,
including five focused R102 tests (5 passed, 0 failed). The four additional
R118/R163 controls in this batch bring the candidate set to **56**.
**Do not claim the 56-sample run passes until Windows build, tests and
benchmark complete at the new branch head.**

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

The second paired batch adds four fixtures on top of the verified 52:

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

- RFC 9110 §5.3 on ambiguous repeated HTTP field lines: https://www.rfc-editor.org/rfc/rfc9110.html#section-5.3
- RFC 7617 on HTTP Basic authentication and Base64 credentials: https://www.rfc-editor.org/rfc/rfc7617.html
- Zeek HTTP logging (connection UID and password-capture defaults): https://docs.zeek.org/en/current/scripts/base/protocols/http/main.zeek.html
- AWS EC2 IMDSv2 request semantics: https://docs.aws.amazon.com/AWSEC2/latest/UserGuide/configuring-instance-metadata-service.html
- Google Cloud metadata HTTP headers: https://docs.cloud.google.com/compute/docs/metadata/querying-metadata
- OWASP SSRF Prevention Cheat Sheet: https://cheatsheetseries.owasp.org/cheatsheets/Server_Side_Request_Forgery_Prevention_Cheat_Sheet.html
- MITRE ATT&CK T1078.001 default accounts: https://attack.mitre.org/techniques/T1078/001/
- Zeek open-source HTTP connection UID and 4-tuple schema: https://docs.zeek.org/en/lts/scripts/base/protocols/http/main.zeek.html
