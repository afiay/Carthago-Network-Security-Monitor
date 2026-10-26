# R118 / R163 evidence contract

Status: **experimental detection, no alert promotion authorized**. This document describes
the minimum evidence needed for a trustworthy decision. It does not assert that field
precision has been measured.

## R118 — IoT default-credential authentication

- **Observed:** a captured plaintext HTTP Basic `Authorization` value matches a
  canonical known-default pair, and the HTTP host identifies a likely device.
  The packet parser derives `HttpBasicDefaultCredentialObserved` from a bounded
  byte span before replacing the header with `[REDACTED]`. It does not retain
  the original credential or Base64 representation in `HttpRequestHeaders`.
- **Not observed:** successful login, account compromise, authorized maintenance,
  or any authentication inside encrypted HTTPS traffic. A packet-level HTTP parser
  is not a TLS decryption engine. Telnet transcript matching is not proof that a
  live Telnet authentication decoder exists.
- **Before promotion:** require trusted device inventory/ownership, a reliable
  authentication outcome or corroborated login audit, an approved provisioning
  window check, and calibrated labeled positive/negative traffic. Keep the
  existing **86% minimum confidence**; no synthetic match can waive it.
- **Negative controls:** help pages containing `admin:admin`, non-default Basic
  credentials, malformed Basic headers, and authorized post-reset provisioning.
  A legitimate default credential can be observable yet should not page.

## R163 — cloud metadata credential access vs. SSRF

- **Observed:** an outbound HTTP request whose destination and Host identify
  a metadata service, with a credential-related path, from a process not on
  the current known-agent list. This is a **metadata access observation**, not
  a demonstrated SSRF exploit.
- **Not independent evidence:** `Metadata: true`, `Metadata-Flavor: Google`,
  or an AWS IMDSv2 session-token header. These are normal provider protocol
  mechanics. Header presence may be useful context, but must not increase
  SSRF confidence.
- **Before promotion:** link a specific untrusted inbound request or redirect
  to the outbound metadata access using a trustworthy request/trace ID and
  process instance (PID + start time + namespace/host). Include redirect-chain
  resolution and destination-IP validation. Temporal proximity alone is not
  causation. Corroborate with web/application traces or host network telemetry,
  and check approved bootstrap/guest-agent workloads. Preserve the existing
  **84% minimum confidence**.
- **Negative controls:** routine instance inventory, approved guest agents,
  custom bootstrap clients using IMDSv2, forged Host headers, and requests
  that merely mention metadata endpoints in documentation. HTTP `Host` must be
  a literal metadata authority, never a parsed URI with userinfo, an embedded
  path, or an unrelated port. An absolute-form request target must agree with
  the observed Host and destination; cross-provider authorities are rejected.
- **Trace trust boundary:** an inbound `traceparent` header is caller-supplied
  and must never, on its own, count as independent proof of SSRF. Promote
  causality only from trusted application/ingress instrumentation that binds
  an accepted inbound request to the outbound client span, with consistent
  process-instance identity, validated endpoint, and a credible timeline.
  Reject missing, forged, or unverified trace ancestry; preserve Shadow.

## Provider-specific credential endpoint matrix

The R163 request classifier now validates **the observed destination, the
HTTP Host authority, and the credential path together**. An arbitrary
credential-looking path on a real metadata IP is not evidence that the
provider would return credentials.

| Observed destination / validated Host | Credential path accepted for an access observation |
| --- | --- |
| `169.254.169.254` | AWS EC2 `/latest/meta-data/iam/security-credentials[/...]`; Azure `/metadata/identity/oauth2/token`; GCP `/computeMetadata/v1/instance/service-accounts/.../token` |
| `169.254.170.2` | AWS ECS task credentials `/v2/credentials[/...]` |
| `100.100.100.200` | Alibaba ECS RAM role `/latest/meta-data/ram/security-credentials[/...]` |
| `metadata.google.internal` as Host, with observed `169.254.169.254` destination | GCP service-account token path only |

The shared `169.254.169.254` address does **not** establish which cloud
provider hosts the VM. The classifier deliberately recognizes multiple
documented provider-specific paths at that address without assigning
provider identity or SSRF causality. ECS and Alibaba paths are not accepted
at that shared address. A recognized path is still **Shadow** without
independent inbound-to-outbound evidence and the 84% confidence floor.

Regression controls include an ECS destination paired with an EC2
instance-credential path, legitimate provider/path combinations, and
synthetic unauthorized ECS and Alibaba credential probes. The malicious
labels describe the synthetic scenario's known intent, not a proven
SSRF causal chain. None of these fixtures contains a real cloud token.

## Open-source implementation comparison

The Falco project's *Contact cloud metadata service from container* rule
observes an outbound connection to the metadata address, includes process
and container context, and offers a known-access exception. Its priority is
NOTICE and its maturity is incubating: this is an access observation, not
proof that an inbound attacker-controlled request caused the connection.
Carthago should retain that distinction while going further: join trusted
server-side inbound spans to outbound client spans, validate actual socket
destination and process instance, and account for authorized workloads.
Never upgrade confidence from a shared timestamp or externally supplied
`traceparent` alone. OpenTelemetry's ASP.NET Core and HttpClient
instrumentation are useful reference implementations for producing the
independent spans, but the instrumented service must establish the trust
boundary; passive capture cannot manufacture missing causality.

## Cross-cutting privacy and quality rules

1. Never persist Basic credentials, IMDS session-token values, cookies, API
   keys, or cloud identity bearer headers in normalized HTTP records.
2. Preserve a source/provenance distinction: wire-derived facts, synthetic
   replay fields, external audit logs, and analyst annotations are not
   interchangeable evidence.
3. Report TP, FP, FN, TN, precision, recall and F1 **at the effective Alert
   decision level**, separately for each tuning profile. Shadow matches
   are not alerts. A benign replay can intentionally match a raw rule.
4. The global *true-positive pass rate* denominator contains only expected
   matches in **malicious** fixtures. Benign raw matches must not inflate it.
5. Keep R102's **80% minimum confidence** unchanged. Do not lower any
   threshold or silently promote a rule to improve headline recall.
6. Use the Windows CI workflow to build, run xUnit and publish labeled replay
   reports. A passing unit suite is not a substitute for production capture
   validation or a representative field confusion matrix.

## Known limitations and next implementation gates

- The current lightweight packet parser inspects early TCP payload bytes;
  fragmented headers, encrypted HTTPS and unobserved host traffic can escape
  this capture path. Add bounded HTTP stream reassembly and explicit capture
  coverage metrics before claiming live detection reliability.
- Process-name allowlists alone are weak: verify process instance, signer,
  executable identity and approved role where available.
- Add independent inbound/outbound SSRF trace correlation and provenance-rich
  replay samples before considering an R163 confidence increase.
- Expand malicious samples from controlled, labeled test environments and
  maintain distinct benign controls; synthetic fixtures are regression
  tests, not estimates of field false-positive prevalence.
- Do not merge or promote based on unverified CI status. Run and inspect
  Windows Release tests and benchmark artifacts first.

## Reference specifications

- RFC 7617, HTTP Basic authentication: https://www.rfc-editor.org/rfc/rfc7617
- AWS EC2 IMDSv2: https://docs.aws.amazon.com/AWSEC2/latest/UserGuide/configuring-instance-metadata-service.html
- AWS ECS task-role credential endpoint: https://docs.aws.amazon.com/AmazonECS/latest/developerguide/security-iam-roles.html
- Alibaba ECS RAM-role metadata endpoint: https://www.alibabacloud.com/help/en/ecs/user-guide/attach-an-instance-ram-role-to-an-ecs-instance
- Azure Instance Metadata Service: https://learn.microsoft.com/en-us/azure/virtual-machines/instance-metadata-service
- Google Compute Engine metadata: https://docs.cloud.google.com/compute/docs/metadata/querying-metadata
- OWASP SSRF Prevention: https://cheatsheetseries.owasp.org/cheatsheets/Server_Side_Request_Forgery_Prevention_Cheat_Sheet.html
- OpenTelemetry context propagation and untrusted trace headers: https://opentelemetry.io/docs/concepts/context-propagation/
- Falco official metadata-access rule: https://falco.org/docs/reference/rules/default-rules/
- OpenTelemetry .NET ASP.NET Core instrumentation: https://github.com/open-telemetry/opentelemetry-dotnet-contrib/tree/main/src/OpenTelemetry.Instrumentation.AspNetCore
- OpenTelemetry .NET HttpClient instrumentation: https://github.com/open-telemetry/opentelemetry-dotnet-contrib/tree/main/src/OpenTelemetry.Instrumentation.Http
