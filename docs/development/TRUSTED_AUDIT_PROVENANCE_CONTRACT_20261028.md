# Trusted audit provenance: signed receipt boundary

**Engineering state:** source candidate, **not built/tested on CARTHAGE**, **not integrated with live rule evaluations**. No production audit producer or pinned public-key provisioning exists yet. This change is not a claim that R163, R275, R295, or R343 can now produce validated alerts.

## Why the boundary exists

The packet capture and offline replay paths expose traffic and untrusted free-text `Info`, URI, port and process *hints*. None can prove that a PowerShell command executed, that a Kubernetes API server approved pod exec, that an identity provider confirmed device-flow abuse, or that an HTTP request causally triggered a metadata fetch.

Do not feed a JSON audit object, a guessed boolean, a self-signed local certificate, or an unverified event log into a rule as "trusted". The trust decision must happen at a separate configured producer boundary, before rules receive typed evidence.

## Foundation implemented

`Carthago/Services/TrustedAudit/TrustedAuditReceiptVerifier.cs` defines:

- `TrustedAuditIssuer`: operator-configured issuer ID, RSA subject-public-key-info (SPKI) and explicitly permitted rule IDs. Only an operator-controlled configuration may supply trusted issuers. No input from `TrafficRecord`, replay JSON or a packet may modify trust anchors.
- `SignedAuditEnvelope`: envelope issuer, base64 JSON claim bytes and detached base64 RSA-PSS/SHA-256 signature, verified over the exact `CARTHAGO-TRUSTED-AUDIT-V1\n` domain prefix plus claim bytes.
- `AuditClaim`: metadata only—rule/operation, receipt UUID, UTC occurrence, source/destination IPs, pseudonymous actor hash, resource hash **and mandatory session/trace hash**. Do not include raw commands, JWTs, access tokens, device codes, HTTP secrets, usernames or request bodies.
- `VerifiedAuditReceipt`: immutable output with an **internal constructor**; unsigned input cannot directly instantiate it.
- `TrustedAuditReceiptVerifier`: pinned key validation (RSA 2048 bits or stronger), issuer-to-rule scope, exact operation mapping, capped input bytes, duplicate/unknown JSON field rejection, strict UTC freshness (10-minute age; 2-minute future tolerance), and a bounded, fail-closed consumed-ID cache.

Allowed rule/operation pairs are fixed in code:

| Rule | Signed operation | Upstream evidence that still must exist |
| --- | --- | --- |
| R343 | `WinRmEncodedCommandExecuted` | Authenticated WinRM host/session operation plus process-command attribution |
| R295 | `KubernetesPodExecAuthorized` | Authenticated API-server audit for pod exec, resource, principal, authorization and outcome |
| R275 | `OAuthDeviceFlowAbuseConfirmed` | Trusted IdP audit plus **independent** evidence of phishing action |
| R163 | `HttpMetadataRequestCausallyLinked` | Trusted request/trace/identity link tying untrusted inbound handling to outgoing IMDS credential request |

**A valid signature is necessary but not sufficient for an alert.** The claim's factual source must be authenticated by the producer, the issuer must be configured and scoped by an operator, and the consumer must bind the event to an actual rule's affected entity, actor, resource, signed session/trace hash and time. **IP + adjacent timestamp alone is insufficient** for R163, Kubernetes, WinRM or OAuth abuse. The current `RuleEvaluationContext` does not consume `VerifiedAuditReceipt`.

## Attack/failure cases covered by new xUnit tests

- Valid signature and metadata-only immutable output
- Signed data tampering and wrong signing key
- Unknown issuer and mismatched issuer claim
- Cross-rule signer misuse and mismatched operation
- Expired and future-dated claims
- Exact replay of a previously consumed signed claim
- Invalid actor/session hashes and contradictory endpoints
- Duplicate/unknown JSON properties, including a raw-command field
- Truncated or malformed base64 signature/payload
- Rejection of weak key sizes, unrecognized rule scopes, and empty trust configuration
- Fail-closed R275/R295/R343 behavior even when a synthetic local test signer issues a correctly formed receipt without a real producer

The tests generate ephemeral local keys and do not mark any real operational outcome as verified.

## Operational constraints and subsequent work

1. **Trust provisioning**: establish an operator-controlled, revocable signer registry. Never ship private keys, test keys or broad wildcard trust in the repository or in user-editable configuration. Define rollover and revocation before live use. The in-memory duplicate-ID set is intentionally capped at 8,192; saturation fails closed. A production cache will need durable bounded idempotency and metrics.
2. **Real evidence producers**: connect authenticated Windows PowerShell/WinRM audit, Kubernetes API-server audit, and IdP audit via explicit vendor/OS authorization and integrity checks. Validate event signing identity and actual operation semantics before signing any claim. Distinguish executed, denied, attempted and authorized outcomes.
3. **Causal binding**: require a shared, authenticated local session/trace correlation ID and match it against the signed pseudonymous `TraceHash` field with unique actor/resource and time binding. Never derive that ID from an unverified HTTP query or packet Info. Do not join unrelated events solely by host/IP, timing or descriptive text.
4. **Rule ingestion**: connect verified, tightly bound receipts to rules as an opt-in dependency. Preserve `R343`, `R295`, `R275` NoMatch defaults until complete. R163 remains a metadata credential-path observation, not proof of SSRF.
5. **Accuracy and privacy**: add authenticated positive/negative/duplicate/reordered/spoofed tests, protect identifiers from export, and measure true positive / false positive alert-level behavior without lowering confidence floors. Do not substitute a synthetic signature for genuine external provenance.
6. **Certification**: run full Windows compilation and tests on CARTHAGE, then separate replay quality; do not change the four existing malicious replay labels or expected minimum confidence solely to obtain a green gate.

## Exact verification

```powershell
git fetch origin
git switch feature/carthago-reliability-hardening
git pull --ff-only
dotnet test .\Carthago.Tests\Carthago.Tests.csproj -c Release --filter "FullyQualifiedName~TrustedAuditReceiptVerifierTests"
.\verify-local.ps1 -Details -LiveOutput
```

The last verified checkpoint before this candidate was **4,797/4,797 xUnit passing** with four replay-expectation failures (R343, R295, R275, R163). The new verifier and tests remain **UNVERIFIED** until the next CARTHAGE run.
