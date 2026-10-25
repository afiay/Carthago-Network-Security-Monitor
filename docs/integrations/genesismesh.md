# GenesisMesh Integration Evaluation — Read-only Pilot

## Decision

**Defer production integration until Carthago's baseline recovery, incident durability,
live ETW/Npcap capture, and sustained-load acceptance have passed on Windows.**
GenesisMesh is a potential *trust-evidence provider*, not a replacement for Carthago's
packet capture, rule engine, host inventory or incident store.

This document records a candidate integration contract; it does not configure a
GenesisMesh Network Authority (NA), install an SDK or enable any enforcement.

## Relevant GenesisMesh capabilities

- Its Network Authority exposes signed trust, attestation, boundary, agreement,
  disclosure and data-usage evidence over HTTP.
- The documented `genesismesh-sdk-dotnet` targets .NET 8. Public `*/verify` calls do
  not require the operator's Ed25519 signing key. Privileged admin routes do.
- The documented unauthenticated verification rate limit is 60 requests/minute/IP
  by default. The pilot must cache results and use a local budget below this limit.
- Verification of caller-supplied signed evidence is **not** equivalent to discovering
  whether an arbitrary observed IP address is trusted. Mapping a Carthago host to a
  GenesisMesh sovereign/agent identity needs an independently validated binding.

Sources: [official .NET SDK](https://docs.genesismesh.org/sdk/dotnet/index.html),
[Trust API](https://docs.genesismesh.org/api/trust-http.html),
[Network Authority API](https://docs.genesismesh.org/reference/network-authority-api.html).

## Candidate boundary in Carthago

```text
Captured observation -> existing Carthago detection/correlation -> enrichment queue
                                                            |
                                                   Identity binding lookup
                                                            |
                                                ITrustEvidenceEnricher (read-only)
                                                            |
                                             Verified signed evidence + provenance
                                                            |
                                               Incident annotation and audit log
```

`ITrustEvidenceEnricher` should return `Verified`, `Rejected`, `Unknown` or
`Unavailable`, plus reason, issuer key identifier, evidence ID/digest, evidence
timestamp, source URL, evaluation timestamp, expiry and lookup duration. The
identity-binding result must be recorded independently of the evidence verdict.
An unavailable network, expired proof or missing identity binding must never be
represented as trusted or denied.

## Read-only pilot requirements

1. Configure a dedicated NA base URL via application settings; allowlist its
   hostname and enforce HTTPS for remote authorities. Allow local HTTP only for
   explicitly opted-in loopback development.
2. Store only trust metadata needed for investigation. Do not upload packet
   payloads, credentials, personal data or a full incident report to the NA.
3. Use a bounded asynchronous queue, short explicit timeouts, retries with jitter
   and a circuit breaker; never block capture, analytics persistence, or UI event
   delivery on a remote verification call.
4. Cache verification by evidence digest and configured issuer identity until
   its validity interval expires. Budget requests below the NA rate limit and
   surface throttling as `Unavailable` with a diagnostic reason.
5. Pin configured issuer public keys through a controlled trust process. Verify
   evidence signatures and validity windows; a successful HTTP 200 is not itself
   proof that a target is authorized.
6. Emit one structured enrichment event containing the host identity binding,
   verification outcome, provenance and latency. Avoid echoing key material in logs.
7. Display the outcome separately from Carthago's local risk score. No automatic
   device blocking, revocation, firewall changes or remote admin calls in the pilot.
8. Include tests with a fake NA for legitimate signatures, altered content,
   mismatched identities, expired/revoked evidence, missing keys, 429, timeout,
   malformed responses and network outage. Verify the capture queue still advances.

## Acceptance gates

| Gate | Required evidence before proceeding |
| --- | --- |
| G1 Core stability | Windows full test suite; crash/restart and baseline incident recovery |
| G2 Monitoring | ETW and optional Npcap: captured/displayed counters, loss, and UI checks |
| G3 Detection | Versioned replay dataset and measured false positives/negatives |
| G4 Performance | Reproducible sustained-load CPU, allocation, memory and queue-drop results |
| G5 Trust pilot | Read-only signature verification, identity binding, privacy and outage tests |

Do not promote a read-only enrichment signal into access-control policy without
a separate threat model, operator approval and recoverable rollout plan.
