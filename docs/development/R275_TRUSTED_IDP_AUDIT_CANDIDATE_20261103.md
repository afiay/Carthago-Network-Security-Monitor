# R275 trusted IdP audit candidate boundary — 2026-11-03

**Status:** SOURCE CANDIDATE — UNVERIFIED

## Purpose

R275 currently fails closed because packet-visible OAuth device-code initiation is not proof of phishing. This increment adds a narrow, non-alerting trust boundary for a future IdP producer without weakening the existing rule.

The implementation reuses CARTHAGO's existing trusted-audit primitives:

- operator-pinned RSA-PSS/SHA-256 public keys;
- strict rule/operation scoping;
- freshness checks and bounded replay protection;
- two independently configured issuers;
- exact actor/resource/trace correlation;
- no raw OAuth code, bearer token, JWT or provider secret in the signed claim.

The accepted R275 audit operation remains:

`OAuthDeviceFlowAbuseConfirmed`

## New source surfaces

- `Carthago/Services/TrustedAudit/OAuthDeviceFlowSignedAuditCandidateIntake.cs`
- `Carthago/Services/TrustedAudit/OAuthDeviceFlowAuditCandidateGate.cs`
- `Carthago.Tests/OAuthDeviceFlowAuditCandidateGateTests.cs`

No `TrafficRecord` trusted flag, ambient singleton, listener, private signing key, IdP credential or rule-engine injection was added.

## Trust model

The intake accepts two `SignedAuditEnvelope` values only through `TrustedAuditReceiptVerifier`. Both receipts must then pass `TrustedAuditReceiptCorrelation`.

A correlated pair must:

1. belong to R275;
2. attest the exact `OAuthDeviceFlowAbuseConfirmed` operation;
3. come from distinct pinned issuers under the same trust-registry instance;
4. bind the same privacy-minimized actor/resource/trace hashes;
5. bind the same source/destination endpoints;
6. be fresh and non-replayed.

The candidate gate independently requires one captured outbound identity-web flow:

- TCP;
- destination port 443;
- valid source and destination IPs;
- HTTP/HTTPS/TLS application context;
- a non-empty observed SNI/TLS-SNI/HTTP host;
- packet endpoints equal to both signed audit receipts;
- packet timestamp within two minutes of both signed audit receipts;
- UTC timestamp input.

These checks provide packet corroboration only. They do not establish user intent or authorize a detection.

## Fail-closed result

Even after every signature, correlation and packet-binding check succeeds, the result is:

`R275_SIGNED_IDP_AUDIT_CANDIDATE_NOT_INTEGRATED`

and `AlertPermitted` is always `false`.

R275 itself remains unchanged and continues to return:

`TRUSTED_DEVICE_CODE_ABUSE_EVENT_UNAVAILABLE`

through the normal rule engine, because `RuleEvaluationContext` does not carry trusted-audit capabilities. A signed audit receipt is deliberately not copied into `TrafficRecord`.

## Focused synthetic tests authored

The new tests cover:

- two independent signed issuers producing only a non-alerting candidate;
- missing packet corroboration;
- arbitrary TCP/443 without identity-web context;
- endpoint mismatch;
- strict two-minute UTC time binding;
- wrong-rule receipt reuse;
- replay rejection;
- missing corroborating receipt;
- forged signer rejection;
- one signer attempting to corroborate itself;
- explicit proof that the candidate path still cannot promote R275.

The tests use synthetic RSA keys and synthetic metadata only. They do not contact Microsoft Entra, another IdP, or any live tenant.

## Verification command

During owner-authorized test time:

```powershell
dotnet test .\Carthago.Tests\Carthago.Tests.csproj `
  -c Release `
  --filter "FullyQualifiedName~MicrosoftEntraDeviceCodeAuditIntakeTests|FullyQualifiedName~OAuthDeviceFlowAuditCandidateGateTests|FullyQualifiedName~R275AdvancedAccuracyBatchTests|FullyQualifiedName~R275R343R485PairedReplayTests"
```

Do not mark this increment GREEN until the focused tests complete successfully on CARTHAGE.

## Next integration boundary

A real IdP producer remains separate work. It must authenticate to its provider using operator-controlled configuration, validate a provider-specific event indicating confirmed device-flow abuse, normalize only privacy-minimized metadata into the existing `AuditClaim`, and sign it outside the packet/replay path.

Raw provider JSON, query parameters such as `user_code` or `device_code`, HTTP request text, SNI, or a caller-supplied `trusted=true` field must never create a signed receipt.

Only after that producer is independently reviewed and tested should a separate design decide how a verified R275 capability reaches rule evaluation. That future integration must preserve the current packet-only negatives and must not lower R275's confidence or policy safeguards.


## Microsoft Entra SigninLogs projection

A provider-facing parser is now also authored:

- `Carthago/Services/TrustedAudit/MicrosoftEntraDeviceCodeAuditIntake.cs`
- `Carthago.Tests/MicrosoftEntraDeviceCodeAuditIntakeTests.cs`

It consumes a deliberately narrow Azure Monitor `SigninLogs` projection rather than a full raw row. The exact accepted fields are:

`Type`, `Id`, `CreatedDateTime`, `AuthenticationProtocol`, `ResultType`,
`RiskState`, `RiskDetail`, `IPAddress`, `UserId`, `AppId`, `ResourceId`,
`HomeTenantId`, and `ResourceTenantId`.

The parser recognizes a candidate only when:

- `Type == "SigninLogs"`;
- `AuthenticationProtocol == "deviceCode"`;
- `ResultType == "0"` (successful sign-in);
- `RiskState == "confirmedCompromised"`;
- `RiskDetail == "adminConfirmedSigninCompromised"`;
- the client IP is valid and non-loopback;
- sign-in/user/app/resource/tenant identifiers are valid GUIDs;
- `CreatedDateTime` carries an explicit UTC time.

Raw user/app/resource identifiers are hashed before leaving the parser. The observation retains only UTC time, source IP, actor hash, resource hash, trace hash, and `FromTrustedProviderTransport=false`.

Extra fields such as `UserPrincipalName`, `UserDisplayName`, token identifiers, raw authentication details, or OAuth/device-code material are rejected instead of being silently ignored.

The parser is intentionally **unsigned and untrusted**. It does not call Microsoft APIs, hold tenant credentials, or assert that caller-supplied JSON came from Entra. A future authenticated collector must establish provider transport provenance before any R275 signing step.

Microsoft schema references used for this contract:
- https://learn.microsoft.com/en-us/azure/azure-monitor/reference/tables/signinlogs
- https://learn.microsoft.com/en-us/entra/identity/conditional-access/concept-authentication-flows
