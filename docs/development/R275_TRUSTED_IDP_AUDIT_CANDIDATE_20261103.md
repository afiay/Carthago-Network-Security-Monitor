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
  --filter "FullyQualifiedName~MicrosoftEntraDeviceFlowClaimMaterialBuilderTests|FullyQualifiedName~MicrosoftEntraLogAnalyticsDeviceCodeSourceTests|FullyQualifiedName~MicrosoftEntraDeviceCodeAuditIntakeTests|FullyQualifiedName~OAuthDeviceFlowAuditCandidateGateTests|FullyQualifiedName~R275AdvancedAccuracyBatchTests|FullyQualifiedName~R275R343R485PairedReplayTests"
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

## 2026-11-03 focused owner verification — GREEN

The owner ran the documented focused test command at branch revision `5f95521611e1549cd89c20d6149ea71fc7e75b36`.

Observed result:
- build succeeded for `Carthago` and `Carthago.Tests`;
- **56 tests passed**;
- **0 failed**;
- **0 skipped**.

The GREEN scope covers:
- `MicrosoftEntraDeviceCodeAuditIntakeTests`;
- `OAuthDeviceFlowAuditCandidateGateTests`;
- existing `R275AdvancedAccuracyBatchTests`;
- existing `R275R343R485PairedReplayTests`.

This closes the synthetic source-candidate verification for the current R275 increment. The parser/candidate boundary is now test-verified but remains non-alerting and not connected to the live rule engine.

R275 still intentionally returns `TRUSTED_DEVICE_CODE_ABUSE_EVENT_UNAVAILABLE` through ordinary packet evaluation. A future live Entra producer must authenticate its source independently and must not convert raw provider JSON, OAuth codes, SNI or packet text directly into trusted rule evidence.


## Authenticated Azure Monitor Logs source

The next source layer is now authored:

- `Carthago/Services/TrustedAudit/MicrosoftEntraLogAnalyticsDeviceCodeSource.cs`
- `Carthago.Tests/MicrosoftEntraLogAnalyticsDeviceCodeSourceTests.cs`

This adapter queries one operator-configured Log Analytics workspace through the Microsoft Entra-authenticated Azure Monitor Logs data-plane endpoint:

`POST https://api.loganalytics.azure.com/v1/workspaces/{workspaceId}/query`

It requests the Log Analytics OAuth scope:

`https://api.loganalytics.io/.default`

No tenant ID, client ID, client secret, certificate, managed-identity identifier, access token, or workspace ID is committed to the repository. The adapter receives a `TokenCredential`, `HttpClient`, and workspace GUID from the host application.

The KQL is fixed inside CARTHAGO and cannot be supplied by a caller. It selects only successful `deviceCode` sign-ins whose Entra risk state is `confirmedCompromised` with `adminConfirmedSigninCompromised`, projects only the already-reviewed R275 fields, orders by newest `CreatedDateTime`, and caps the result at 100 rows.

The query lookback is bounded to 1–60 minutes. HTTP failures are converted to stable sanitized reason codes; response payloads are capped at 1 MiB; the returned table schema must exactly match the expected projection; more than 100 rows, malformed cells, schema drift, and rows that fail the strict Entra parser are rejected fail-closed.

A row accepted from this authenticated source is re-created as a `MicrosoftEntraDeviceCodeAuditObservation` with `FromTrustedProviderTransport=true`. This proves only that CARTHAGO obtained the row through an authenticated Azure Monitor Logs API call using the configured credential. It still does not sign an R275 audit receipt, prove the human phishing label, or authorize an alert.

Microsoft references used:
- https://learn.microsoft.com/en-us/azure/azure-monitor/logs/api/request-format
- https://learn.microsoft.com/en-us/azure/azure-monitor/logs/api/access-api
- https://learn.microsoft.com/en-us/azure/azure-monitor/logs/api/overview
- https://learn.microsoft.com/en-us/azure/azure-monitor/reference/tables/signinlogs

**Status:** SOURCE CANDIDATE — UNVERIFIED until the updated focused R275 test command is executed.

## 2026-11-03 authenticated source focused verification — GREEN

The owner pulled revision `9c0d11ad7971a9f6b272611cc870abcea74217f6` and ran the expanded focused R275 suite containing the Azure Monitor Logs source-adapter tests, strict Entra parser tests, signed candidate-gate tests, existing R275 advanced accuracy controls and paired replay.

Observed:
- `Carthago` build succeeded;
- `Carthago.Tests` build succeeded;
- **66 tests passed**;
- **0 failed**;
- **0 skipped**;
- focused xUnit duration **15.2 seconds**.

The authenticated source increment is therefore **GREEN at the contract-test level**. The current source adapter correctly remains configuration-injected and non-alerting; it has not been exercised against a live tenant or workspace in this evidence record.

The next engineering boundary is no longer HTTP/query parsing. It is the trusted producer handoff: converting an authenticated, privacy-minimized Entra observation into a separately signed R275 audit claim without placing signing keys or ambient trust inside the packet/rule process. That handoff must preserve replay protection, independent signer requirements and the current `TRUSTED_DEVICE_CODE_ABUSE_EVENT_UNAVAILABLE` behavior until explicitly wired and tested.


## Authenticated Entra-to-packet claim material boundary

A further non-signing boundary is now authored:

- `Carthago/Services/TrustedAudit/MicrosoftEntraDeviceFlowClaimMaterialBuilder.cs`
- `Carthago.Tests/MicrosoftEntraDeviceFlowClaimMaterialBuilderTests.cs`

This layer exists because Microsoft Entra `SigninLogs` identifies the client/source IP but does not supply a trustworthy IdP destination IP suitable for CARTHAGO's generic signed `AuditClaim`. The implementation does **not** invent or infer that destination.

Instead, one observation that already has `FromTrustedProviderTransport=true` must be correlated with one independently captured identity web flow. The captured flow must be TCP/443 with HTTP/HTTPS/TLS application context, a valid client and destination IP, exact client/source IP equality with the Entra observation, a maximum two-minute UTC time difference, and an identity host that matches an explicit operator-approved host policy.

The IdP destination IP is taken only from the captured packet record. The resulting `MicrosoftEntraDeviceFlowClaimMaterial` carries privacy-minimized source/destination IPs, actor/resource/trace hashes, UTC time and the reviewed identity host. It is deliberately unsigned and cannot become a `VerifiedAuditReceipt`.

Host matching uses exact names or proper subdomains of configured hosts; lookalikes such as `login.microsoftonline.com.attacker.test` fail closed. Arbitrary TCP/443 application contexts also fail closed.

**Status:** SOURCE CANDIDATE — UNVERIFIED. This boundary has not yet been executed in the owner test environment.
