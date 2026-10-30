# GA R381–R390 — Azure, GCP and tunnel-provider request provenance

**SOURCE CANDIDATE — UNVERIFIED · 2026-10-30.** Existing branch:
`feature/carthago-reliability-hardening`. Inspected live base HEAD:
`5ac74dcf3e8d5555b33e40e5ce271a78c23262a4`.
Granular unpublished candidate source:
`8b7a7ce717926a10f6286d358fe964485fd97ada`;
authored-test candidate:
`5c654b8433f164926fe7350c8e1ec7f63310aea6`.
Final publication, if authorized by the expected-HEAD lease, is the
documentation descendant at the feature branch HEAD. Do not treat this
candidate as a verified build or validated detection.

## Evidence boundary and static divergence review

The only applicable capture producer is
[PacketHandler](../Carthago/Services/PacketHandler.cs) with the bounded
cleartext HTTP parser. Its [TrafficRecord](../Carthago/Models/TrafficRecord.cs)
can hold parsed HTTP method, origin-form request target and a **client-supplied**
Host. It does not authenticate cloud identity or audit, decrypt HTTPS, prove
server responses, validate access grants, provide token-issuance bodies,
track response object bytes, or attest local tunnel-agent commands.
The existing
[CloudDevPrecisionDetectionRuleBase](../Carthago/Engine/Rules/Expansion/CloudDevPrecisionDetectionRuleBase.cs)
and [EvidenceDrivenPrecisionRuleBase](../Carthago/Engine/Rules/Expansion/EvidenceDrivenPrecisionRuleBase.cs)
still enforce original profiles. The new
[CloudProviderRequestEvidence](../Carthago/Engine/Rules/Expansion/CloudProviderRequestEvidence.cs)
reuses the existing bounded origin-target and request-ID guards; it does not
parse credentials, reconstruct TLS, or synthesize cloud audit events.

**Start/end GA divergence check (source-only):** Existing rule IDs/classes,
severity, minimum confidence 82, Alert mode, original windows, burst
thresholds, cooldowns, cross-boundary gates, approvals, runtime modes,
privacy controls, and R102/R118/R163 floors were not intentionally changed.
R382 and R388 narrowed their generic text/process/token indicators to
specific HTTP method, Host and path shapes and now require HTTP.
No UI, models, services, runner, tests outside this batch, holdout, settings,
journal, or CI files were changed. Actual build and runtime compatibility
remain unverified until the owner authorizes execution.

## Rule-by-rule disposition and original policy

| Rule | Evidence and disposition | Original severity; threshold / window / cooldown | Legitimate-traffic and missing-evidence risk |
| --- | --- | --- | --- |
| R381 Azure ARM Token Request Burst | **BLOCKED:** no parsed OAuth token request body or trusted Azure audit; generic login host cannot prove ARM token issuance. | Critical; 4 / 10m / 30m | Normal deployment/identity traffic; TLS opaque. |
| R382 Azure KeyVault Secret Enumeration | **CONDITIONAL:** four distinct cleartext `GET /secrets?api-version=<safe version>` requests within 10m to a vault-specific `*.vault.azure.net` Host, not successful listing or exfiltration. | Critical; 4 / 10m / 30m | Legitimate inventory, paging, retries; spoofed client Host, no server authentication. |
| R383 Azure Storage SAS Token In URL | **BLOCKED:** no parser-owned, pre-retention SAS query classification; avoid retaining signatures. | Critical; 1 / 15m / 30m | Legitimate presigned access, sensitive query bytes. |
| R384 Azure IMDS Token Request | **BLOCKED:** link-local metadata traffic conflicts with original cross-boundary gate; no trusted IMDS header/token outcome. | Critical; 1 / 15m / 30m | Normal Azure VM initialization; boundary policy needs separate GA. |
| R385 GCP OAuth Scope Broad Request | **BLOCKED:** no safe parsed OAuth form-body scope producer or authenticated consent/audit. | High; 1 / 15m / 30m | Legitimate `cloud-platform` grants, TLS opaque. |
| R386 GCP Storage Signed URL Mass Access | **BLOCKED:** no safe signed-query classifier, request/response correlation or distinct completed accesses. | High; 4 / 10m / 30m | CDN, downloads, backups, signed query privacy. |
| R387 GCP ServiceAccount Key Download | **BLOCKED:** no authenticated key-operation outcome or response bytes; packet length is not a downloaded private key. Original 25MiB minimum unchanged. | Critical; 1 / 15m / 30m | Administrative key management, API errors; response semantics absent. |
| R388 Cloudflare Tunnel Creation Indicator | **CONDITIONAL:** exact cleartext `POST /client/v4/accounts/<32-hex-id>/cfd_tunnel` with `api.cloudflare.com` Host; **request shape only**, not authenticated tunnel creation. | High; 1 / 15m / 30m | Approved Zero Trust provisioning, Host spoofing; production API typically HTTPS. |
| R389 Ngrok Tunnel Creation Or Auth | **BLOCKED:** no authenticated ngrok agent API or token/creation outcome; local agent traffic conflicts with cross-boundary requirement. | High; 1 / 15m / 30m | Approved developer tunnels, TLS opaque. |
| R390 Tailscale Tailnet Auth Indicator | **BLOCKED:** no authenticated tailnet control-plane event or successful device registration producer. | Medium; 1 / 15m / 30m | Routine device login and reconnects; TLS opaque. |

**No rule proves malicious intent or a successful cloud operation.**
R382/R388 are eligible request shapes only. R382 uses original four-in-ten
minute scoring, bounded distinct packet IDs and monotonic observation times;
this is **not** HTTP transaction-level deduplication. R388 uses the original
one-in-fifteen-minute threshold. The original 30-minute cooldowns, all modes,
approvals and confidence floors remain intact.

## Source and privacy changes

- Ten existing classes:
  [R381](../Carthago/Engine/Rules/Expansion/R381_AzureARMTokenRequestBurstRule.cs),
  [R382](../Carthago/Engine/Rules/Expansion/R382_AzureKeyVaultSecretEnumerationRule.cs),
  [R383](../Carthago/Engine/Rules/Expansion/R383_AzureStorageSASTokenInURLRule.cs),
  [R384](../Carthago/Engine/Rules/Expansion/R384_AzureIMDSTokenRequestRule.cs),
  [R385](../Carthago/Engine/Rules/Expansion/R385_GCPOAuthScopeBroadRequestRule.cs),
  [R386](../Carthago/Engine/Rules/Expansion/R386_GCPStorageSignedURLMassAccessRule.cs),
  [R387](../Carthago/Engine/Rules/Expansion/R387_GCPServiceAccountKeyDownloadRule.cs),
  [R388](../Carthago/Engine/Rules/Expansion/R388_CloudflareTunnelCreationIndicatorRule.cs),
  [R389](../Carthago/Engine/Rules/Expansion/R389_NgrokTunnelCreationOrAuthRule.cs),
  [R390](../Carthago/Engine/Rules/Expansion/R390_TailscaleTailnetAuthIndicatorRule.cs).
- Added `CloudProviderRequestEvidence.cs` with exact method/host/path,
  bounded API-version query validation and fail-closed missing-producer codes.
  The version query is read for a strict shape check, never used as evidence.
- Narrowed R382 and R388 generic indicators to concrete request attributes.
  No new dependencies, telemetry producers, credential extraction, model
  setters or audit trust claims.
- Added R381–R390 event redaction for `http.path`, `clouddev.host`,
  `network.bestHost` and `DestinationHost`. This does **not** prove
  upstream raw capture/Info, external logging or exports cannot retain
  sensitive query values; those paths need separate privacy review.

## Authored xUnit inventory — ZERO EXECUTED

Source:
[NetworkBatch381390AccuracyTests.cs](../Carthago.Tests/NetworkBatch381390AccuracyTests.cs).
Counts are xUnit invocations/theory rows, not passing tests. A static
source review only was performed; no `dotnet`, build, xUnit, replay, CI,
runner, benchmark, holdout or production capture was invoked.

| Rule | Authored invocations | Exact scenario inventory |
| --- | ---: | --- |
| R381 | 8 | Plausible Azure OAuth request, descriptor spoof, TLS-only, wrong Host, missing source, synthetic secret query, fake audit header, original profile. |
| R382 | 16 | Three below/fourth at threshold; duplicate packet ID; out-of-order replay; wrong method; individual secret GET; management host; suffix-spoof Host; TLS-only; UDP; absolute-form URL; injected query; missing api-version; descriptor spoof; missing source; redacted event evidence; original profile. |
| R383 | 8 | SAS-shaped URL, descriptor spoof, TLS-only, wrong Host, missing source, synthetic secret query, fake audit header, original profile. |
| R384 | 8 | Link-local metadata token request, descriptor spoof, TLS-only, wrong Host, missing source, synthetic secret query, fake audit header, original profile. |
| R385 | 8 | GCP OAuth request, descriptor spoof, TLS-only, wrong Host, missing source, synthetic secret query, fake audit header, original profile. |
| R386 | 8 | GCP signed URL, descriptor spoof, TLS-only, wrong Host, missing source, synthetic secret query, fake audit header, original profile. |
| R387 | 8 | GCP service-account key route, descriptor spoof, TLS-only, wrong Host, missing source, synthetic secret query, fake audit header, original profile. |
| R388 | 14 | Exact create POST; list GET; wrong route; wrong Host; suffix-spoof Host; TLS-only; UDP; absolute-form URL; synthetic secret query; invalid account ID; descriptor spoof; missing source; redacted account path; original profile. |
| R389 | 8 | Ngrok tunnel request, descriptor spoof, TLS-only, wrong Host, missing source, synthetic secret query, fake audit header, original profile. |
| R390 | 8 | Tailscale auth-shaped request, descriptor spoof, TLS-only, wrong Host, missing source, synthetic secret query, fake audit header, original profile. |
| **Total** | **94 AUTHORED** | **0 EXECUTED; all SOURCE CANDIDATE — UNVERIFIED.** |

## Outstanding quality GAs

1. Owner-authorized Windows compile, consolidated xUnit and replay/holdout
   verification at a pinned SHA. The earlier 4,940/4,940 result **predates**
   this and previous candidate batches.
2. Packet-level parser reachability and attribution; HTTPS request content
   cannot be assumed visible. Request IDs do not guarantee transaction
   uniqueness; the burst window is not a proven successful operation count.
3. Real trusted Azure/GCP/Cloudflare audit/response producers before any
   success, abuse, key download, consent or tunnel-creation outcome claim.
4. Full upstream query/Info/diagnostic privacy audit. No token or secret bytes
   were added to rule evidence by this GA.
5. Independent replay GAs R343/R295/R275/R163; frozen R102 V1
   **FAILED 4/6** and V2 **0/4 approved sources**, with confidence floors
   R102 80%, R118 86%, R163 84%, external R102 0.75 unchanged.

**Next contiguous ten-rule development GA: R391–R400**, only after this
source/test/docs candidate is published atomically and live HEAD rechecked.

## Authoritative request-contract references

- [Azure Key Vault — List Secrets REST API](https://learn.microsoft.com/en-us/rest/api/keyvault/secrets/get-secrets/get-secrets)
  — GET `/secrets` requires an `api-version` query and permission;
  HTTP request alone is not proof of a successful list.
- [Cloudflare API — Create a Cloudflare Tunnel](https://developers.cloudflare.com/api/resources/zero_trust/subresources/tunnels/subresources/cloudflared/methods/create/)
  — POST `/accounts/{account_id}/cfd_tunnel` with API authentication;
  request shape is not tunnel creation or a running connector.
- [Microsoft C# identifier naming](https://learn.microsoft.com/en-us/dotnet/csharp/fundamentals/coding-style/identifier-names)
  — existing public rule identifiers and serialized contracts retained.
