# R151-R155 HTTP/2, TLS ASN fan-out and API enumeration precision

**CANDIDATE - UNVERIFIED (2026-10-27).** Authored five detection
implementations, one shared HTTP/ASN evidence contract, a narrowly
scoped shared HTTP evidence redaction, five eight-case advanced test
classes and one shared fixture. **40 xUnit facts authored; zero executed.**
No builds, xUnit, development replay, synthetic holdout, GitHub Actions
or Windows runner jobs were executed.

| Rule | Candidate precision changes | Eight authored advanced cases |
| --- | --- | --- |
| R151 | Require a parser-attributed TLS/TCP session with explicit `Alpn=h2`, external destination IP and original uncommon destination port; browser-like clients remain suppressed. Packet Info, HTTP/2 words and unverified hostnames alone do not qualify. | h2 positive, ordinary port, http/1.1 ALPN, packet Info h2, browser, internal socket, QUIC/UDP, Shadow/floor. |
| R152 | Require typed TLS/TCP, actual JA3/JA4, external destination socket and normalized valid ASN enrichment. Count distinct ASNs only from independent records by one source + fingerprint in a bounded per-instance window, rejecting duplicate record IDs and invalid ASN labels. | Five-ASN positive, same ASN, duplicate ID, source isolation, invalid ASN, browser, internal/UDP, Candidate/Shadow threshold/floor. |
| R153 | Require typed HTTP request, explicit GraphQL endpoint, cross-boundary source/target, and an actual introspection GET query/operationName parameter. No introspection inference from packet Info, arbitrary headers or path tokens. | Introspection positive, ordinary query, Info-only, path-only, internal/internal, missing TCP, query-secret redaction, Shadow/floor. |
| R154 | Require attributed GraphQL POST and bounded explicit batching marker (X-Graphql-Batch header or explicit batch-array summary), then five independent source/endpoint observations in a per-instance bounded replay-resistant window. | Five positives, duplicate ID, source isolation, generic operationName, GET, unrelated API path, UDP, Shadow/threshold/floor. |
| R155 | Require typed cross-boundary HTTP GET/HEAD/OPTIONS, API resource path and six distinct paths in a bounded source+destination+host window, not six query-string variations. Reject client replays and outbound browser traffic; redact resource paths. | Six-resource positive, replay ID, query-only variance, outbound browser, same network boundary, destination isolation, POST, privacy/Shadow/floor. |

## Evidence contracts and limitations

- `NetworkBatch151155Evidence.HttpRequest` uses the existing strict
  parser contract for GET/POST/PUT/PATCH, with a similarly attributed
  HEAD/OPTIONS path to preserve those existing detection use cases.
- R153 recognizes only observable GraphQL GET parameters in the current
  schema; the model has **no typed GraphQL request body field**.
  A body-only introspection attack remains outside reliable detection.
- R154 allows the existing explicit batch-array packet summary format
  solely as a bounded **untrusted metadata marker**, not proof of parsed
  GraphQL body contents or malicious intent.
- R155 counts distinct normalized *resource paths*, not query values,
  and does not infer enumeration from a single request or a port number.
- The shared `MatchHttpApi` builder redacts raw `http.path` **only**
  for R153, R154 and R155. Their rule-owned evidence supplies fixed
  categories; raw request paths can contain access tokens or personal
  identifiers and must not be persisted via these rules.
- R152 ASN data remains enrichment, not independently verified routing
  telemetry. ASN attribution may lag or refer to a shared hosting provider.
  Distinct ASN counts are candidate indicators requiring external review.
- R152 uses the `NetworkBatch146152AsnWindow` bounded source-scoped
  state; R154 uses `NetworkBatch141145Window`; R155 uses a bounded
  per-instance unique-path/packet-ID window. Concurrency, out-of-order
  and legitimate high-volume API activity require subsequent runtime tests.
- Existing thresholds R151=1, R152=5, R153=1, R154=5, R155=6,
  confidence minimums, Shadow modes, baseline approvals, privacy and
  frozen synthetic holdout inputs were not changed.

## Published candidate scope

Source commit `3faabf8577416865bd934077764b8d8d428cb540`
and test commit `05ccac85e793126dd8ae69dae9cb405e1cc11049`.
The single deferred Windows gate
`scripts/verify-all-rule-batches.ps1` discovers R146-R155 automatically;
it has not been executed after these commits.

The frozen V1 R102 holdout remains **FAILED at 4/6**.
The separately versioned V2 remains pending independent, licensed,
reviewed PCAPs and new explicit approval. No frozen sample or label
has been changed.

**Next batch after this 10-rule manual session: R156-R160.**
