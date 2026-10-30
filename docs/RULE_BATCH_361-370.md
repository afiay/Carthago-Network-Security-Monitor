# GA R361–R370 — DevOps request and token provenance

**CANDIDATE — UNVERIFIED.** Ten source implementations and authored tests; zero tests/builds/replays/holdouts/CI/runner/capture executed. HTTP request shape is not server identity, token issuance, credential validity, completed download, successful decryption, or proof of compromise.

## Rule dispositions and evidence limits

| Rule | Disposition | Evidence gate | Residual limitation |
| --- | --- | --- | --- |
| R361 GitHub Actions OIDC | **BLOCKED** | Fail closed: runtime-supplied runner URL is not authenticated runner audit. | No trusted runner/job producer; no positive fabricated. |
| R362 Runner registration token | **CONDITIONAL** | Parsed POST to exact GitHub repository/organization runner registration-token endpoint, exact api.github.com Host. | Request does not prove token issuance or runner registration; normal administration expected. |
| R363 CI artifact archive burst | **OPERATIONAL — request shape only** | Five distinct, ordered parsed GETs to numeric GitHub Actions artifact ZIP route. | No completed download or delivered-byte evidence; routine CI clients can trigger. |
| R364 AWS Secrets Manager enumeration | **CONDITIONAL** | Four distinct POSTs to regional Secrets Manager root, exact complete parser-owned X-Amz-Target ListSecrets observation. | Client Host/header do not prove AWS authentication or successful enumeration; normal HTTPS is opaque. |
| R365 HashiCorp Vault token in HTTP | **CONDITIONAL** | Parsed /v1/ request and unique complete X-Vault-Token with recognized token-shaped value. Parser redacts the header before retention. | No token validity or service identity; normal Vault API clients carry this header. |
| R366 Vault Transit decrypt burst | **OPERATIONAL — request shape only** | Five distinct ordered POSTs to /v1/transit/decrypt/{key}. | No proof of successful decrypt, identity or authorized key; normal crypto workloads can burst. |
| R367 Terraform Cloud token exposure | **CONDITIONAL** | Exact app.terraform.io Host and parser-owned Authorization atlasv1. prefix, secret bytes redacted. | No valid-token proof or decrypted HTTPS. |
| R368 Docker Hub pull storm | **OPERATIONAL — request shape only** | Ten distinct ordered GETs to registry-1.docker.io /v2/.../manifests or blobs exact terminal resource. | No completed pull, bytes or verified registry identity; mirrors and CI generate bursts. |
| R369 npm token exposure | **CONDITIONAL** | Exact registry.npmjs.org Host, parser-owned Authorization npm_ prefix, redacted. | No credential validity; normal package-client authentication and TLS limit recall. |
| R370 PyPI credential upload attempt | **CONDITIONAL** | External-boundary POST to upload.pypi.org/legacy/ with complete parser-owned Basic/Bearer authorization. | Only request attempt, not upload success or valid credential. |

Host headers are client-asserted, not authenticated server identity. No rule upgrades untrusted Info, JSON, SNI, arbitrary process strings, or generic descriptor text into trusted audit evidence. The bounded HTTP parser does not decrypt TLS.

## Source and privacy

- Added DevOpsRequestPrecisionEvidence with exact method/host/origin-form path gates and bounded source+destination+host burst duplicate/out-of-order guards. Original thresholds R363=5, R364=4, R366=5, R368=10 are unchanged.
- The HTTP parser now classifies complete AWS ListSecrets target, Vault hvs./hvb./s. token patterns, Terraform atlasv1., npm npm_, and PyPI Basic/Bearer authorization before redaction. Internal-set-only TrafficRecord flags cannot be asserted by imported JSON.
- X-Vault-Token is always redacted from retained HttpRequestHeaders, even on incomplete or duplicate headers. Existing Authorization redaction remains. Event http.path is redacted for R361–R370.
- Confidence floors, runtime modes, severities, configured thresholds, cooldowns, privacy, baseline readiness, approvals, and frozen holdout artifacts are unchanged.

## Authored advanced scenarios (NOT EXECUTED)

| Rule | xUnit facts | Cases |
| --- | ---: | --- |
| R361 | 6 | Runtime URL, provider Host, Info claims, spoofed environment header, TLS-only, spoofed host — all fail closed. |
| R362 | 10 | Repo/org registration POST, wrong path, TLS, UDP contradiction, absolute target, missing method, spoofed host, query redaction, profile invariants. |
| R363 | 11 | 4-below/5th-at-threshold, duplicate, out-of-order, nonnumeric artifact ID, wrong route, TLS, UDP, absolute target, missing method, spoofed host, profile. |
| R364 | 11 | 3-below/4th-at-threshold, duplicate, out-of-order, wrong route, missing parser flag, TLS, UDP, absolute target, missing method, spoofed host, profile. |
| R365 | 9 | Vault token parser flag, missing flag, wrong path, TLS, UDP, absolute target, missing method, event redaction, profile. |
| R366 | 9 | 4-below/5th-at-threshold, duplicate, out-of-order, wrong route, TLS, UDP, absolute target, missing method, profile. |
| R367 | 10 | Terraform token parser flag, missing flag, wrong provider, TLS, UDP, absolute target, missing method, spoofed host, event redaction, profile. |
| R368 | 11 | 9-below/10th-at-threshold, duplicate, out-of-order, trailing route, wrong route, TLS, UDP, absolute target, missing method, spoofed host, profile. |
| R369 | 10 | npm token parser flag, missing flag, wrong provider, TLS, UDP, absolute target, missing method, spoofed host, event redaction, profile. |
| R370 | 10 | PyPI authorization flag, missing flag, wrong path, TLS, UDP, absolute target, missing method, spoofed host, event redaction, profile. |

**97 advanced xUnit facts + 13 parser/privacy invocations = 110 authored, ZERO executed.** Parser/privacy tests cover three Vault token prefixes, incomplete/duplicate header redaction, Terraform/npm token classification, AWS target exactness/duplicates, PyPI authorization and JSON non-importability.

## Outstanding quality GAs

1. Owner-authorized Windows build and consolidated regression/replay/holdout verification at a pinned SHA. Source changes are not passing tests or field precision.
2. Real cleartext parser reachability, client-to-server attribution, duplicate/retransmission and redaction validation.
3. Authenticated GitHub runner, AWS CloudTrail and secret-management operation outcomes for any future claims beyond request shape.
4. Separate R343/R295/R275/R163 replay expectations; R102 frozen V1 FAILED 4/6, V2 0/4 independently approved sources. No changes to confidence floors or frozen samples.

**Next contiguous batch after safe publication: R371–R380.**
