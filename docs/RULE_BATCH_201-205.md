# R201-R205 — Typed Kubernetes, registry, Terraform and CI/CD evidence

**CANDIDATE / UNVERIFIED. 48 advanced xUnit facts authored; 0 executed.**

| Rule | Candidate production change | Advanced xUnit facts |
| --- | --- | ---: |
| R201 | Replace packet-Info/mounted-file claims with typed HTTP POST to the Kubernetes TokenRequest API, exact service-account path and Kubernetes service authority; preserve kubelet/component exclusions, bounded duplicate/out-of-order guard and redaction. | 10 |
| R202 | Require typed Docker Registry v2 manifest/blob request paths and methods to observed external destination; bound distinct-artifact windows by source/registry and packet ID; retain first-seen baseline gate and official-registry suppression. | 10 |
| R203 | Require valid 64-hex SHA256 blob digest and typed GET/HEAD; count independent distinct layers and observed bytes in the same bounded window without duplicate inflation; retain first-seen and official-registry gates. | 10 |
| R204 | Require typed HTTP request to external destination with anchored state-file basename, excluding documentation and query-only references; bounded replay/out-of-order guard, redact artifact path. | 9 |
| R205 | Require typed HTTP URL with exact CI/CD token parameter and non-placeholder value; reject packet-Info claims and parameter substrings, redact token-bearing URL, replay/out-of-order guard. | 9 |
| **Total** | **Five consecutive rules** | **48** |

**Production paths:** `Carthago/Engine/Rules/Expansion/R201_KubernetesServiceAccountTokenAccessRule.cs` through `R205_CiCdSecretTokenInUrlRule.cs`, new `NetworkBatch201205Evidence.cs` and `NetworkBatch201205Window.cs`, and scoped redaction in `HttpApiPrecisionDetectionRuleBase.cs`.

**Advanced tests:** `Carthago.Tests/R201AdvancedAccuracyBatchTests.cs` through `R205AdvancedAccuracyBatchTests.cs` plus `NetworkBatch201205Context.cs`. Existing `Carthago.Tests/CloudDevPrecisionRuleTests.cs` fixtures were statically aligned with a real Kubernetes TokenRequest POST and full SHA256 digest. Existing legacy test assertions were not removed or disabled.

**Candidate commits:** source `2d9e77f4145ae8010e553b6d15e8c15e1c041587`; provenance/replay correction `be66197f2fd135291d8e33046e22f781f4a17b3f`; advanced tests `5872d8fddfb0e5597106a14235743bded883b0f1`; legacy fixture/privacy correction `fa013568897f61215f29c482d3d00d151c67e17b`.

## Evidence and verification limitations

The unexecuted tests cover typed positives, close benign routes, forged packet-Info indicators, contradictory transport/Host, exact path and digest validation, duplicate packet IDs, independent sources, out-of-order observations, threshold and byte-volume boundaries, sensitive evidence redaction and configured confidence/default modes.

R201 can observe an HTTP TokenRequest API **request**, not a mounted-file read or issued service-account token. The stricter authority check may miss custom cluster API hostnames until their provenance is modeled explicitly. R202/R203 first-seen evidence depends on the existing baseline store and approval/readiness gates; synthetic registry traffic does not certify those gates. R203's `TrafficRecord.Length`/`L4Len` measures observed packet bytes, **not confirmed image-layer download success**; missing response-body attribution may reduce recall. R204 requests do not prove a Terraform state file was returned. R205 detects token-like URL values, not token validity or privilege.

No builds, xUnit, replay, benchmark, frozen holdout, CI or Windows runner executed. `scripts/verify-all-rule-batches.ps1` remains unchanged as the single deferred Windows verification entry point. Frozen R102 V1 remains FAILED at 4/6 and immutable; V2 awaits independent licensed PCAP and analyst review. Confidence floors R102=80%, R118=86%, R163=84%, all other configured thresholds/floors, Shadow/Disabled/Alert defaults, baseline-readiness/asset approvals and evidence privacy remain unchanged.

**R196-R205 combined: ten consecutive rules, 107 advanced xUnit facts authored, zero executed. All CANDIDATE / UNVERIFIED. Next R206-R210, then R211-R215.**
