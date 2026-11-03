# R196-R200 — Typed NXDOMAIN, rebinding and cloud metadata request attribution

**CANDIDATE / UNVERIFIED. 59 advanced xUnit facts authored; 0 executed.**

| Rule | Candidate source improvement | Individually authored advanced facts |
| --- | --- | ---: |
| R196 | Require parsed DNS response, NXDOMAIN code and resolver source-port attribution; bounded per-instance client/resolver windows counting distinct registrable roots, rejecting duplicate IDs and out-of-order observations; redact queried names. | 10 |
| R197 | Require parsed A/AAAA DNS response with answer metadata and valid transport; retain low-TTL, loopback and mixed public/private evidence alternatives; reject duplicate IDs; redact private addresses and names. | 10 |
| R198 | Require cleartext HTTP GET to observed link-local AWS IMDS socket, exact role-credential path and coherent Host header; preserve known-agent exclusions; replay guard and path redaction. | 13 |
| R199 | Require cleartext HTTP GET to observed link-local GCP IMDS socket, exact service-account token/identity route, Metadata-Flavor header and Host consistency; preserve guest-agent exclusions and redaction. | 13 |
| R200 | Require cleartext HTTP GET to observed link-local Azure IMDS socket, exact identity-token route, Metadata:true and nonempty api-version plus resource/scope query; preserve agent exclusions and redaction. | 13 |
| **Total** | **Five consecutive rules** | **59** |

**Source paths:** `Carthago/Engine/Rules/Expansion/R196_NxdomainUniqueRootSpikeRule.cs` through `R200_AzureMetadataCredentialRetrievalRule.cs`; new `Carthago/Engine/Rules/Expansion/NetworkBatch196200Evidence.cs`; existing bounded window `NetworkBatch181185Window.cs`; scoped redaction in `Carthago/Engine/Rules/Dns/DnsPrecisionDetectionRuleBase.cs` and `Carthago/Engine/Rules/Expansion/HttpApiPrecisionDetectionRuleBase.cs`.

**Test paths:** `Carthago.Tests/R196AdvancedAccuracyBatchTests.cs` through `R200AdvancedAccuracyBatchTests.cs` and `Carthago.Tests/NetworkBatch196200Context.cs`.

**Candidate commits (not yet acceptance evidence):** source `024d554e64403119277fa82eb507d6ca1a2b2d73`, authored tests `0df0a523b90265bc0bee88ae9b2296ec2ac5b4c8`, import correction `dd3086dfe0603b6750d52f759b9cec7a1b1ccd72`, metadata-agent/transport correction `511ce9e560ccdbb944a47649927f33e65fac2e4c`.

## Test intent and evidence boundaries

The unexecuted cases exercise positives, close benign paths and split-horizon answers, query-vs-response and HTTP-vs-DNS contradictions, packet-Info spoofing, duplicate IDs, source/resolver partitioning, out-of-order timestamps, evidence redaction, configured confidence floors and Shadow/Alert defaults. Metadata cases also exercise approved guest-agent suppression, forged Host headers, unrelated external destinations, wrong HTTP methods, and contradictory TLS attribution.

**Known limits:** The inspected live `PacketHandler` DNS parse paths do not currently populate `DnsAnswers` or `DnsTtl`. Consequently R197's positive answer/TTL tests are **synthetic schema-contract tests only**, not evidence that live packet capture can emit this detection. R196 also depends on actual parsed DNS response/rcode direction and transport metadata; adapter mapping remains unverified. Metadata request rules can only establish a request for a credential endpoint, **not a successful credential retrieval, response body, or downstream cloud compromise**. The strict link-local and cleartext requirements may lower recall on partial/translated telemetry. Enterprise cloud guest-agent inventories remain necessary.

No builds, xUnit, development replay, benchmark, frozen holdout, CI, Windows runner or other tests were executed. `scripts/verify-all-rule-batches.ps1` remains the single deferred Windows verifier, unchanged. No frozen holdout or labels were touched. R102 V1 holdout remains **FAILED at 4/6**; V2 is **PENDING** independently licensed PCAP and analyst review. Confidence floors R102=80%, R118=86%, R163=84%, all other configured floors, thresholds, Shadow/Disabled/Alert defaults, approvals and baseline-readiness gates remain unchanged.

**Next consecutive subbatch: R201-R205, then R206-R210.**
