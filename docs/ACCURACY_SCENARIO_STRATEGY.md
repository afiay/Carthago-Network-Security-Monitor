# Accuracy-first validation: R102, R118 and R163

Status: **candidate changes, pending clean Windows verification**. The changes do not certify production precision, recall, false-positive rate, or live delivery. Do not change profile modes or lower rule-specific confidence floors just to raise a score.

## What is being exercised?

The `Carthago.Tests/AccuracyScenarioMatrixTests.cs` suite contains **200 separately parameterized synthetic test cases**:

| Rule family | Synthetic cases | Variations | Positive/negative meaning |
| --- | ---: | --- | --- |
| R118: default Basic authentication | 144 | Six IoT host forms × eight known default pairs × three request methods | Observed wire credentials must be parsed and redacted; the raw detector recognizes the attempt while policy remains nonpaging |
| R118: auth/authority decoys | 16 | Bearer, Digest, unrelated Basic, invalid encoding, duplicate Host/Authorization, contradictory Host, proxy authorization, documentation, marketing hosts and userinfo | Must **not** match R118 |
| R163: cloud metadata paths | 14 | Seven provider-compatible destinations/authorities/credential paths × GET/HEAD | Candidate metadata-path access is recognized; direct requests alone do not establish SSRF |
| R163: decoy metadata traffic | 21 | Ordinary metadata, host spoofing, duplicates, path traversal, encoded separators, provider confusion, unsupported methods and trusted agents | Must **not** match R163 |
| R163: agent name spoofing | 5 | Cloud-agent basenames in user-writable home, download and temporary paths | Must remain a raw candidate and **not** become a proven SSRF alert |

The R102 test also checks that **ten ordinary DNS queries cannot prime a suspicious repeat counter**. One borderline random-label query must not inherit unrelated browsing as evidence. A second independent suspicious-shape query may qualify as a candidate, subject to the unchanged 80% precision floor and baseline policy.

These scenarios are **not 200 independent field incidents**. They are deterministic, overlapping boundary checks that prevent the same parser or detector from regressing under many input permutations. Their success should never be added to the main benchmark denominator as if they represented a new production distribution.

## End-to-end full-engine replay controls

Four new JSON fixtures complement the parameterized suite:

- `r118-conflicting-host-default-basic-over-tls`: benign ambiguous HTTP authority must not manufacture an IoT default-login match
- `r118-router-support-parser-default-basic`: raw synthetic Basic bytes are parsed, redacted and recognized before reaching the rule
- `r163-home-cloud-init-basename-spoof`: a user-writable executable name is not proof of an authorized guest agent; remains nonpaging
- `r163-approved-cloud-init-imdsv2-head`: known installed agent performing a normal metadata HEAD request remains benign and nonpaging

Each replay runs against the full default rule catalog and every supported profile. The benign/malicious fixtures are balanced to avoid inflating plain accuracy with easy benign traffic.

## Scorecard and statistical limits

The `build-verify/tuning-benchmark.md` report now includes:

- TP / FP / FN / TN on **emitted replay alerts** by profile
- Precision, recall, specificity and F1; **balanced accuracy** and **Matthews correlation coefficient (MCC)**
- Wilson 95% intervals for observed precision, recall and false-positive rate
- The original detector-recognition → Shadow/Disabled policy → simulated-alert funnel

A 100% observed precision rate is not 100% certainty: if all 8 observed alerts are correct, the illustrative Wilson 95% lower bound is about **67.6%**. Likewise 0/43 observed benign false positives has a Wilson 95% upper bound of about **8.2%**. These intervals assume independent Bernoulli observations and can **understate** uncertainty for correlated synthetic variants; real-world base rates, incident labeling and traffic mix are unknown.

Do **not** inflate the test score by changing a malicious label to benign, turning off a rule, raising confidence floors indiscriminately, or counting Shadow candidates as emitted alerts. A Shadow candidate contributes to detector recognition but is not an alert.

## Verification on Windows

```powershell
git fetch origin feature/carthago-reliability-hardening
git merge --ff-only FETCH_HEAD

# Target the new deterministic matrix and score calculations first.
dotnet test .\Carthago.Tests\Carthago.Tests.csproj -c Release --filter "FullyQualifiedName~AccuracyScenarioMatrixTests|FullyQualifiedName~DetectionQualityUncertaintyTests|FullyQualifiedName~R102DistinctTxtCorrelationTests"

# Then build, run the complete unit suite and simulate all 6 profiles.
.\verify-local.ps1 -Details -LiveOutput

# Inspect actual denominators and the spread of plausible replay rates.
.\scripts\inspect-accuracy-evidence.ps1
```

Acceptance gates: **successful build; zero test failures; no missing positive controls or unexpected explicit negative matches; zero benign alert-level false positives in all six profiles; no broken policy-funnel accounting; unchanged R102/R118/R163 precision floors, and no synthetic secrets in persisted evidence**.

## Further validation needed

For high-confidence field accuracy, add owner-authorized, independently labeled benign and malicious telemetry from **different organizations, protocols, vendors, operating systems and time windows**. Use a locked holdout corpus for measurement and a separate development corpus for tuning. Investigate each missed expected rule or benign alert without changing labels after observing results. Measure the held-out per-rule and per-environment error rates before policy promotion.
