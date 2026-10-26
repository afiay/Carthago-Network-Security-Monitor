# Accuracy evaluation without score inflation

## Current scope

Carthago now has **two separate replay corpora**:

- **Development:** `Tests/RuleReplaySamples`, evaluated by `verify-local.ps1`. These fixtures were available while the detector was being tuned; they measure regression coverage, **not unbiased field accuracy**.
- **Frozen synthetic holdout:** `Tests/RuleReplayHoldout`, evaluated separately by `scripts/evaluate-holdout.ps1`. The `docs/holdout-evaluation-manifest.json` pins fixture names, class labels, focused rules and Git object hashes. This is a newly authored, intentionally unseen-by-the-development-benchmark set of **12 synthetic cases**: two positive and two negative controls each for R102, R118 and R163. It **still is not an independent, real-world dataset**.

Holdout scenarios represent candidate interpretations and benign counterexamples, not proven incidents. For R118, observing a default Basic pair does not prove an authentication succeeded, and an approved provisioning note is not proof of policy approval. For R163, observing metadata credential-path traffic does not prove an attacker-controlled SSRF causal chain. For R102, suspicious TXT names are DNS tunneling candidates without packet-level exfiltration confirmation.

**Keep the pinned synthetic holdout frozen.** Do not copy it into the development fixture directory, silently edit its labels, automatically promote a rule, or iteratively tune against its results. If a genuine labeling error or protocol ambiguity is discovered, disclose the correction and version a new evaluation cohort.

## Commands

From a PowerShell terminal in the repo root:

```powershell
git fetch origin feature/carthago-reliability-hardening
git merge --ff-only FETCH_HEAD

# Existing 544-rule build, tests and development replay checks.
.\verify-local.ps1 -Details -LiveOutput

# Pinned synthetic holdout, independently executed in its own report directory.
.\scripts\evaluate-holdout.ps1 -NoBuild
.\scripts\inspect-accuracy-evidence.ps1 -Report .\build-verify\holdout\tuning-benchmark.json

# Find benign RAW detections that merit analyst review. They are not
# false-positive alerts unless a profile actually emitted an alert.
.\scripts\inspect-noisy-rules.ps1 -Top 20 -ExportCsv .\build-verify\noise-audit.csv
.\scripts\inspect-noisy-rules.ps1 -RuleId R018,R028,R032,R045,R047,R057,R062,R086,R095,R102
```

The first manual GitHub Actions `Carthago detection quality` workflow also executes the pinned synthetic holdout after build, tests and development benchmark succeed. It is **manual dispatch only** and uses the self-hosted Windows runner; this documentation does not claim the runner is online or GitHub billing/artifact quota restrictions have been cleared.

## Separate scorecards

Both benchmarks produce `tuning-benchmark.json` and `tuning-benchmark.md` within **their own output directories**. Never combine their sample counts or report the development plus holdout as an independent larger test. Per profile, present:

- Raw expected-rule recognition against explicitly labeled malicious (sample, rule) pairs
- Explicit nonmatch failures against labeled negative (sample, rule) pairs
- Emitted **alert-level** TP/FP/FN/TN (Shadow is neither a TP alert nor an FP alert)
- Precision, recall, specificity, balanced accuracy, F1 and MCC, with **numerators and denominators**
- Wilson 95% intervals on observed proportions, explicitly marked as optimistic when related synthetic cases are statistically dependent
- Policy Shadow, Disabled, baseline not ready, missing evidence and unmet confidence-floor explanations

The synthetic holdout gate requires all pinned fixtures present/unchanged, all declared malicious rule matches recognized, all declared negative rule matches absent, zero benign alert emissions in every profile and no policy-funnel inconsistency. A passing gate does **not** establish that alert-level recall is adequate for production; deliberate Shadow/Disabled rules may keep recall near zero.

## Real-world validation protocol (not yet performed)

For defensible real-world estimates:

1. Obtain **written permission** from network owners; collect only traffic and logs you are authorized to observe. Do not generate unauthorized login attempts, remote exploitation or real cloud credential requests.
2. Prefer schema-level telemetry: protocol, request method, normalized host, safely redacted path, ports, process basename and trustworthy capture attribution. **Never upload passwords, Basic/Bearer tokens, session cookies, client data, request bodies or full capture payloads**. Redact at ingestion, review artifacts before sharing, and avoid storing customer identifiers in Git history.
3. Record source provenance, sensor version, time interval, network class, protocol/vendor and confidence in the incident label. Preserve an `Unknown/Ambiguous` label instead of forcing these into benign or malicious.
4. Require independently corroborated outcomes: authentication server result + authorization/asset context for R118; causal parent request/trace + process identity for R163; DNS/TXT cadence + destination/egress or server evidence for R102. Generic process descriptions and timing proximity are **not** corroboration.
5. Split field data by **organization/network, device family and time window**. Reserve a previously unseen deployment/time cohort; random individual-packet splitting leaks highly correlated traces into both training and evaluation. Group related retry sequences and avoid duplicates across sets.
6. Keep development tuning separate from final sealed holdout testing. Require two independent reviewers for borderline cases and log label changes, taxonomy, detection code revision and disposition.
7. Evaluate **per-rule**, **per-profile**, and **per-environment**, and audit worst-case slices (OT, IoT, cloud guest agents, CDNs, managed devices, proxies, missing attribution). Report FP per benign device-hour and true positives per confirmed incident in addition to per-sample proportions when denominators are available.
8. Promote policy modes only after owner approval, demonstrated field benefit, rollback strategy, calibrated confidence, fresh baseline and measured false-positive load. Never remove the current policy gates solely to improve benchmark recall.

## Noisy rule audit

A raw match on legitimate traffic often represents a weak hypothesis or a deliberate Shadow candidate. The noisy-rule inspector lists the number of **benign fixtures matched** per rule, how many profile decisions were Alert/Shadow/Disabled, and example scenario names. Use the ranking to select rules for *future* validation. It must not change thresholds, labels or modes automatically. Rule coverage gaps across the wider 544-rule catalog remain separate work.

## Acceptance before advancing rule promotion

- Zero build and test failures; no trusted evidence or redaction regression
- Zero labeled benign alerts across the existing development corpus and frozen synthetic holdout
- No missing positive or failed explicitly negative rule assertions; no unsafe profile-decision accounting
- R102 / R118 / R163 floors unchanged at 80%, 86% and 84% respectively
- No synthetic secrets exposed in reports, telemetry events, CI logs or uploaded artifacts
- All claims about production accuracy deferred until independently labeled, authorized, held-out field data is available
