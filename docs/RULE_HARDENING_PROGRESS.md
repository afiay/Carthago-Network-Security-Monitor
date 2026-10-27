# Detection-rule hardening progress

This ledger is the durable handoff for sequential five-rule development on
`feature/carthago-reliability-hardening`. Automated development must update it
in the same commit as each batch's code, tests and technical assessment.

| Batch | Rules | Development status | Test evidence |
| --- | --- | --- | --- |
| 01 | R001–R005 | Accepted for synthetic development gates | Windows 2026-10-27: targeted 62/62, advanced 28/28, full local regression PASS, frozen holdout 12/12 and expected matches 6/6 |
| 02 | R006–R010 | **CANDIDATE — UNVERIFIED** (41 advanced xUnit facts, four new development replay fixtures) | No builds, tests or replay executed; candidate commit 8efa410ee20a3e551ca29a52f9bc50ed24f7c947 |
| 03 | R011–R015 | **CANDIDATE — UNVERIFIED** (44 advanced xUnit facts; five benign development replay controls) | No builds, tests or replay executed; candidate commit 01e35f522f87ad70cd3f3590e8942fcf31aa31bf |
| 04 | R016–R020 | **CANDIDATE — UNVERIFIED** (43 advanced xUnit facts; five benign development replay controls) | No builds, xUnit, replay or holdout executed; candidate commit 46b60c6f553e38b461e9d65a8e6f6060813e9a38 |
| 05 | R021–R025 | **CANDIDATE — UNVERIFIED** (31 advanced xUnit facts; five benign development replay controls) | No builds, xUnit, replay or holdout executed; candidate commit ada69fb870bf1ad4c8a2c4c34fe2d25826e6871e |
| 06 | R026–R030 | **CANDIDATE — UNVERIFIED** (41 advanced xUnit facts; five benign development replay controls) | No builds, xUnit, replay or holdout executed; candidate commit 7eb86797dc6285e499502265316a7a4da5566b67 |
| 07 | R031–R035 | **CANDIDATE — UNVERIFIED** (30 advanced xUnit facts; five benign development replay controls) | No builds, xUnit, replay or holdout executed; candidate commit 39b93b772ea9d388738b11519b83644afbefa26b |
| 08 | R036–R040 | **CANDIDATE — UNVERIFIED** (38 advanced xUnit facts; five benign development replay controls) | No builds, xUnit, replay or holdout executed; candidate commit recorded in follow-up ledger commit |

**Next batch to author: R041–R045.** R006–R040 is authored but remains unverified; do not treat those batches as accepted. Continue in exact ascending groups of five.
Do not mark a subsequent batch accepted until the user explicitly initiates
the deferred consolidated Windows verification and the corresponding evidence
is reviewed. The hourly automation must not run any tests or builds meanwhile.

## Candidate-batch contract

1. Read the latest remote HEAD and this ledger before selecting a batch.
2. Inspect actual code, configuration, dependencies, rule adapters and tests.
3. Add at least five meaningful advanced xUnit scenarios per rule, using the
   filename `Carthago.Tests/RNNNAdvancedAccuracyBatchTests.cs`; use additional
   cases and labeled development replays wherever warranted.
4. Cover real positives, convincing benign negatives, evasive variants,
   incomplete/contradictory evidence and stateful operational boundaries.
5. Preserve policy/confidence floors, source attribution, privacy controls,
   frozen holdout identities and baseline readiness safeguards.
6. Publish candidate changes with a branch-head lease, never force-push or
   overwrite concurrent changes. Record the exact batch and commit SHA here.
7. Label all unexecuted work **CANDIDATE — UNVERIFIED**. No synthetic scores
   or production-quality claims without fresh verification evidence.

## Deferred one-run acceptance

When the user says it is test time, freeze the branch head, then run on Windows:

```powershell
git fetch origin feature/carthago-reliability-hardening
git merge --ff-only FETCH_HEAD
.\scripts\verify-all-rule-batches.ps1
```

The consolidated command runs the full xUnit suite once (including all
authored advanced rule cases), the development replay once, and the frozen
holdout once. It enforces contiguous rule coverage and at least five passing
advanced cases per authored rule, and exports one timestamped complete TXT
under `build-verify/rule-batches/` with separate stage logs.

Passing these synthetic gates does not establish independently labeled
field precision, operational alert recall or authorization to promote rules.
