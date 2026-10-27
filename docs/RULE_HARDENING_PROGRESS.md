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
| 08 | R036–R040 | **CANDIDATE — UNVERIFIED** (38 advanced xUnit facts; five benign development replay controls) | No builds, xUnit, replay or holdout executed; candidate commit 510e4a8f2787792c9644c68080a02bea4b811fb8 |
| 09 | R041–R045 | **CANDIDATE — UNVERIFIED** (35 advanced xUnit facts; five benign development replay controls) | No builds, xUnit, replay or holdout executed; candidate commit cadc84785a10e0a427d28101c9e72914c34556c0 |
| 10 | R046–R050 | **CANDIDATE — UNVERIFIED** (36 advanced xUnit facts; five benign development replay controls) | No builds, xUnit, replay or holdout executed; candidate commit 000db46565ca2870a76a0741fca12f330ebb35b7 |
| 11 | R051–R055 | **CANDIDATE — UNVERIFIED** (46 advanced xUnit facts; typed health-snapshot scenarios, no traffic-only replay labels) | No builds, xUnit, replay or holdout executed; candidate commit 67cc49dddc21e7564feef0e1f2af56bcba12d9c1 |

| 12 | R056–R060 | **CANDIDATE — UNVERIFIED** (48 advanced xUnit facts; typed health/ARP evidence, no manufactured replay labels) | No builds, xUnit, replay or holdout executed; candidate source/test commit 8494092f871fbeea46cce72500706f9c2406944d |

| 13 | R061–R065 | **CANDIDATE — UNVERIFIED** (37 advanced xUnit facts; typed network evidence and ready durable baseline gate) | No builds, xUnit, replay or holdout executed; candidate source/test commit 7754f330fdd00e38b6a86b13c9bc7fe54ef8486f |

| 14 | R066–R070 | **CANDIDATE — UNVERIFIED** (48 advanced xUnit facts; typed IPv6/asset country evidence; no manufactured replay labels) | No builds, xUnit, replay or holdout executed; candidate source/test commit 4103ab4155b8a915583dc5999e961669ed10272e |
| 15 | R071–R075 | **CANDIDATE — UNVERIFIED** (35 advanced xUnit facts; typed IPv6/multicast and internal administrative-flow evidence; no manufactured replay labels) | No builds, xUnit, replay or holdout executed; candidate source/test/docs commit 107e45d0a1df67730739077359559a18957a1f89 |

| 16 | R076–R080 | **CANDIDATE — UNVERIFIED** (35 advanced xUnit facts; typed SMB/RPC/LDAP/Kerberos correlation; no manufactured positive traffic-only replay labels) | No builds, xUnit, replay or holdout executed; candidate source/test/docs commit 853ce656e1b408873687ad16469303402e7b02ed |

| 17 | R081–R085 | **CANDIDATE — UNVERIFIED** (35 advanced xUnit facts; two benign-only development replay controls; typed Kerberos/NTLM/name-service and structured HTTP evidence) | No builds, xUnit, replay or holdout executed; candidate source/test/docs commit 371f87bed66061cf9d80e854a756caaeb088ccf8 |

| 18 | R086–R090 | **CANDIDATE — UNVERIFIED** (35 advanced xUnit facts; bounded HTTP request-target evidence and typed upload/deserialization classification; no manufactured replay controls) | No build, xUnit, replay, holdout or Windows runner executed; candidate source/test/docs commit 10b658263de484e9a727dcb0e4eb2f0b9c2f4c1a |

| 19 | R091–R095 | **CANDIDATE — UNVERIFIED** (35 advanced xUnit facts; corroborated HTTP indicators and strengthened typed DNS question evidence; mature DNS precision profiles retained) | No build, xUnit, replay, holdout or Windows runner executed; candidate source/test/docs commit d9b259f1a572a4fb1228cc313c8bda855963e1b2 |

**Next batch to author: R096–R100.** R006–R095 is authored but remains unverified; do not treat those batches as accepted. Continue in exact ascending groups of five.
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
