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

| 20 | R096–R100 | **CANDIDATE — UNVERIFIED** (43 advanced xUnit facts; typed DNS response/address and query validation, distinct-record windows, reputation-timing and public-resolver evidence; no manufactured replay labels) | No build, xUnit, replay, holdout or Windows runner executed; candidate source/test/docs commit 2915d378303b1845d928b7900e28992df6f47818 |

| 21 | R101–R105 | **CANDIDATE — UNVERIFIED** (35 advanced xUnit facts; connected CNAME chains, typed DNS/state dedup, durable cloud first-seen, typed upload/URI privacy) | No build, xUnit, replay, holdout or Windows runner executed; candidate source/test/docs commit d7af63d19de25f37583233b33d33f0790fdee5c2 |

| 22 | R106–R110 | **CANDIDATE — UNVERIFIED** (25 advanced xUnit cases; typed sweep, cloud transfer, dedup, URI privacy) | No build, xUnit, replay, holdout or Windows runner executed; candidate changes in this commit |

## CARTHAGE acceptance checkpoint — 2026-10-27 18:06

At source HEAD `6a11c049f2273b830c3093f090c973b36039556b`,
the user ran the consolidated Windows acceptance command. Test and benchmark
projects built successfully (four test-build warnings). Full xUnit:
**2,004 passed, 25 failed, 0 skipped (2,029 total)**. Development replay
reported four unsatisfied positive match expectations (R102-related and R084).
The benchmark processed 146 labeled samples, but the replay expectation
stage failed; the frozen holdout was **not accepted or evidenced** by that run.

Subsequent repair commits correct the isolated baseline test scope, legacy
R092/R109 test contracts, R102 duplicate-ID tests and structured DNS replay
transport, serialize shared DNS state tests against replay resets, and extend
bounded R084 Log4j lookup normalization with an explicit regression test.
These repairs are **UNVERIFIED** until a fresh consolidated CARTHAGE run.
No malicious labels, confidence floors, baseline approvals, disabled/shadow
policy or frozen holdout identities have been relaxed.

## CARTHAGE acceptance checkpoint — 2026-10-27 18:29

The newer consolidated Windows run compiled the test and benchmark projects
without reported warnings/errors. The development replay recognized **48/48**
expected malicious rule matches and completed its expectation stage.
Full xUnit still failed **two** cases:
`R103AdvancedAccuracyBatchTests.Six_Independent_Stable_Intervals_Produce_Beacon_Candidate`
and `R103AdvancedAccuracyBatchTests.Duplicate_Id_Cannot_Fill_A_Stable_Interval_Window`.
The frozen holdout has not been accepted based on this run.

R103 has a separate older positive test in `DnsPrecisionRuleTests` using
six valid independent DNS requests. Candidate repair `234141af28722d2eda3f2b1d633191d641d4e951`
aligns advanced fixtures with that existing passing contract and adds
effective configuration details to failure diagnostics. The change does **not**
lower the six-observation default threshold or remove negative/duplicate tests.
**Candidate — unverified** until a fresh run; all R006–R110 batches remain
unaccepted.

**Next batch to author: R111–R115.** R006–R110 is authored but remains unverified; do not treat those batches as accepted. Continue in exact ascending groups of five.
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
