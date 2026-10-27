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
| 23 | R111–R115 | **CANDIDATE — UNVERIFIED** (39 advanced xUnit facts; typed HTTP export/upload and MQTT protocol/action evidence; dedup and privacy) | No build, xUnit, replay, holdout or Windows runner executed; candidate source/tests/docs in this commit |
| 24 | R116–R120 | **CANDIDATE — UNVERIFIED** (35 advanced xUnit facts; typed SSDP/Telnet/Modbus contracts, camera source evidence, duplicate-resistant bounded per-detector windows, credential transport and privacy) | No build, xUnit, replay, holdout or Windows runner executed; candidate source/tests/docs in this commit |

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

## R103 source-correlation correction — 2026-10-27 18:45 run

At HEAD `7d51e48df6b3d8b7614b9a7621fe787da5e59684`, CARTHAGE
restored and built both projects with zero warnings/errors. The xUnit suite
reported **2,028 passed, 2 failed, 0 skipped (2,030 total)**. Both failures
were in `R103AdvancedAccuracyBatchTests`, while the 146-sample development
replay benchmark recognized 48/48 expected malicious rules and reported zero
benign false-positive alerts. Consolidated acceptance remains **FAILED**;
the frozen holdout is not certified by this run.

Root cause of the two R103 failures: the test's `Hit(...)` method used
source `10.103.0.10`, whereas direct `DnsFixture(...)` calls defaulted to
`10.101.0.10`. R103 correctly partitions its six-observation windows by
source IP, so the last sample was not part of the first five. Commit
`4935b5630eef4c889970bfd030b9f06c0940eb6f` makes both paths
share one source constant. Only the test fixture changed; **no detector
logic, threshold, confidence or policy changes**. **UNVERIFIED** until the
next fresh targeted and consolidated run.

## R111–R115 candidate implementation — 2026-10-27

The next contiguous batch was authored against remote HEAD `72a1266b4d953d54e018171d24f187365f45d049`.
Seven rule/infrastructure source files, one shared test fixture, five advanced
test files (39 xUnit facts), and `docs/RULE_BATCH_111-115.md` describe
narrowly scoped typed HTTP and MQTT precision hardening, duplicate-ID
resistance, source/broker separation and URI/topic redaction. No builds or
tests were run. The existing single Windows verification script remains
unchanged. **CANDIDATE — UNVERIFIED**; prior 2,028/2,030 regression evidence
is not evidence for this new batch.

**Next batch to author: R121–R125.** R006–R115 is authored but remains unverified; do not treat those batches as accepted. Continue in exact ascending groups of five.
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

## CARTHAGE full verification — 2026-10-27 19:02

The user-run consolidated transcript
`build-verify/rule-batches/all-rule-batches-2026-10-27_19-02-08.txt`
covered **R001–R110** (110 authored advanced rule files). Test and benchmark
restores/builds passed, with **zero build warnings and errors in that run**.
Full xUnit **2,030/2,030 passed; 0 skipped**. The 146-sample development
replay passed, recognizing **48/48** labeled malicious rule expectations
with no benign critical alerts. These results verify the R001–R110
regression and development replay stages for that local snapshot; they
**do not** verify any subsequently authored R111–R115 candidate changes
and do **not** establish production precision.

The separate pinned synthetic holdout **FAILED**: detector recognition
**4/6**, expected **6/6**, with no benign simulated alerts. Both missed
positives belong to **R102**:
`holdout-r102-multistage-encoded-txt` and
`holdout-r102-second-client-encoded-txt`. Each reported no match
and confidence 0.00 (required floor 0.75). The cause is a **frozen
fixture telemetry/schema gap**, not evidence justifying a weaker rule:
all six records in these two scenarios explicitly declare
`protocol: "DNS"`, `applicationProtocol: "DNS"`, `dnsQtype: "TXT"`,
and `destinationPort: 53`, but **none contains an explicit
`isUdp: true` or `isTcp: true` transport assertion**.
`NetworkBatch096100Evidence.Dns` deliberately requires an attributed
UDP or TCP transport and fails closed for records missing both flags;
`R102` therefore cannot match. The prior development DNS fixtures
were corrected to carry explicit transport attribution. Both affected
holdout JSON blob SHAs still match their frozen manifest entries.

**Disposition: consolidated acceptance NOT COMPLETE.** Do not relax
production transport validation, manufacture absent transport evidence
during holdout replay, reduce confidence floors, or silently edit
pinned holdout labels/data/hashes. Keep v1 immutable and retain the
failed result. If a new holdout is commissioned, it needs a separately
approved, newly frozen version with independently sourced **typed**
DNS transport evidence and its own manifest; that would **not**
retroactively make this v1 evaluation pass. Until an evidence-valid
holdout passes, no new batch is promoted on the strength of the
green regression alone.

## Separately versioned R102 holdout v2 — candidate infrastructure, 2026-10-27

After CARTHAGE passed 2,030/2,030 regression tests and 48/48
development replay recognitions, frozen v1 holdout remained FAILED (4/6)
because two R102 positive cases lacked parser-attributed UDP/TCP evidence.
The v1 corpus and its manifest remain unchanged and failed.

New opt-in **v2 candidate infrastructure**, with no new capture files
fabricated or evaluated:

- docs/holdout-evaluation-v2-manifest.json: twelve separately specified
  cases. Eight original R118/R163 synthetic cases are reused by their
  immutable v1 Git blob SHA; four R102 entries are deliberately
  PENDING_EXTERNAL_CAPTURE_AND_REVIEW.
- scripts/import-holdout-v2-r102.ps1: TShark import from an externally
  obtained PCAP, requiring explicit port-53 UDP/TCP decode, packet frames,
  source attribution, dataset license and independent analyst label rationale;
  outputs only under build-verify until reviewed.
- scripts/freeze-holdout-v2.ps1: explicit local freeze after review,
  restricted to four candidate R102 cases and provenance, pinning hashes.
- scripts/evaluate-holdout-v2.ps1: **fail-closed until frozen**; validates
  every pinned fixture, provenance and transport contract before replay,
  then enforces 6/6 malicious recognition, 0 benign alerts and profile
  accounting.
- scripts/verify-all-rule-batches.ps1: new optional
  -HoldoutVersion v2 switch, with v1 deliberately remaining the default.
- docs/HOLDOUT_V2_PROTOCOL.md: source, privacy, label, evidence and
  manual acceptance procedure.

This is a **CANDIDATE — UNVERIFIED / AWAITING REAL CAPTURES**, not a
passing v2 evaluation, independently labeled field dataset or authorization
to change production rules. The hourly rule-development automation remains
bound by its separate no-tests/no-builds instruction. No tests or Windows
runner were executed by this work. The original v1 evaluation remains failed
regardless of any future v2 outcome.

## V2 provenance hardening — continued, 2026-10-27

V2 remains PENDING_EXTERNAL_CAPTURE_AND_REVIEW. No new external PCAP
was imported, frozen, evaluated or labeled as field independent.
Neither v1 evidence nor R102 production detection logic was altered.

- scripts/audit-holdout-v2-candidates.ps1 re-decodes the original
  PCAPs, verifies SHA-256 and every referenced packet frame, checks
  typed UDP/TCP/DNS fields and rejects reused frames or overlapping
  malicious-client source IPs.
- scripts/freeze-holdout-v2.ps1 now requires original captures and
  successful packet audit before any file copy, checks eight reused v1
  blobs, requires both approval switches, rolls back copied files on
  failure and atomically updates only the v2 manifest.
- scripts/verify-all-rule-batches.ps1 fails early when v2 is pending,
  before expensive builds or tests; v1 remains the default.
- Six new unexecuted xUnit facts in
  Carthago.Tests/SyntheticHoldoutV2ContractTests.cs check manifest
  version separation, v1 hash reuse, new R102 slots, label balance,
  pending/frozen hash discipline and opt-in holdout selection.
- docs/HOLDOUT_V2_PROTOCOL.md documents packet audit and recognizes
  that CSV-only features cannot establish raw PCAP transport.

**CANDIDATE — UNVERIFIED.** No Carthago build, xUnit, benchmark,
holdout, Windows runner or production data capture was executed.
No synthetic results establish production precision or alert recall.

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

## R116–R120 candidate implementation — 2026-10-27

Authored against remote branch HEAD `ead1471cc86052b0b5fa51d6772ea21e4ce39154` after checking the
contiguous batch ledger and existing R111–R115 tests. The candidate includes
five rule changes, a narrowly scoped shared evidence/window helper, an
IoT/OT raw-Info privacy fix, one isolated test context and 35 new xUnit facts
(7 per rule). R116/R119 now use per-instance, bounded duplicate-resistant
observations; R117 and R120 require coherent parser-attributed protocol
evidence, while R118 retains the existing default-credential matcher and
86% floor with additional contradictory-transport/authority rejection.

**CANDIDATE — UNVERIFIED.** No build, xUnit, development replay, frozen
holdout, Windows runner or automated tests were executed. The single
deferred verification entry point remains
`scripts/verify-all-rule-batches.ps1`, unchanged. No holdout files,
manifest hashes, replay labels, approval gates, thresholds, modes or
confidence floors were modified.

The existing v1 synthetic holdout failure (R102 4/6) is not cured by
this batch. V2 still awaits independent captures and approval. Detector
changes and tests require a future owner-authorized consolidated run;
review real SSDP/Telnet/RTSP/Modbus parser mappings and any IoT/OT
false-negative impact before acceptance. **Next batch: R121–R125.**
