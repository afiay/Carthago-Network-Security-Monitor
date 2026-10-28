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

## V2 source acquisition and safer PCAP preparation — 2026-10-27

The v2 manifest remains PENDING_EXTERNAL_CAPTURE_AND_REVIEW and the
original v1 evaluation remains FAILED (R102 4/6). No new PCAP has yet
been downloaded, imported, labeled, reviewed or frozen by this stream.
No Carthago build, xUnit suite, benchmark, live monitoring or Windows
runner was executed.

Candidate additions and repairs, all UNVERIFIED:

- scripts/acquire-holdout-v2-source-candidates.ps1 pins the Elastic iodine
  example PCAP to immutable commit 6d86454ebb7a850bcd7e80abe86fe683370018a6,
  blob f43152b995d0eb9127d5a8fcaf13e5c26595ce69 (77,524 bytes).
  Downloads stay in private build-verify paths; acquisition is not approval.
- scripts/inspect-holdout-v2-pcap.ps1 provides source/client and DNS QTYPE
  summary without emitting raw QNAMEs or IPs by default. Bounded
  packet scans avoid unbounded memory use on large captures.
- scripts/audit-holdout-v2-candidates.ps1 now limits TShark output to
  **selected pinned frame numbers** instead of materializing every DNS
  query from a large source PCAP.
- scripts/import-holdout-v2-r102.ps1 restricts input decoding volume,
  documents a bounded source selection and requires an explicit
  approved license identifier plus HTTPS license evidence.
- Source audit, freeze and v2 evaluator independently enforce license
  evidence fields; audit rejects noncommercial license identifiers for
  potentially commercial data incorporation. A cited code license
  alone still does not establish rights over a third-party capture.
- Import, inspection and acquisition output directories are constrained
  to build-verify/, preventing accidental public Git check-in of
  unreviewed packet data via output-path overrides.
- docs/HOLDOUT_V2_SOURCE_REVIEW.md screens multiple external sources;
  Apache-2.0 repository license for Elastic was checked at the pinned
  source revision; actual packet attributes and independent labels
  remain unknown until the capture is acquired and decoded.

**CANDIDATE — UNVERIFIED.** Authored changes do not constitute
independent field evidence or permission to promote R102. No frozen
v1 blobs, thresholds, Shadow/Disabled policy or detector code changed.

## V2 candidate qualification and fail-closed evaluation — 2026-10-27

External evidence discovery identified an important mismatch: a public
A-Packets analysis of a same-named and same-sized iodine capture reports
222 NULL (DNS type 10) queries and zero TXT. The source downloader now
compares the published SHA-256 before flagging that sample as NULL-only;
without a matching hash and local decode, its identity is not proven.
Do not use the NULL-only capture in the encoded-TXT v2 cases.

Source-only changes published since the prior checkpoint:

- V2 PCAP inspector now redacts source IPs, DNS root labels and explicit
  filter root metadata by default; raw DNS QNAMEs are not exported.
- Elastic source acquisition remains hash-pinned, but emits a visible
  ineligibility warning when the downloaded SHA-256 matches the
  published NULL-only analysis. No capture was downloaded in this stream.
- Korving-F TXT-mode iodine scenario metadata for BIND9/base32 and
  BIND9/base64 was inspected. Rights, packets and source independence
  remain unverified; scripted lab clients reuse 192.168.0.30.
- R102 malicious importer and original-PCAP audit now require three
  distinct, captured TXT names with labels at least 50 characters.
  A NULL/CNAME-only capture cannot be relabeled as an encoded-TXT case.
- scripts/evaluate-holdout-v2.ps1 independently checks the unchanged
  0.75 minimum R102 fixture confidence floor, distinct malicious client
  sources, no repeated original capture/frame keys and source/root
  correlation even if normal freeze flow is bypassed.
- docs/HOLDOUT_V2_SOURCE_REVIEW.md and HOLDOUT_V2_PROTOCOL.md now
  identify the NULL-vs-TXT mismatch, exact TXT-mode scenario references,
  the rights/label limitations and non-executable illustrative values.

**STATUS: CANDIDATE — UNVERIFIED.** V2 remains
PENDING_EXTERNAL_CAPTURE_AND_REVIEW (zero frozen new R102 samples).
The last passing xUnit evidence still applies only to the older R001-R110
snapshot. The frozen v1 4/6 failure and all production confidence/
baseline/Shadow safeguards are unchanged. No Carthago builds, tests,
benchmark runs or Windows runner jobs were executed by this work.

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

## R121–R125 candidate implementation — 2026-10-27

Authored against exact remote HEAD `85996ab87dc83863922ffb9de1f23ad86c2467a8` after confirming the
R116–R120 ledger and absence of R121–R125 advanced files. Five rule
implementations, one shared protocol-evidence contract, two narrow evidence
privacy changes, five new advanced test classes and one isolated fixture
were prepared. **37 xUnit facts authored; 0 executed.**

**CANDIDATE — UNVERIFIED.** The single Windows entry point discovers
R121–R125 automatically and remains unchanged. No builds, tests, replay,
holdout or runner were invoked. No confidence floors, approval policy,
thresholds, frozen inputs or labels were changed. The R102 frozen v1
holdout remains failed, v2 pending. See `docs/RULE_BATCH_121-125.md`.
**Next contiguous batch: R126–R130.**

## R126-R130 candidate implementation - 2026-10-27

Five IdentityAccess rules hardened with explicit TCP/HTTP/SSH provenance,
IP-boundary checks, fixed-category route evidence and bounded per-instance
burst state. 35 new advanced xUnit facts authored (7 per rule), plus shared
context and evidence helper. **CANDIDATE - UNVERIFIED: zero tests run.**
Existing default Shadow, confidence floors, approval/baseline gates and
frozen holdout were not changed. The consolidated Windows entry point
remains unchanged. See `docs/RULE_BATCH_126-130.md` for scope and risks.
**Next contiguous batch: R131-R135.**

## R131-R135 candidate implementation - 2026-10-27

Authored five HTTP identity/credential rules against remote HEAD
`dfa8883313b63397edded2f25ddec8d548a083c8`: R131 independent
HTTP auth-failure bursts, R132 pseudonymized source-country churn,
R133 Basic cleartext exposure, R134 opaque token query exposure and
R135 Bearer cleartext exposure. Added one narrowly scoped shared
HTTP/credential evidence contract, reused existing per-instance bounded
duplicate-resistant windows, and redacted raw HTTP paths for these
five rules in the shared identity-access event builder. Added 40 new
advanced xUnit facts (eight per rule) and one shared fixture.
See `docs/RULE_BATCH_131-135.md`.

**CANDIDATE - UNVERIFIED.** Zero new tests or builds executed; no
replay/holdout/runner invocation. Existing confidence floors, thresholds,
Shadow/Alert/Disabled policy, baseline approvals, frozen v1 labels and
v2 pending status were not changed. The last user-run regression cannot
certify this batch. The frozen v1 R102 4/6 failure remains.
**Next contiguous batch: R136-R140.**

## R136-R140 candidate implementation - 2026-10-27

Authored the next contiguous five-rule batch after verifying R131-R135 at
`af10ebe187bd4559f3117190dca38529496333a9`. R136 now requires
wire-attributed cleartext HTTP and a real Cookie request header; R137
requires independent, duplicate-resistant recovery/enrollment submissions;
R138 requires an external destination IP and exact certificate issuer/subject
DN equality (self-issued indicator, **not** signature verification); R139
accepts only canonical weak negotiated-version field values; R140 requires
an exact suspicious issuer CN rather than a substring in an arbitrary DN.

Shared evidence helper `NetworkBatch136140Evidence.cs` and identity
event-builder redaction avoid raw session tokens, recovery paths and
certificate distinguished names. Five advanced xUnit classes contain
**40 new facts (eight per rule)** plus one isolated fixture. Source commit
`70a8db22cc27de593e7fd18feb3e2ab86dffa7e5`; test commit
`2d40c469ebe49e6656c7a3a5873caffee6601fac`.
See `docs/RULE_BATCH_136-140.md`.

**CANDIDATE - UNVERIFIED.** No builds, xUnit, replay, benchmark, holdout
or runner jobs executed. Existing confidence floors, configured thresholds,
default modes, Disabled/Shadow behavior, approvals, baseline readiness and
frozen holdout data remain unchanged. The previous user-run verification
does not validate these new changes. Frozen V1 R102 remains FAILED 4/6;
V2 still awaits independently sourced, licensed, reviewed typed PCAP evidence.
**Next contiguous batch: R141-R145.**

## R141-R145 candidate implementation - 2026-10-27

The automation was paused at the user's request after its in-flight
R136-R140 work finished at commit `39028c248b189d98626dacb5b278ac77efdc416b`.
This R141-R145 batch was developed manually on the SAME existing branch,
without resuming or duplicating the automation.

Five TLS/PKI rules received typed transport/SNI/observed-socket validation,
bounded source-scoped duplicate-resistant fingerprint windows, ordered
certificate lifetime checks and certificate distinguished-name evidence
redaction. The implementation preserves R141/R145 Candidate/Shadow,
R142-R144 Shadow, all existing confidence floors and configured thresholds,
and the user's frozen holdout constraints. Added one shared evidence/window
helper and one test fixture plus **40 advanced xUnit facts (8 per rule)**.
Source commit `beafa9350916eb599ed7523d010fb3382942d2e5`;
test commit `fb889bf4052160a19171afdb0660d652a7a6b5cd`.
See `docs/RULE_BATCH_141-145.md` for cases, limits and risks.

**CANDIDATE - UNVERIFIED:** no build, xUnit, development replay,
benchmark, V1/V2 holdout or Windows runner executed by this work.
Previously passing R001-R125 regressions do not verify R126-R145.
Frozen V1 remains FAILED (R102 4/6); V2 awaits independent reviewed
PCAP evidence. **Next contiguous batch: R146-R150.**

## R146-R150 candidate implementation - 2026-10-27

Manually advanced the five TLS/PKI rules after the automation was paused.
Hardened TLS/transport attribution and summary provenance, keyed replay-
resistant failure bursts by observed source+destination+port, anchored
dynamic DNS and IP-literal names to SNI and an external socket, and
retained R150's existing Alert floor while disclosing that its Info
label is untrusted. **40 xUnit facts authored, 0 executed.**
Source commit `03561a9e83dac813fe2212e4c8cf01df6d904861`;
test commit `9fb2caee6190682234d635ee577b31f17b389d48`.
See `docs/RULE_BATCH_146-150.md`.

**CANDIDATE - UNVERIFIED.** No build, xUnit, benchmark, replay, holdout or
Windows runner used; R102 frozen V1 remains FAILED 4/6 and V2 pending
independent PCAP. Same branch, no extra branches or automation resume.
**Next contiguous batch: R151-R155.**

## R151-R155 candidate implementation - 2026-10-27

Completed the second half of the user-requested **10-rule manual
continuation**, R146-R155 inclusive, without restarting the paused
automation. Added typed HTTP/2 ALPN, source-isolated deduplicated ASN
fan-out, explicit GraphQL GET introspection parameter matching, bounded
deduplicated GraphQL batch POST counters and distinct REST API path
enumeration with endpoint isolation. Scoped R153-R155 HTTP path redaction
in the shared event builder. **40 xUnit facts authored, none executed**.
Source commit `3faabf8577416865bd934077764b8d8d428cb540`;
test commit `05ccac85e793126dd8ae69dae9cb405e1cc11049`.
See `docs/RULE_BATCH_151-155.md`.

**MANUAL R146-R155 TOTAL: 10 consecutive rules, 80 authored advanced
test facts, all UNVERIFIED.** No builds, tests, benchmark, replay, holdout,
Windows runner or CI invoked. No thresholds, confidence floors, Shadow
or Alert policies, asset approvals, baseline gates or frozen holdout
samples modified. Frozen V1 R102 failure remains 4/6; V2 independent
capture review pending. Same branch throughout.

**Next contiguous batch: R156-R160. Automation remains PAUSED.**

## Aliased SNI fixture correction - 2026-10-27

Static inspection established that `TrafficRecord.Sni` and
`TrafficRecord.TlsSni` are aliases of the same backing field,
so tests trying to set conflicting independent SNI fields were
unrepresentable. Five advanced test files R141, R142, R145, R148
and R149 were corrected to exercise contradictory HTTP request
metadata instead; commit `29238dac5e2c24feaab9357798bc1b18f3946063`.
The source detector code and frozen holdout were not modified.
**No tests run.** All R126-R155 recent authored work remains
**CANDIDATE - UNVERIFIED** pending user-initiated consolidated Windows
validation. **Next batch: R156-R160; hourly automation PAUSED.**

## R156-R160 candidate implementation - 2026-10-27

Authored the first resumed hourly five-rule subbatch from HEAD `dbb636acbc9b9d840117867d0f30005e6304a940`: typed HTTP and structural JWT attribution, anchored Swagger/Actuator/Kubernetes routes, scoped HTTP path redaction and instance-owned bounded replay guards. **41 advanced xUnit facts authored; zero executed.** See `docs/RULE_BATCH_156-160.md`. Code and tests remain CANDIDATE / UNVERIFIED. The single deferred Windows verifier is unchanged. Frozen V1 R102 still FAILED 4/6, V2 pending independent licensed captures/review. No threshold, confidence floor, Shadow/Disabled policy or approval/baseline gates changed. **Next: R161-R165.**

## R161-R165 candidate implementation - 2026-10-27

Authored the second consecutive five-rule subbatch after published R156-R160 checkpoint `089739eea938379a61c7c249bb93c911328d874a`: typed Docker/cache/phpinfo probes, authority consistency, preserved R163 provider-specific metadata credential contract with contradictory-transport rejection, redirect target privacy and bounded replay guards. **40 advanced xUnit facts authored, none executed.** See `docs/RULE_BATCH_161-165.md`. R156-R165 hourly total **81 new authored/unexecuted facts across 10 consecutive rules**. All remain CANDIDATE / UNVERIFIED. The consolidated Windows verifier remains unchanged. Frozen V1 R102 still FAILED 4/6; V2 pending independent licensed captures and review. Existing modes, thresholds, confidence floors and approval/baseline gates unchanged. **Next: R166-R170, then R171-R175.**

## R166-R170 candidate implementation - 2026-10-28

From verified remote HEAD `360a5ee3e3a8903744d0baf187a2fb2ac7dff410`, authored five consecutive HTTP rules with typed authority/transport checks, exact secret/Git/backup paths, bounded independent admin-login failures and query-observable XML indicators. Added shared `NetworkBatch166170Evidence.cs`, scoped event redaction, a correction to the older R170 synthetic fixture and **45 advanced xUnit facts across five rule files**, all unexecuted. See `docs/RULE_BATCH_166-170.md`. Source candidate `9b57ed7c237c6ec5495c3872a7bf8fce085506df`; tests candidate `cd83035693e2c4e80112a49499854154602c686e`.

**CANDIDATE - UNVERIFIED.** No build, xUnit, replay, benchmark, holdout, runner or CI invoked. R169 still depends on an HTTP failure summary whose capture provenance requires review; R170 cannot inspect body XML. Confidence floors, thresholds, Shadow/Disabled policies, approvals and frozen V1/V2 remain untouched. Frozen R102 V1 still FAILED 4/6. **Next contiguous batch: R171-R175, then R176-R180.**

## R171-R175 candidate implementation - 2026-10-28

From R166-R170 remote HEAD `605613ca572cb9deea0015a7cbd714bfc5a815a7`, authored five more consecutive HTTP rules: SOAP action classification, bounded User-Agent matching, coherent CORS preflight, typed WebDAV request checks and parsed HTTP framing. Source candidate `f8a723cb81f927d50fa2b9da177e0f28f1bce53b`; advanced tests candidate `f695fe49b72f4700622de5e95bbfec6a439615e0`. Added `NetworkBatch171175Evidence.cs`, five advanced test classes and scoped redaction. **47 new advanced xUnit facts authored, zero executed.** See `docs/RULE_BATCH_171-175.md`.

**R166-R175 combined: ten consecutive rules, 92 authored advanced facts, zero executed. CANDIDATE - UNVERIFIED.** No build, xUnit, replay, benchmark, frozen holdout, runner or CI invoked. Confidence floors, modes, thresholds, approvals and frozen inputs unchanged. Frozen V1 R102 remains FAILED 4/6; V2 awaits independently licensed captures and review. **Next R176-R180, then R181-R185.**

## R176-R180 candidate implementation - 2026-10-28

Authored five consecutive rules after remote HEAD `54eee0e2077439b8eae0f8f6c253b58dffa45103`: wire-attributed Host and upload evidence, strict DNS question/transport attribution, instance-owned replay protection, fixed-category HTTP path and DNS qname redaction. Added shared `NetworkBatch176180Evidence.cs`, scoped event redaction and 45 advanced xUnit facts (nine per rule) in five new test classes plus fixture. **CANDIDATE / UNVERIFIED: 0 executed.** See `docs/RULE_BATCH_176-180.md`. No tests/builds/replay/holdout/runner/CI invoked. Existing floors, modes, thresholds, approvals and frozen V1/V2 unchanged; R102 V1 remains FAILED 4/6. **Next R181-R185, then R186-R190.**

## R181-R185 candidate implementation - 2026-10-28

After verified R176-R180 HEAD `f62ffdcf6391b1809f372e37ecbea31668f86cf4`, authored five additional DNS rules with typed DNS attribution, bounded per-instance duplicate-resistant source/resolver windows, TCP zone transfer boundaries and redacted qnames. Added `NetworkBatch181185Window.cs` and 40 advanced xUnit facts (eight per rule), zero executed. Corrected R177 multipart test escaping in commit `9c93dfe6849763f55f44c1fc7e899e4c239f9e07`. See `docs/RULE_BATCH_181-185.md`.

**R176-R185 total: 10 consecutive rules, 85 advanced xUnit facts authored, zero executed. CANDIDATE / UNVERIFIED.** No builds/tests/replays/holdouts/CI/runner. Existing floors, modes, thresholds, approvals and frozen evidence preserved. Frozen V1 R102 FAILED 4/6; V2 independent PCAP pending. **Next R186-R190, then R191-R195.**

Static follow-up: R178 requires a pool/stratum service subdomain rather than the mining-provider brand apex; candidate correction `806a6244cd549c2606f9a23ba535b51a2bef0744`. The R178 apex benign negative remains unexecuted. No test or build was run.

Static R178 service-label refinement: anchored pool/stratum/rig service labels now reject benign provider website `www.2miners.com`; one additional unexecuted advanced fact. R176-R180 now 46 facts; R181-R185 40; combined R176-R185 86 authored, 0 executed. All CANDIDATE/UNVERIFIED. Next R186-R190 then R191-R195.

## R186-R190 candidate implementation - 2026-10-28

From remote HEAD `2f8eaee4e33a48be886a54ab1a099cc97fcf9856`, authored five DNS candidate hardenings: typed CAA/NULL/SRV queries, internal-to-external AD SRV leakage, bounded duplicate-resistant windows and a strict response-only short-TTL contract. Added `NetworkBatch186190Evidence.cs`, scoped DNS qname/answer redaction for R186-R195, and **50 advanced xUnit facts (10 per rule), zero executed**. Source `ef92684391f13953128933df811cf310a461027f`, tests `b4f5b597844f688573460b4c3a40312dd9306469`, static fixture/attribution correction `b4bc16137e343dc51fa991b1b732586582a70bc6`. See `docs/RULE_BATCH_186-190.md`.

**CANDIDATE / UNVERIFIED.** R190's `DnsTtl` is not currently populated by the inspected live `PacketHandler` DNS parse paths; no live TTL recall claim. No builds/tests/replays/holdouts/CI/runner. Confidence floors, policies, approvals, thresholds and frozen evidence preserved. Frozen V1 R102 FAILED 4/6; V2 independent reviewed PCAP pending. **Next R191-R195, then R196-R200.**

## R191-R195 candidate implementation - 2026-10-28

After R186-R190 remote HEAD `6464296111ae5a82e06f1195764b5aabd11f86ce`, authored five consecutive candidate rules for typed DGA-like DNS, valid registrable IDNA punycode, exact registrable brand lookalikes, DoH-shaped HTTP requests and TCP/853 TLS DoT candidates. Added `NetworkBatch191195Evidence.cs`, scoped HTTP host/path and TLS SNI redaction, replay guards and **51 advanced xUnit facts** (10,10,10,11,10), **none executed**. Source `064dc0a45b70cb786d6b040e251e6b80becacd44`, tests `1d7ec5d3495c4f43244eca1e71bbab92649c9ee6`, static follow-ups `a2039b6a5ca68aad4b43a44d192b3c6ec991ef2c` and `c2ea55c3d911aa23611415bb53eb300aaff1fd04`. See `docs/RULE_BATCH_191-195.md`.

**R186-R195 total: 10 rules, 101 advanced xUnit facts authored, 0 executed. CANDIDATE / UNVERIFIED.** R190 live TTL capture missing; R194 POST payload and R195 encrypted DNS payload unobserved. No builds/tests/replays/holdouts/CI/runner. Floors, thresholds, policies, approvals, baseline gates and frozen evidence unchanged. Frozen V1 R102 FAILED 4/6; V2 independent licensed reviewed PCAP pending. **Next R196-R200, then R201-R205.**

## R196-R200 candidate implementation - 2026-10-28

From verified remote HEAD `4550ce7479a8b5b9d2ce12c68bb733908d42825c`, authored typed NXDOMAIN and rebinding response checks, bounded client/resolver isolation, and AWS/GCP/Azure IMDS credential-request attribution with exact observed link-local socket, parsed cleartext HTTP, exact credential paths, original guest-agent exclusions and redaction. **59 advanced xUnit facts authored, 0 executed.** Source `024d554e64403119277fa82eb507d6ca1a2b2d73`; tests `0df0a523b90265bc0bee88ae9b2296ec2ac5b4c8`; static import correction `dd3086dfe0603b6750d52f759b9cec7a1b1ccd72`; agent/transport correction `511ce9e560ccdbb944a47649927f33e65fac2e4c`. Paths, limitations and scenarios: `docs/RULE_BATCH_196-200.md`.

**CANDIDATE / UNVERIFIED.** No build, xUnit, replay, holdout, CI or runner. Live DNS answer/TTL adapter gap remains; metadata requests do not prove credential issuance. Floors, thresholds, modes, approvals, baseline readiness and frozen evidence unchanged. R102 frozen V1 FAILED 4/6; V2 independent licensed reviewed PCAP pending. **Next R201-R205, then R206-R210.**

## R201-R205 candidate implementation - 2026-10-28

From verified R196-R200 remote HEAD `0a6c882250cfd9cb44e155242675c206f03d3a1e`, authored five consecutive typed Kubernetes TokenRequest, Docker Registry manifest/blob, valid SHA256 layer, anchored Terraform state and exact CI/CD token-query candidates. Added bounded source/registry state, duplicate/out-of-order protections, scoped host/path/token redaction and static legacy fixture alignment for observable TokenRequest and valid SHA256. **48 advanced xUnit facts authored, 0 executed.** Source `2d9e77f4145ae8010e553b6d15e8c15e1c041587`; provenance/state correction `be66197f2fd135291d8e33046e22f781f4a17b3f`; tests `5872d8fddfb0e5597106a14235743bded883b0f1`; fixture/privacy correction `fa013568897f61215f29c482d3d00d151c67e17b`. Paths and limitations: `docs/RULE_BATCH_201-205.md`.

**R196-R205 combined: 10 rules, 107 advanced facts authored, zero executed, CANDIDATE / UNVERIFIED.** No build, xUnit, replay, benchmark, holdout, CI or runner. DNS answer/TTL live capture gap persists. Registry byte totals do not prove successful downloads; Kubernetes TokenRequest does not prove token issuance. Existing confidence floors, policies, thresholds, approvals, baseline gates and frozen evidence preserved. Frozen V1 R102 FAILED 4/6; V2 independent reviewed PCAP pending. **Next R206-R210, then R211-R215.**


## R206-R210 candidate implementation - 2026-10-28

From remote HEAD `71133c0a7cab70c9fbc340c00d73d9e34f246ccd`, authored five consecutive Git and package-client rule hardenings with typed HTTP request/protocol/authority evidence, non-official external destination validation, instance-owned bounded replay/out-of-order guards, and host/path redaction. **55 advanced xUnit facts authored, zero executed.** Source `15ae3a5aeda96e8c3ad7e428ed0ac725d4809e63`, Git path correction `335bfd1cb7c0f104bb51c77f6fd55c7fdf105fe3`, tests `e1a60edaaa1fbe9e45e1094760bf4573b1bcb5b5`. Paths and scenario ledger: `docs/RULE_BATCH_206-210.md`.

**CANDIDATE / UNVERIFIED.** Live capture lacks decrypted HTTPS and may not attribute process identity; npm install-hook query labels do not prove execution. No build, xUnit, replay, holdout, CI or runner. Existing floors, policies, thresholds, approvals, baseline readiness and frozen evidence unchanged; frozen R102 V1 FAILED 4/6, V2 independent PCAP pending. **Next R211-R215, then R216-R220.**


## R211-R215 candidate implementation - 2026-10-28

After verified R206-R210 remote HEAD `a895673929bb9b23671778869665c70adc6687e7`, authored five consecutive PowerShell/curl raw-script and AWS/Azure/GCS storage-request candidates with typed HTTP/authority/transport checks, bounded duplicate/out-of-order guards, redacted host/path evidence and SHA256-fingerprinted R213 object-path state. **62 advanced xUnit facts authored, zero executed.** Source `fa699244fe601ec4f6d4693b71d957a19084593a`; tests `9a5b0f9ca2fa5142f45f005af1befbbffbcef701`. See `docs/RULE_BATCH_211-215.md` for paths, scenarios and limitations.

**R206-R215 total: 10 consecutive rules, 117 advanced facts authored, ZERO executed; CANDIDATE / UNVERIFIED.** R212 packet Info does not establish shell execution; R213 requests do not prove object downloads; HTTPS metadata capture is unverified. No build, xUnit, replay, holdout, CI or runner. Floors, policies, thresholds, approvals, baseline readiness and frozen evidence unchanged; frozen R102 V1 FAILED 4/6, V2 independent PCAP pending. **Next R216-R220, then R221-R225.**

## R216-R220 candidate implementation — 2026-10-28

From verified remote HEAD `2cb4d5f71a5de850956872d8f8acf389b68f6bce`, authored five consecutive request-shape candidates with typed HTTP authority/transport checks, exact cloud/collaboration endpoints, token-bearing host/path redaction, bounded per-detector duplicate/out-of-order protection and per-source paste-post windows. **81 advanced xUnit facts authored, ZERO executed.** Source `9dd80a0b4f5901f1ab1c3f8de75298bae512a473`; tests `f7d662bad5ba50182060740703b2234c77b00b2d`; fixture correction `105501ecb04d13ca86c2c3f5fe5f0ba226d9c2d0`. Exact paths and test coverage: `docs/RULE_BATCH_216-220.md`.

**CANDIDATE / UNVERIFIED.** Declared Content-Length/multipart do not prove payload transmission or exfiltration; inspected live capture does not decrypt HTTPS. No build, xUnit, replay, holdout, CI or runner. Existing floors, policies, thresholds, approvals, baseline readiness and frozen evidence preserved. Frozen R102 V1 FAILED 4/6; V2 independent reviewed PCAP pending. **Next R221-R225, then R226-R230.**

## R221-R225 candidate implementation — 2026-10-28

After verified R216-R220 remote HEAD `e187add7142346bf85b6b44d21a8e185c09c7875`, authored five consecutive remote-support/overlay and industrial-protocol precision candidates. Replaced untrusted packet Info, port guesses and global burst counts with process+host or parser-attributed L7/transport evidence, bounded per-instance dedup/out-of-order state and scoped host/Info redaction. **78 advanced xUnit facts authored, ZERO executed.** Source `e06e157af4bf2ab4d45f27657ea08ca52ecb305a`; tests `325a0b59099da484b9a3a7d5345cff2a6d89c6ad`; ScreenConnect/authority correction `2a0a0caeb5c867d388cb2db9e7043c95611566e0`. Paths and limitations: `docs/RULE_BATCH_221-225.md`.

**CANDIDATE / UNVERIFIED.** Current PacketHandler does not populate industrial L7 ApplicationProtocol; R223-R225 typed positive fixtures are contract-only and NOT live capture reachability. Process attribution for R221/R222 is unverified; /24 is not an approved-segment source. No build, xUnit, replay, holdout, CI or runner. Confidence floors, modes, thresholds, approvals, baseline readiness and frozen evidence unchanged. Frozen R102 V1 FAILED 4/6; V2 independent reviewed PCAP pending. **R216-R225 total 159 advanced facts authored, zero executed. Next R226-R230 then R231-R235.**

### Static OT parser follow-up — 2026-10-28

After R221-R225 documentation, added bounded captured-byte OT framing recognition for Modbus/TCP, DNP3 header CRC, S7 TPKT/COTP and BACnet BVLC/NPDU to `Carthago/Services/OtProtocolLight.cs` and `Carthago/Services/PacketHandler.cs`, so the four typed L7 fields can in principle originate from packet bytes rather than port-guessed ApplicationService. **11 additional parser-specific xUnit facts authored, ZERO executed**, in `Carthago.Tests/OtProtocolLightTests.cs`. Source `5e4841a47eb5f18609e5942f76c418c6283dc8c1`; tests `a6bf28a34931921a886d7bf70912030117b103b0`. Candidate parser coverage is not proof of live capture reachability, complete OT decoding, valid field accuracy or approved segments. Other OT protocol parsers remain absent. No build, test, replay, holdout, CI or runner executed. **R216-R225: 159 rule-advanced facts + 11 parser facts = 170 authored, zero executed, CANDIDATE/UNVERIFIED. Next R226-R230 then R231-R235.**

## R226-R230 candidate implementation — 2026-10-28

From verified remote HEAD `cb1dec3ae74356ea45c30bad9d35e0aa36fb70f2`, authored five consecutive candidate precision changes for EtherNet/IP ListIdentity, Profinet DCP L2, OPC UA egress, retained MQTT PUBLISH and MQTT CONNECT Will. Added bounded per-instance replay/out-of-order state, typed operation contracts, minimal captured-byte CIP/MQTT parsing, and **raw MQTT topic non-retention**. **45 advanced rule xUnit facts plus 7 wire-parser facts authored; zero executed.** Source `9ebc4e8f565a984ed5d4ca2e220f00314e31f533`, tests `6eb113168ec3b0bba4521798b157200a9b1cd7ce`, privacy correction `71d4c002c6f8482ab8c5bc450e674e4ced8fa635`. See `docs/RULE_BATCH_226-230.md` for exact paths and individual scenarios.

**CANDIDATE / UNVERIFIED.** R227 Profinet DCP is Ethernet L2 and current PacketHandler drops it; R228 OPC UA has no captured-byte parser. Their positive facts are contract-only, not proof of live reachability. MQTT parser is bounded v3.1.1 first-packet only, no TLS/stream reassembly. No builds/tests/replays/holdouts/CI/runner. Confidence floors, policies, thresholds, asset approvals, baseline readiness and frozen evidence unchanged. Frozen R102 V1 FAILED 4/6; V2 independent reviewed PCAP pending. **Next R231-R235 then R236-R240.**

## R231-R235 candidate implementation — 2026-10-28

From verified R226-R230 remote HEAD `fb95f11e9ea8b952acaf9dafeb6ba0cc97f37b30`, authored five consecutive CoAP, mDNS, printer admin, RTSP PLAY and ONVIF WS-Discovery candidates. Added bounded captured-byte CoAP/RTSP/ONVIF parsing, UDP/5353 mDNS DNS-question routing, scoped host/destinationHost/Info/path privacy, and per-instance replay/out-of-order guards. **48 advanced rule xUnit facts plus 7 parser facts authored; zero executed.** Source `77b313a762bbc495efaacc087ee1d2f998b91771`; tests `910c5003ebb18d160c88c964cf68604faaa7cb6d`; RTSP HTTP-clearing/window correction `af2ac46ca47358a7a12c9e87145b5b4d924a5473`; ONVIF-specific Probe correction `7fba4587a2ee6a699e1c5c29f5671c9184d456ee`. Paths and limitations: `docs/RULE_BATCH_231-235.md`.

**R226-R235 total: ten consecutive rules, 93 advanced rule facts + 14 parser facts = 107 authored, ZERO executed, CANDIDATE/UNVERIFIED.** R227 L2 DCP and R228 OPC UA have no live capture adapter; R235 process enrichment and new CoAP/RTSP/ONVIF/mDNS parsing remain unverified. No builds, xUnit, replays, holdouts, CI or runner. Floors, modes, thresholds, approvals, baseline gates and frozen evidence preserved. Frozen R102 V1 FAILED 4/6; V2 independent reviewed PCAP pending. **Next R236-R240 then R241-R245.**

## R236–R240 candidate implementation — 2026-10-28

From verified remote HEAD `d9cf594b1f2740f69c05f9d0f75108ebde843c5f`, authored five consecutive typed IoT HTTP/MQTT and parsed Modbus-write precision candidates. Added anchored HTTP routes, independently attributed device/hub/bridge processes, strict MQTT operation evidence, bounded replay/out-of-order protection, scoped host/Info/path/topic privacy, and client-to-server MBAP write-function classification. **52 advanced rule xUnit facts plus 4 parser facts authored, ZERO executed; CANDIDATE/UNVERIFIED.** Source `8f3e75fd63841531d9849a96046363d4fb8a864a`; tests `4c030c1f331c6dce0920cd6ea52cc04d7bce98cf`; source/parser correction and 5 additional authored facts `70a9991c094db57a3e8ae469ad2ceb7e892c3024`. Exact paths and caveats: `docs/RULE_BATCH_236-240.md`.

**No builds, xUnit, replay, holdout, CI or Windows runner.** Process enrichment, bounded HTTP/MQTT and Modbus capture behavior are not verified. No field accuracy or emitted-alert recall claimed. Confidence floors, runtime modes, thresholds, asset approvals, baseline readiness and frozen evidence preserved. Frozen R102 V1 FAILED 4/6; V2 independent reviewed PCAP pending. **Next R241–R245 then R246–R250.**

## R241–R245 candidate implementation — 2026-10-28

From confirmed R236–R240 remote HEAD `6cc2a2a5169511372e140aab91768a4eaa6f6ee1`, authored five consecutive BACnet/NTP and cleartext upload-request precision candidates. Added bounded UDP operation parsing, per-instance duplicate/out-of-order windows, typed HTTP request/filename/declared-length gates, approved backup exclusions and scoped evidence privacy. **60 advanced xUnit facts (12 per rule) plus 6 parser facts authored; ZERO executed. CANDIDATE/UNVERIFIED.** Source `1cc794dbfb0ff45ede8682f92bbe3ea89d03b2d7`, tests `2e44a879888d264270055320d6ff691a65e44c4f`, static approval/NTP correction `71c844b1408a0753aa3e0934c05e120ab63c5a5e`. Full paths and limitations: `docs/RULE_BATCH_241-245.md`.

No builds, xUnit, replay, benchmark, frozen holdout, CI or Windows runner. Content-Length does not prove transferred bytes; NTP mode-7 requests do not prove amplification. BACnet parsing is bounded and unverified. Existing confidence floors, default modes, thresholds, approvals, baseline readiness and frozen evidence preserved. R102 V1 FAILED 4/6; V2 independent PCAP pending. **Next R246–R250 then R251–R255.**

## R246–R250 candidate implementation — 2026-10-28

From verified remote HEAD `62e7e6be618d833eac076e0dc5057b611edee927`, authored five consecutive typed exfiltration request/packet precision candidates. Added bounded captured-byte FTP STOR/APPE and SMB2 WRITE recognition, conservative HTTP source-archive and IP-literal declared-body classification, instance-owned SSH packet-byte windows, replay/out-of-order protection, approved-client exclusions and redacted host/path/destination evidence. **52 advanced rule xUnit facts plus 10 wire-parser facts authored, ZERO executed; CANDIDATE/UNVERIFIED.** Source commit `0d72c519deebd55b411c825b1dd01cef3b0df1c6`; test commit `8188f4b84b8abddc33f17086861b8af68d37c0f6`. Exact paths, contracts and limitations: `docs/RULE_BATCH_246-250.md`.

**No builds, xUnit, replays, benchmarks, holdouts, CI or runner.** FTP/SMB request framing does not prove successful writes; HTTP Content-Length is declared, not delivered; R247 counts unique packet IDs and packet lengths, not TCP-delivered bytes, and requires unverified process attribution. Floors, default modes, thresholds, asset approvals, baseline readiness and frozen evidence unchanged. Frozen R102 V1 FAILED 4/6; V2 independent reviewed PCAP pending. **Next R251–R255 then R256–R260.**

## R251–R255 candidate implementation — 2026-10-28

From verified R246–R250 remote HEAD `f6964db23175dbd95d7127ee128dcb795754af53`, authored five consecutive cleartext HTTP exfiltration request candidates. Replaced untrusted Info/port guesses and global first-seen with typed multipart request, instance-first domain, entropy path without token evidence, query-only base64, bounded repeated small declared-body requests, and UTC off-hours large declared-body classification. **52 advanced xUnit facts authored, ZERO executed; CANDIDATE/UNVERIFIED.** Source `3a8b3202742a44efbbc20398c925294ff90a2a4f`; first-seen/process provenance correction `d88fbaa8f1c36b3e3f9f7ed9a163a93720d720fa`; tests `2a727a2924577d3c5519b2e21691f1055e09d95f`. Paths and limitations: `docs/RULE_BATCH_251-255.md`.

**No builds, xUnit, replays, benchmarks, holdouts, CI or runner.** R251 instance-first is not approved baseline novelty; R253 observes query only, not POST body; R254/R255 declared Content-Length does not prove delivery; UTC off-hours is not local asset schedule. Process enrichment and new source paths unverified. Confidence floors, modes, thresholds, asset approvals, baseline readiness and frozen evidence preserved. Frozen R102 V1 FAILED 4/6; V2 independent reviewed PCAP pending. **R246–R255: ten consecutive rules, 104 advanced rule facts plus 10 parser facts = 114 authored, ZERO executed. Next R256–R260 then R261–R265.**

## R256–R260 candidate implementation — 2026-10-28

From verified remote HEAD `ac1870bc2fd84bb61e419178d8e5d82072461a67`, authored five consecutive typed network-evidence candidates: repeated internal archive-named HTTP requests (R256), exact credential-tool process plus parsed external upload co-observation (R257), ICMP unreachable type/code bursts (R258), TCP RST-flag bursts (R259), and JA4T SYN fingerprint change relative to instance-first observation (R260). Added bounded detector-instance replay/out-of-order windows, typed contradictions, and evidence redaction. **59 advanced xUnit facts authored, ZERO executed, CANDIDATE/UNVERIFIED.** Source `7372869c3f69126aee505917c60aa0af5c98604f`; tests `58ec8142a8fef5c0a2cd954b61e280d679b99632`; fixture correction `088c85ddc0172aa798367730308748d9e9f5dbea`; typed and window correction `10dc2c66bec27a10cf274832a24823d1a937acc8`. Exact paths and cases: `docs/RULE_BATCH_256-260.md`.

**No builds, xUnit, replays, benchmarks, frozen holdouts, CI, GitHub Actions or Windows runner.** R256 repeated declared HTTP requests do not prove staging/bytes delivered; R257 has no verified upstream credential alert chain; R260 instance-first JA4T change is not approved baseline rarity and live JA4T population is unverified. Confidence floors, modes, thresholds, approvals, baseline readiness and frozen evidence unchanged. Frozen R102 V1 FAILED 4/6; V2 independent reviewed PCAP pending. **Next R261–R265 then R266–R270.**


## R261–R265 candidate implementation — 2026-10-28

From verified R256–R260 remote HEAD `89e8682e68b0ed0fd6a45cfdd6c26066a518ce0e`, authored five consecutive typed TTL/fragment and proxy/Tor/VPN attribution candidates. **47 advanced xUnit facts authored (9+10+9+9+10), ZERO executed; CANDIDATE/UNVERIFIED.** Source `e0c94719367a281d156b369b888591343281968f`; tests `e7d75dc9f1ed3ec1aaf8fac7a15e17565d739459`. Paths, individual test cases, typed provenance and limitations: `docs/RULE_BATCH_261-265.md`.

**Critical capture limitation:** R262 fragment fields are synthetic typed contract-only: PacketHandler drops fragmented frames and does not populate them. R261 TTL is observable but path change is not spoofing proof. R263/R264 process attribution remains unverified; R264 is Tor-process egress, NOT verified directory/guard identity. R265 TLS SNI provider contact does not establish VPN tunnel use. No build, xUnit, replay, holdout, CI or runner. Floors, modes, thresholds, approvals, baseline readiness and frozen evidence unchanged; frozen R102 V1 FAILED 4/6, V2 reviewed independent PCAP pending. **Next R266–R270 then R271–R275.**


## R266–R270 candidate implementation — 2026-10-28

From verified R261–R265 remote HEAD d25b1329d6150b39f908217e811086aa19631016, authored five consecutive typed process/DNS precision changes and a fail-closed pipeline-tamper safety gate. **62 advanced xUnit facts authored (12+12+14+14+10), ZERO executed; CANDIDATE/UNVERIFIED.** Source 7babe8b2bec3919b5764bdfc122eecb177af50ac; source corrections 756be6f511041f52740e64bb0967d40122bbddc1 and c39c7a8133b7f43e54e5b7807708ca263290f650; tests 871432c905d2201c819f98f2ff2561912ed05d96. Exact paths, test scenarios and caveats: docs/RULE_BATCH_266-270.md.

**Critical contract limitation:** R266–R268 process/PID evidence is not populated by PacketHandler; their positives are synthetic typed contract-only, not live reachability. R266 first-observed is detector-instance memory, not new process launch or approved baseline. R269 is repeated typed DNS SERVFAIL/REFUSED for exact security-update QNAME, not proven deliberate blocking or endpoint update failure. R270 deliberately fails closed with 10 negative/policy facts because no trusted structured pipeline-tamper producer exists; no positive was invented. **No builds, xUnit, replay, benchmark, holdout, CI, GitHub Actions or Windows runner.** Confidence floors, modes, thresholds, approvals, baseline readiness and frozen evidence unchanged. Frozen R102 V1 FAILED 4/6, V2 reviewed independent PCAP pending. **Next R271–R275 then R276–R280.**

## R271–R275 candidate implementation — 2026-10-28

From verified remote HEAD `2b0ddd89339cbbc55af0bcc0785101ea35eba9de`, authored exact source-IP threat-feed/reputation corroboration (R271) and intentionally fail-closed correlation/IdP controls (R272–R275) where trustworthy producers are absent. **60 advanced xUnit facts authored (14+11+11+11+13), ZERO executed; CANDIDATE/UNVERIFIED.** Source `eef05eb707b50bcafcb536ae58d12d046ce0be52`; tests `5ee517694f5e162269ea50a56a206808ea0e3ab4`. Full paths and test scenarios: `docs/RULE_BATCH_271-275.md`.

R271's typed helper positive is contract-only; live feed snapshot freshness and manual source-IP reputation population are unverified. R272 lacks trusted emitted-rule correlation; R273/R274 lack IdP/MFA audit events; R275 lacks authenticated device-flow abuse evidence and HTTPS decryption. **All four fail closed; no positive attack/identity event invented.** Existing R275 legacy positive/replay expectation conflicts with fail-closed semantics and was not changed; owner-approved future reconciliation required. No builds, tests, replay, holdout, CI or runner. Floors, modes, thresholds, approvals, baseline readiness and frozen evidence preserved. R102 V1 FAILED 4/6; V2 independent reviewed PCAP pending. **Next R276–R280 then R281–R285.**

## R276–R280 candidate implementation — 2026-10-28

From verified R271–R275 remote HEAD `88b2fc52ce8bdaf303a43bd2eb752c553c058c64`, authored five conservative identity precision changes that intentionally fail closed without authenticated consent, legacy-protocol AUTH, account failure, credential-stuffing or session-reuse telemetry. **55 advanced xUnit facts authored (11 each), ZERO executed; CANDIDATE/UNVERIFIED.** Source `27ba609074a0c271904b9ff5fe0f3310e982d094`; tests `eb116e0c0862ac68f53e17216eba9982ec37a2ad`. Exact paths, cases, missing producers and limitations: `docs/RULE_BATCH_276-280.md`.

No positives were invented: network packets, URL/query strings, User-Agent, cookies and GeoIP do not establish IdP consent, authenticated failures, account spray or session replay. No builds, xUnit, replays, benchmarks, holdouts, CI, GitHub Actions or runner. Floors, modes, thresholds, approvals, baseline readiness and frozen evidence unchanged; R102 V1 FAILED 4/6, V2 independent reviewed PCAP pending. **R271–R280 combined 115 authored unexecuted advanced facts; next R281–R285 then R286–R290.**


## R281-R285 candidate implementation — 2026-10-28

From verified HEAD `bfc3840d233f18eeecf3e620a3b2d4915b2a02ef`, authored five fail-closed identity/SCIM precision candidates. **60 advanced xUnit facts authored (12 per rule), ZERO executed; CANDIDATE/UNVERIFIED.** Source `1714a18f3d3ab40e6aae64f63646b77476034790`; tests `bdd03951ae6a135c520efccb21ad0f0ccd68ca33`; exact paths, missing trusted producers and scenarios: `docs/RULE_BATCH_281-285.md`. No authenticated positive events invented; no build, tests, replay, holdout, CI or runner. Floors, modes, approvals, baseline readiness and frozen evidence preserved; R102 V1 FAILED 4/6, V2 reviewed PCAP pending. **Next R286-R290 then R291-R295.**


## R286-R290 candidate implementation — 2026-10-28

From verified R281-R285 remote HEAD `f67bafb70607f8908f517be23193fec5a6f6dc08`, authored five fail-closed LDAP, Kerberos, NTLMv1, RADIUS and Citrix exploit-probe precision candidates. **60 advanced xUnit facts authored (12 per rule), ZERO executed; CANDIDATE/UNVERIFIED.** Source `8fe3e00586d7405da8c1b46da04a46e5f3edb66f`; tests `f901a120ba262467a8fb4fcd8fd332408190da7b`; exact paths, missing parsers and scenarios: `docs/RULE_BATCH_286-290.md`. No successful authentication or exploit positive events invented; no build, tests, replay, holdout, CI or runner. Floors, modes, approvals, baseline readiness and frozen evidence preserved; R102 V1 FAILED 4/6, V2 reviewed PCAP pending. **R281-R290 combined 120 authored unexecuted facts; next R291-R295 then R296-R300.**


## R291-R295 candidate implementation — 2026-10-28

From verified remote HEAD `c1e2019cb0176220470041fc35aaab9552538fd3`, authored five fail-closed appliance-exploit and Kubernetes API provenance candidates. **70 advanced xUnit facts authored (14+14+14+14+14), ZERO executed; CANDIDATE/UNVERIFIED.** Generic Fortinet/GlobalProtect paths and CVE strings do not establish exploit signatures or affected targets; Kubernetes HTTP API paths do not establish authenticated anonymous discovery, secrets-access outcomes or pod-exec sessions. No trusted exploit/appliance or Kubernetes audit producer is connected. No positive invented. Exact paths and scenarios: `docs/RULE_BATCH_291-295.md`. No builds, tests, replay, holdout, CI or runner. Floors, modes, approvals, baseline readiness and frozen evidence preserved; R102 V1 FAILED 4/6, V2 independent PCAP pending. **Next R296-R300 then R301-R305.**


## R296-R300 candidate implementation — 2026-10-28

From verified R291-R295 remote HEAD `97957516a86ae32b3ca512dd49340447fab7bbeb`, authored five fail-closed Kubernetes port-forward, service-account token exfiltration, container runtime socket, Docker container-create and etcd client-access precision candidates. **70 advanced xUnit facts authored (14+14+14+14+14), ZERO executed; CANDIDATE/UNVERIFIED.** No trusted Kubernetes operation audit, token delivery correlation, runtime socket inventory, Docker API result or etcd authenticated endpoint/segment provenance producer exists. No positives invented. Exact paths and scenarios: `docs/RULE_BATCH_296-300.md`. No builds, tests, replay, holdout, CI or runner. Floors, modes, approvals, baseline readiness and frozen evidence preserved; R102 V1 FAILED 4/6, V2 independent PCAP pending. **R291-R300 combined 140 authored unexecuted advanced facts; next R301-R305 then R306-R310.**
