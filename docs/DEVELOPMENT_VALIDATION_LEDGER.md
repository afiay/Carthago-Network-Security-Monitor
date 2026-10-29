# Carthago Development and Deferred Validation Ledger

**Owner-controlled execution gate:** PARKED. All builds, .NET/xUnit runs,
benchmarks, replays, holdout evaluations, source-contract checks and GitHub
Actions jobs require explicit authorization from the project owner
("now it's test time"). Preparing checks and documenting them is permitted;
their presence does not imply successful execution.

**Development track:** Complete the R102 binary-DNS wire-name and original
capture provenance foundation **before** expanding the remaining detector
rules. Keep the single existing branch
`feature/carthago-reliability-hardening`. Preserve the frozen V1 failure,
all R102 thresholds/confidence weights and benign controls, and V2
`PENDING_EXTERNAL_CAPTURE_AND_REVIEW` until separate authorization.

This is the **central step ledger**, not a replacement for detailed design,
protocol, fixture or forensic source documents. Each future change must append
a dated entry describing the changed file/commit, decision, authored test,
validation command, parked or observed outcome, evidence boundary, and next
gate. Never mark an unexecuted check green.

**Compile-time parking:** Stages 2, 3 and 4 have regression source files
already authored, but each is surrounded by a distinct C# preprocessor guard:
`CARTHAGO_DNS_WIRE_STAGE2`, `CARTHAGO_DNS_WIRE_STAGE3`, or
`CARTHAGO_DNS_WIRE_STAGE4`. This is intentional: `dotnet test --filter`
filters *execution*, not which test sources compile, so future contract
references would otherwise prevent earlier stages from building. During
explicit test time, enable only the target stage through
`-p:DefineConstants=CARTHAGO_DNS_WIRE_STAGEn`; observe RED, implement the
feature, observe GREEN, then remove that stage's guard in a separate commit
so all subsequent normal regression runs include its tests. Do not report
tests as passing merely because they were preprocessor-excluded.

## Current evidence and decisions — 2026-10-29

| ID | Item | Evidence / state | Next gate |
| --- | --- | --- | --- |
| E01 | Original Korving-F `bind9/dns.pcap` | SHA-256 `b9c5ec5b6a50facb8719ffe47656d2cda0f0704ed08d91130c8b48a3e0ddf102` pinned; source Git blob `c061d953b9e21068031d604b9c1001ddcd1cfa53` | Private original capture must be present for each future selected-frame audit |
| E02 | Binary-name research | 15,942 frames, 7,991 TXT questions, 5,335 names passing the legacy printable policy, 2,656 wire-valid binary-name exclusions; TShark 4.2.2 and 4.6.9 corroboration recorded in source review | Validate codec and importer against original frame bytes |
| E03 | Selected-frame independent corroboration | Separate raw-frame decoder matched TShark 4.2.2 `jsonraw` for **121/121** DNS messages, checked QTYPE 121/121, including 41 printable and 80 text-policy-excluded questions; no names or source IPs published | Repeat selected-frame test with production PowerShell contract and TShark 4.6.9 on CARTHAGE, once authorized |
| E04 | Apparently separate sources | Both PCAP source/root groups share 3,977 identical distinct QNAMEs; **not** independent malicious clients merely because two source addresses appear | Collect separate originating-client/session evidence and human label/licensing review |
| E05 | Frozen V1 / candidate V2 | Preserve known R102 V1 miss; V2 contains eight immutable R118/R163 predecessor fixtures and four unapproved R102 slots, **0/4** candidate approvals | Never auto-promote, relabel, import or freeze |
| D01 | Selected design | Approach A: canonical Base64 **per original DNS label**, exact label octets, ASCII-case-only identity, optional private provenance, no reversible fields in ordinary telemetry | Execute test-first implementation stages |
| D02 | Why R102 first | It currently loses binary label octets and therefore misses independent detection evidence; broad rule expansion would compound the unresolved accuracy risk | Complete and review R102 pathway before adding batches |
| D03 | One GitHub Actions entry point | Reuse `.github/workflows/carthago-detection-quality.yml` with an authorization-gated profile selector; retire the redundant focused, one-shot, and baseline YAML definitions from the development branch | No workflow dispatch until owner authorization |

## Parked implementation and validation matrix

All commands are **prepared instructions**, not evidence of executions.
The exact implementation plan lives in
`docs/superpowers/plans/2026-10-29-dns-wire-name-provenance.md`.

| Stage | Planned implementation / contract | Parked validation and acceptance | Status |
| --- | --- | --- | --- |
| 1 | `DnsWireNameCodec`: original byte labels, canonical Base64, 255-octet DNS limit, compression bounds, ASCII-only case identity | `dotnet test Carthago.Tests/Carthago.Tests.csproj -c Release --filter "FullyQualifiedName~DnsWireNameCodecTests"`; observe expected **RED** before code, then **GREEN** | Test authored, **RED NOT RUN** |
| 2 | `PacketHandler` + `TrafficRecord`: preserve binary bytes while keeping safe legacy `DnsQname` and default JSON redaction | Focus `DnsWirePacketTests` with `-p:DefineConstants=CARTHAGO_DNS_WIRE_STAGE2`, plus `PacketHandlerLinkLayerTests`; validate UDP/TCP and no replacement characters | Test authored, compile-parked; **RED NOT RUN** |
| 3 | R102-only opt-in to wire-based evidence and original-byte entropy/distinctness, preserving existing thresholds | Focus `R102BinaryDnsPrecisionTests` with `-p:DefineConstants=CARTHAGO_DNS_WIRE_STAGE3` alongside existing correlation/accuracy/diagnostic tests; precision, recall, F1 and privacy review | Ten named test methods authored, compile-parked; **RED NOT RUN** |
| 4 | Private replay hydrator with strict version, legacy-name consistency and default-JSON exclusion | Focus `DnsWireReplayHydratorTests` with `-p:DefineConstants=CARTHAGO_DNS_WIRE_STAGE4` plus pinned V2 contract; verify conflicting names fail closed | Nine named test methods authored, compile-parked; **RED NOT RUN** |
| 5 | TShark original-frame/private-PCAP decoder and bounded binary-name source inspector | `powershell.exe -NoProfile -File scripts/verify-dns-wire-source-contract.ps1 -TsharkPath 'C:\Program Files\Wireshark\tshark.exe'`; compare frame, question ordinal, name octets, QTYPE and transport | Synthetic test authored; **RED NOT RUN**; decoder/inspector implementation pending |
| 6 | Importer/auditor exact PCAP hash, frame/ordinal, byte labels, source/session independence and strict fixture schema | Focus `SyntheticHoldoutV2ContractTests` and source contract with `-IncludeV2Provenance`; reject tampering, same-frame reuse and mirrored clients | Source-binding and logical-client review cases authored, **RED NOT RUN**; importer/auditor enforcement and rights cases pending |
| 7 | Versioned V2 readiness/evaluator/freeze integration; preserve V1 hashes, acceptance floor and V2 pending | V2 contract plus readiness-only inspection; **no freeze/evaluation** without separate owner approval | DESIGN READY / PARKED |
| 8 | Whole-feature acceptance | One controlled Windows full regression, benchmark/replay and separately pinned holdout **only at test time**; record counts, warnings, SHA and original frozen V1 miss | NOT AUTHORIZED |
| B01 | Remaining five-rule development batches | `scripts/verify-all-rule-batches.ps1 -HoldoutVersion v1`; for each rule require at least five advanced cases; run the suite exactly once when authorized | BACKLOG, not the active path |

## One centralized GitHub Actions workflow

The workflow has **only** `workflow_dispatch`: there is no automatic
`push`, `pull_request` or scheduled test. Every job is further guarded
by the exact explicit input `authorization = NOW_TEST_TIME`.
Only CARTHAGE may execute a job; a hostname check precedes checkout.
No test logs or replay artifacts are uploaded; private output stays on
the runner. An authorization token **is not** a substitute for the
project owner's decision to initiate the run.

| Profile | Scope | Current gate |
| --- | --- | --- |
| `dns-wire-codec` | Stage 1 focused RED/GREEN | PARKED |
| `dns-wire-packet` | Stage 2 focused parser compatibility | PARKED; stage-specific preprocessor symbol needed |
| `r102-accuracy` | Stage 3 R102/diagnostics regression | PARKED; stage-specific preprocessor symbol needed |
| `dns-wire-replay` | Stage 4 private replay hydration and pinned V2 contract | PARKED; stage-specific preprocessor symbol needed |
| `dns-source-contract` | Stage 5 synthetic PCAP and TShark | PARKED; source-contract script authored, decoder missing by design |
| `v2-contract` | Stage 6/7 strict V2 schema plus opt-in original-frame source binding | PARKED; no dispatch or capture access |
| `v2-readiness` | Read-only V2 manifest/source readiness | PARKED |
| `rule-batches` | Complete advanced five-rule and frozen V1 acceptance | PARKED |
| `baseline` | Prior main Windows restore/build/xUnit baseline | PARKED |
| `detection-quality` | Previous quiet build, alert-level replay, pinned holdout and benign false-positive checks | PARKED |
| `full-verification` | Previous one-shot full verifier plus separate frozen V1 holdout | PARKED |

Manual `workflow_dispatch` requires a workflow available on the repository's
default branch. The existing detection-quality workflow already exists
there; the **new profile selector on the feature branch is not certified
operational** until GitHub resolves the selected ref to the new definition.
No dispatch may be used as a probe before explicit test time.

The legacy `windows-ci.yml` previously ran on main pushes/PRs. Its
automatic trigger is intentionally parked in this consolidation; restoring
continuous integration after approval is a distinct owner-controlled change.
Deleting obsolete YAML definitions does **not** erase their recoverable
Git history.

## Chronological step record

| Step | Commit / evidence | Change or decision | Execution state |
| --- | --- | --- | --- |
| 2026-10-29 01 | `4e83d33` | Approved binary DNS-name design | Design only |
| 2026-10-29 02 | `58d94a1` | Seven-stage lossless DNS/provenance implementation plan | Plan only |
| 2026-10-29 03 | `a694b6b` | Stage 1 byte-perfect codec regression tests | Authored; **not executed** |
| 2026-10-29 04 | `0db83af` | Dedicated focused CI temporarily introduced | Replaced by centralized workflow |
| 2026-10-29 05 | `51fcbac` | Parked focused CI; earlier run `40895663121` cancelled and replacement job skipped | **No test executed** |
| 2026-10-29 06 | `2f03976` | Parked legacy one-shot full verifier; earlier run `40792433511` cancelled and replacement job skipped | **No test executed** |
| 2026-10-29 07 | `37f8023` | Centralized the existing manual detection-quality workflow with **eleven** explicit profiles and a required owner authorization gate | Authored; **not dispatched or executed** |
| 2026-10-29 08 | `e058af0` | Removed temporary focused DNS workflow after cancelling its queued run | Recoverable in Git; no tests |
| 2026-10-29 09 | `71082e3` | Removed obsolete one-shot full-verification workflow after cancelling its queued run | Recoverable in Git; no tests |
| 2026-10-29 10 | `7c0d0fd` | Removed automatic main Windows CI workflow from feature branch; baseline command remains a manual profile | Recoverable in Git; no tests |
| 2026-10-29 11 | `f8852f0` | Prepared six synthetic UDP/TCP, legacy-ASCII, embedded-dot and JSON-privacy contracts for Stage 2 | **RED NOT RUN**; no production implementation |
| 2026-10-29 12 | `09e558a` | Prepared ten named R102 binary-accuracy/negative-control test methods (twelve parameterized xUnit cases); no external PCAP embedded | **RED NOT RUN**; no production implementation |
| 2026-10-29 13 | `b798a36` | Prepared nine named private V2 replay hydration tests (twelve parameterized cases): strict version, legacy/wire agreement, tamper rejection, transactionality and default JSON privacy | **RED NOT RUN**; no production implementation |
| 2026-10-29 14 | `cbcf3e1`, `1d84db8`, `e98e64d` | Keep Stage 2/3/4 tests authored but excluded from the default compiler until their own test-first activation | **No execution**; guards must be removed after each stage goes GREEN |
| 2026-10-29 15 | `60a4729` | Add exact stage-specific compiler symbols to the three manual validation profiles | **Not dispatched** |
| 2026-10-29 16 | `093dd53` | Author deterministic six-frame synthetic UDP/TCP PCAP, TShark `jsonraw` corroboration and private source-bound question assertions in `scripts/verify-dns-wire-source-contract.ps1` | **RED NOT RUN**; no source decoder implemented |
| 2026-10-29 17 | `853c37c` | Extend the same source test script with a separate Stage 6 switch, exact two-record original-frame binding and nineteen negative provenance scenarios | **RED NOT RUN**; binding function not implemented |
| 2026-10-29 18 | `2483f8f` | Connect Stage 6's opt-in source binding after the V2 .NET contract under the **same** manual centralized GA profile | **Not dispatched**; no additional workflow YAML |
| 2026-10-29 19 | `3aa5d1a` | Add seven synthetic logical-source overlap, session, origin, frame-reuse and byte-identity review cases to existing opt-in Stage 6 source test | **RED NOT RUN**; logical-source classifier not implemented |

**Stage 2 deferred command:** `dotnet test Carthago.Tests/Carthago.Tests.csproj -c Release -p:DefineConstants=CARTHAGO_DNS_WIRE_STAGE2 --filter "FullyQualifiedName~DnsWirePacketTests|FullyQualifiedName~PacketHandlerLinkLayerTests"`. It is not authorization to run; record missing-contract RED and final GREEN separately when the owner permits.

### R102 deferred evidence and privacy checkpoint

- **Source:** a synthetic-only test module at `Carthago.Tests/R102BinaryDnsPrecisionTests.cs` on the same development branch; no live packet or frozen holdout values are duplicated.
- **Positive contract:** three independently observed high-entropy binary-label TXT names from one attributed source and root must produce distinct-count evidence 1, 2, 3 without lowering `PrecisionProfile.MinimumConfidence = 80` or promoting an unready baseline out of Shadow.
- **Negative contracts:** identical packet-ID replay, new packet with the same name, case-only label variations, and a second observed source address must not inflate per-client distinct-name confidence. Unattributed UDP/TCP, malformed/noncanonical Base64, and 40-byte labels that expand to 56 Base64 characters must not become positive evidence. Binary ACME validation remains excluded.
- **Privacy contract:** binary-name events must not publish reversible Base64, synthesized `?`/replacement-character names, raw source identity, or the generic `dns.qname` evidence item. Structural length/entropy/count metadata remains available. The current shared `DnsPrecisionDetectionRuleBase.MatchDns` emits text-based `dns.qname`, and `DetectionEvent` carries source IP metadata; R102 needs a narrow privacy-safe event path before any binary-name promotion. This is an **identified design risk**, not a tested or fixed defect.
- **Pending execution:** run `dotnet test Carthago.Tests/Carthago.Tests.csproj -c Release -p:DefineConstants=CARTHAGO_DNS_WIRE_STAGE3 --filter "FullyQualifiedName~R102BinaryDnsPrecisionTests|FullyQualifiedName~R102DistinctTxtCorrelationTests|FullyQualifiedName~R102AdvancedAccuracyBatchTests|FullyQualifiedName~DnsReplayTelemetryDiagnosticsTests"` on verified CARTHAGE only after explicit test-time authorization, with first-failure and final-success evidence and no new warnings. No detection-quality estimate is valid until the labeled replay and benign cohorts have been evaluated separately.

### Private replay deferred-hydration checkpoint

- **Source:** synthetic in-memory `Carthago.Tests/DnsWireReplayHydratorTests.cs`; no source PCAP, corpus file or default serializable raw label property is added.
- **Positive contract:** a sample with the explicit `dnsWireNameEncoding = labels-base64-v1` marker can hydrate exact original Base64 label strings into an in-memory `RuleReplaySample`, preserving the legacy ASCII field when it denotes the same case-insensitive wire name.
- **Negative contract:** absent/unsupported version, contradicting `DnsQname`, invalid padding bits, unexpected private debug fields, misaligned record counts and mixed valid/invalid multi-record input must fail closed with **no partially hydrated records**. Historical legacy samples lacking wire metadata remain unchanged.
- **Privacy contract:** the default `System.Text.Json` serialization of a hydrated replay sample must omit the reversible label collection. Hydration is explicit and private; ordinary replay deserialization must not silently authorize wire values.
- **Pending execution:** run `dotnet test Carthago.Tests/Carthago.Tests.csproj -c Release -p:DefineConstants=CARTHAGO_DNS_WIRE_STAGE4 --filter "FullyQualifiedName~DnsWireReplayHydratorTests|FullyQualifiedName~SyntheticHoldoutV2ContractTests"` on CARTHAGE after owner authorization, observing RED before any hydration implementation and GREEN after minimal implementation. Existing V1 and pending V2 fixture hashes remain frozen.

### Stage 5 deferred independent source-contract checkpoint

- **Authored test:** `scripts/verify-dns-wire-source-contract.ps1` (`093dd53`), **not executed**. The test constructs exactly six synthetic raw-IPv4 PCAP frames in an uniquely named OS temporary directory: binary TXT label with embedded `0x2e` and `0xff`; two distinct question ordinals in one UDP DNS message with a backward compression pointer; an in-bounds forward pointer; a self-referential pointer; a length-prefixed TCP AAAA question; and a truncated label.
- **Independent oracle:** hardcoded expected per-label RFC 4648 Base64 strings and QTYPEs, not values obtained from the planned decoder. TShark's `-T jsonraw` must return byte-identical original DNS messages for frames 1, 2 and 5; its independently exported frame/QTYPE and UDP/TCP fields must match, including ordered QTYPEs 16 and 1 in the two-question frame. TShark textual QNAMEs are explicitly not an oracle. The test captures temporary PCAP SHA-256 and verifies decoder provenance against it.
- **Proposed helper API:** `Read-DnsWireQuestion -CapturePath -FrameNumber -QuestionIndex -TsharkPath` must return one private structured object exposing `CaptureSha256` (lowercase hex), `FrameNumber`, zero-based `QuestionIndex`, `DnsWireLabelsBase64`, `Qtype`, `Transport` (`UDP`/`TCP`), `SourceAddress`, `DestinationAddress`, `SourcePort` and `DestinationPort`. Four source-bound questions must match their exact fixture labels, destination port and source addresses/ports. Five negative selections must reject: nonexistent question ordinal, forward pointer, cyclic pointer, truncated label and nonexistent frame. Exception messages and ordinary console output must not reveal original names, addresses or reversible values.
- **Privacy and lifecycle:** test fixtures use documentation-only IP ranges, stay under a unique OS temp directory and are removed by `finally`; no PCAP or per-name evidence is committed. A deterministic synthetic fixture is **not** independent malicious ground truth, source-license approval, or frozen V2 evidence. No detector is invoked. A future source audit must independently select and verify frames from the pinned `b9c5ec5b6a50facb8719ffe47656d2cda0f0704ed08d91130c8b48a3e0ddf102` original PCAP.
- **Parked RED then GREEN:** after explicit owner test-time approval and CARTHAGE/TShark verification, run `powershell.exe -NoProfile -File .\scripts\verify-dns-wire-source-contract.ps1 -TsharkPath 'C:\Program Files\Wireshark\tshark.exe'`. Initially expect missing `scripts/DnsWirePcap.psm1` (`decoder-not-implemented-red`) **only after** the independent synthetic/TShark checks pass; do not call missing-TShark or malformed-fixture failures a valid RED. Implement the minimal decoder, observe GREEN, then extend the inspector's wire-invalid-versus-text-excluded accounting. Record exact TShark version, PCAP hash, return code, failing assertion or passing count and warnings in this ledger; no result may be inferred from this unexecuted contract.
- **Ruling:** the synthetic script is the next RED-first deliverable; the helper module and production inspector remain unimplemented because the owner explicitly parked validation. The central workflow has a matching `dns-source-contract` profile but no job may be dispatched yet. If its expected TShark field representation differs in the installed version, compare against the original raw message and update the contract with an auditable reason before any GREEN claim.

### Stage 6 deferred original-frame binding and provenance checkpoint

- **Authored contract:** optional `-IncludeV2Provenance` in the existing `scripts/verify-dns-wire-source-contract.ps1` (`853c37c`). Without this switch, the Stage 5 check and its expected RED are unchanged. The opt-in mode adds two synthetic records bound to original frame/question pairs `(1,0)` and `(2,1)`, with separately captured SHA-256, transport, ports, source/destination and exact canonical per-label Base64.
- **Proposed narrow integration API:** `Confirm-DnsWireCandidateBinding -CapturePath -Provenance -Records -TsharkPath` in the future private `DnsWirePcap.psm1` module; return only a bounded `MatchedQuestionCount` and `CaptureSha256`, with no raw QNAME/address/label in normal results. This is a source-fidelity check for the existing PowerShell V2 importer/auditor, **not** an independent-label, source-rights, logical-client or freeze approval. Reuse the same original-frame decoder for selected question ordinals instead of trusting mutable JSON names.
- **Nineteen negative cases:** altered capture hash; wrong frame; wrong question ordinal; misaligned ordinal array; unsupported encoding version; changed valid Base64 bytes; noncanonical Base64; changed QTYPE; changed source address/port; changed UDP/TCP flags; reused frame/ordinal; missing originating-client label or collection session; unrecognized vantage; non-HTTPS independent-client evidence URI; unexpected private debug field; and missing original PCAP. A failure must reveal no reversible DNS names or source addresses. The validation contract itself remains unexecuted and may require correction after the first authorized run.
- **Logical-source review regression authored:** `3aa5d1a` extends the *same* `-IncludeV2Provenance` mode with seven independent synthetic scenarios: mirrored complete name sets at different observed IPs and with different letter casing/name order; disjoint groups; partial QNAME overlap; identical recording sessions with different source IPs; the same originating-client label with different sessions; reused capture SHA/frame references across sources; and non-ASCII label bytes that must remain distinct under ASCII-only DNS case folding. The outputs must be bounded metadata counts and risk flags only, never raw names, origin labels, sessions or addresses.
- **Proposed advisory API:** `Measure-DnsWireMaliciousSourceIndependence -Candidates` (future private helper) returns `CompleteNameSetOverlap`, `SharedCollectionSession`, `SameOriginatingClient`, `ReusedOriginalFrame`, `OverlappingDistinctNameCount`, `RequiresAnalystReview`, and `IndependenceApproved`. All synthetic results must require manual analyst review and have `IndependenceApproved = false`, **including disjoint sources with apparently distinct clients and sessions**. This separate review classifier must not claim source authenticity, construct a malicious label, or auto-promote a fixture. Its record-name comparisons use canonical Base64 label bytes with ASCII-only case identity, not textual `dns.qry.name` or source-IP inequality.
- **Still to author before Stage 6 GREEN:** behavior-level *actual importer/auditor* rejection cases for mirrored malicious groups, session collisions and original-frame reuse across complete four-slot V2 candidates, plus unreviewed license/classification and strict sample/provenance allowlists. The new advisory test checks a proposed common risk function; it does **not** yet demonstrate that `audit-holdout-v2-candidates.ps1` enforces those risks. The existing auditor presently relies on textual `dns.qry.name` and distinct source IP checks; these do **not** prove binary-name byte equality or logical-client independence. Preserve existing two-benign/two-malicious, confidence-floor and label/rights protections while extending checks.
- **Parked commands:** first finish Stage 5 RED→GREEN after explicit owner approval. Then run `powershell.exe -NoProfile -File .\scripts\verify-dns-wire-source-contract.ps1 -TsharkPath 'C:\Program Files\Wireshark\tshark.exe' -IncludeV2Provenance` for Stage 6 RED before implementing `Confirm-DnsWireCandidateBinding`, and rerun for its source-binding GREEN. Next observe the distinct expected RED for missing `Measure-DnsWireMaliciousSourceIndependence`, implement the minimal review-only classifier, and observe overall GREEN without source approval. The sole GA `v2-contract` profile (`2483f8f`) contains this optional source contract in addition to `SyntheticHoldoutV2ContractTests`, but it is **not authorized** for dispatch.
- **Connectivity boundary:** owner reported being on a public connection and expressly withheld permission for tests. No current session test, live capture, TShark run, holdout evaluation, GitHub Actions run, source upload or runner activity occurred. This authorizes only reviewable source/test preparation and documentation; the original pinned PCAP and private evidence must remain local/ignored and V2 stays `PENDING_EXTERNAL_CAPTURE_AND_REVIEW`, 0/4 approved.

**Read-only state check:** the feature branch now lists exactly one file in
`.github/workflows/`: `carthago-detection-quality.yml`. The cancelled
workflow runs have no recorded execution steps; their cancellation/skipped
conclusions are not counted as test evidence. The single central workflow
has not been dispatched.

## Required future entry template

- **Date / step ID / commit / file:** exact identifiers; one file per code commit.
- **Intent and boundary:** what was changed, and what intentionally remains unchanged.
- **Regression authored:** test name, synthetic scenarios, negative controls, privacy checks.
- **Execution status:** `PARKED`, `RED OBSERVED`, `GREEN OBSERVED`, or
  `FAILED`; never infer a result from source review or a successful commit.
- **When authorized, validate:** exact command, CARTHAGE hostname, source
  SHA, exit code, counts and private artifact location; document any known
  preexisting failures separately from regressions.
- **Decision / next gate:** threshold, provenance, licensing, source-label,
  or freeze approval that remains outstanding.

### Authoritative references

- RFC 1035: https://www.rfc-editor.org/rfc/rfc1035
- RFC 2181 (DNS name character/octet rules): https://www.rfc-editor.org/rfc/rfc2181
- RFC 4343 (ASCII case-insensitive DNS identity): https://www.rfc-editor.org/rfc/rfc4343
- RFC 4648 (Base64): https://www.rfc-editor.org/rfc/rfc4648
- GitHub manual workflow dispatch: https://docs.github.com/en/actions/how-tos/manage-workflow-runs/manually-run-a-workflow


### 2026-10-29 — Stage 6 actual auditor harness checkpoint (PARKED)

- **Commits:** `6aa9f01` authored `scripts/verify-v2-auditor-enforcement.ps1`; `5fbe6ce` documented its implementation scope and verification hazards in `docs/STAGE6_V2_AUDITOR_ENFORCEMENT_CONTRACT_20261029.md`.
- **Scope:** A synthetic four-slot original-PCAP harness calls the actual `audit-holdout-v2-candidates.ps1`, using manifest-declared sample identifiers. Local-only generated IPv4/UDP TXT PCAPs, sample records, and provenance JSON; no real capture or personal address.
- **Prepared scenarios:** BASELINE control, A01 mirrored malicious name sets across distinct IPs, A02 duplicate collection sessions, A03 duplicate origins, A06 changed QNAME, A09 tampered hash, A11 missing analyst flag, A12 added private field, A14 changed malicious expectation. Each is checked by process exit status. These are **authored expectations, not observed results**.
- **Expected RED:** A01–A03 should expose lack of actual logical-origin/session enforcement *only if baseline passes*. Missing TShark, malformed synthetic fixtures, parser failures or baseline mismatch are harness defects, not a valid security RED.
- **Deferred:** A04/A05/A07/A08/A10/A13/A15/A16 await binary-wire decoder and V2 schema work; no claim of complete coverage. Synthetic metadata does not prove licensing, malicious classification, or real independence. V2 remains 0/4 approved.
- **Privacy:** Redirect child process output to private temporary log; delete synthetic fixture directory in finally; do not upload packets, raw labels, client attribution or private logs.
- **Future command (NOT authorized):** `powershell.exe -NoProfile -File .\scripts\verify-v2-auditor-enforcement.ps1 -TsharkPath 'C:\Program Files\Wireshark\tshark.exe' -AuthorizedTestTime`. This requires separate owner approval first. No CARTHAGE build, xUnit, TShark, PCAP processing, replay, evaluation or GitHub Actions run has occurred in this step.
- **Next gate:** when test time is explicitly authorized, verify the control, record actual RED, then implement the smallest possible audited enforcement and extend the same harness. Maintain the single GA workflow and frozen V1.


### 2026-10-29 — Stage 6B reason-bound actual-auditor regression expansion (PARKED)

**Branch:** `feature/carthago-reliability-hardening`. **Execution authorization:** NOT GRANTED. The owner remains on a public connection and has not said "now it's test time." No process execution, runner activity or source capture is part of this checkpoint.

| Step | Commit | File | Change | Execution/evidence |
| --- | --- | --- | --- | --- |
| S6B-01 | `d4cbdca` | `scripts/verify-v2-auditor-enforcement.ps1` | Expand the real-auditor synthetic harness with A04 SHA/frame reuse, A08 QTYPE/port mutation, A09 missing PCAP, A10 invalid vantage, A11 invalid license, A13 review-only control, A16 duplicate-but-capture-aligned TXT names; require specific failure reasons rather than any nonzero exit; scan private stdout/stderr for literal QNAME and source/destination IP disclosures. | Authored only; no PowerShell/TShark invocation. |
| S6B-02 | `05e5dda` | `scripts/verify-v2-auditor-enforcement.ps1` | Prevent false baseline failure from PowerShell pipeline collapsing empty benign `expectedMatches` to JSON null; construct typed arrays before serialization. | Static source correction only; Windows PowerShell compatibility not executed. |
| S6B-03 | `e17d2f0` | `docs/STAGE6_V2_AUDITOR_ENFORCEMENT_CONTRACT_20261029.md` | In-depth scenario-by-scenario matrix, privacy expectations, error-code contract, red/green sequencing, known hazards and explicit deferred binary-only coverage. | Documentation committed; no validation. |

**Prepared test inventory:** two legitimate *attribution-only* controls (`BASELINE`, `A13`) and fifteen independent rejection mutations (`A01`, `A02`, `A03`, `A04`, `A06`, `A08-qtype`, `A08-port`, `A09`, `A09-missing`, `A10`, `A11`, `A11-license`, `A12`, `A14`, `A16-distinct`). All synthetic; each fixture is generated under a private randomly named OS temporary directory, with no packet capture or network interface access. Both controls must succeed before any failing mutation may be interpreted as a security RED; every rejection must match its specific intended reason. The actual auditor was not modified.

**Known expected RED:** `SOURCE_INDEPENDENCE_MIRROR`, `SOURCE_SESSION_COLLISION`, `SOURCE_ORIGIN_COLLISION` and `SOURCE_VANTAGE_UNREVIEWED` are proposed privacy-safe error identifiers for unimplemented auditor enforcement. The current legacy auditor checks source-IP inequality but not independently corroborated original clients/sessions. An error from a missing dependency or broken synthetic fixture is **not** a valid RED.

**Privacy checkpoint:** in the planned future run, the harness inspects only a local temporary log and rejects any literal generated QNAME, source address or destination address in it; private logs are deleted under `finally`. This is not a complete audit of every possible credential or binary payload disclosure. GitHub Actions stays a single existing manually dispatched, owner-gated YAML file, unchanged in this step.

**Remaining gaps before claiming Stage 6 complete:** A05 per-frame DNS question ordinals, A06 binary-byte identity and A07 canonical Base64, A08 full TCP/question transport binding, A10 independently verified vantage, A11 substantive license/analyst proof, A12 provenance allowlists, A15 full privacy redaction, A16 byte-length and entropy, and actual production importer/auditor enforcement. Frozen V1 remains unchanged; V2 remains `PENDING_EXTERNAL_CAPTURE_AND_REVIEW`, 0/4 approvals. No claims about R102 precision/recall/F1 follow from prepared syntax regressions.

**Parked future command, not permission:** `powershell.exe -NoProfile -File .\scripts\verify-v2-auditor-enforcement.ps1 -TsharkPath 'C:\Program Files\Wireshark\tshark.exe' -AuthorizedTestTime`, only on CARTHAGE after separate explicit owner authorization. Record original repository SHA, TShark version, exact failing case/error, synthetic capture hash and sanitized exit status when authorized. Do not upload detailed logs or packet data.

**Next development boundary:** prepare narrow code changes to the actual auditor *only after* an authorized and valid security RED confirms the new enforcement gaps. Until then, continue with independent test contract design/documentation or other non-executed tasks without changing frozen evidence.


### 2026-10-29 — Stage 6C logical-source spoofing and provenance schema contract

**Execution status: PARKED — NOT RUN.** No test, script, TShark, build, live capture, replay, holdout evaluation, source upload or GitHub Actions job ran. Changes are confined to authored regression contract and documentation on `feature/carthago-reliability-hardening`.

| ID | Commit | Changed file | Decision and authored regression | Unobserved gate |
| --- | --- | --- | --- | --- |
| S6C-01 | `365db90` | `scripts/verify-v2-auditor-enforcement.ps1` | Added five isolated mutations: A01-case mirrored complete QNAME set with different ASCII case and order, A10-origin absent logical-origin label, A10-session absent collection-session ID, A11-review-type string masquerading as boolean analyst flag, A12-provenance extra unapproved provenance property. Added stable expected rejection identifiers. | Verify original-frame baseline first; observe RED individually without printing packet content. |
| S6C-02 | `b20fd83` | `scripts/verify-v2-auditor-enforcement.ps1` | Insert untrusted `unreviewedImportedDebug` via explicit ordered-dictionary index to guarantee the mutated JSON contains the added field. | Windows PowerShell 5.1 behavior not executed; inspect resulting private fixture at authorized test time. |
| S6C-03 | `ba43f15` | `docs/STAGE6_V2_AUDITOR_ENFORCEMENT_CONTRACT_20261029.md` | Added detailed security threat model, exact inputs/expected reasons for all five cases, false-RED avoidance, privacy requirements, future production interface, human rights/label review and ordered validation. Corrected escaped inline-code Markdown. | Source review only, no passing results. |

**Prepared total:** 2 acceptance-for-attribution-only controls plus 20 negative mutations = **22 test invocations** planned. Their execution count remains **zero**. The new cases are not proof of malicious classification, independent original clients or validated source licensing.

**Exact new expected codes:** `SOURCE_INDEPENDENCE_MIRROR` for A01-case; `SOURCE_ORIGIN_MISSING` and `SOURCE_SESSION_MISSING` for absent client/session identifiers; `SOURCE_REVIEW_FIELD_INVALID` for a truthy non-boolean flag; `SOURCE_PROVENANCE_SCHEMA_REJECTED` for an unexpected provenance key. These errors do not yet exist in the production auditor. Never count a generic TShark/parsing error as their expected RED.

**Compatibility/design notes:** DNS ASCII A–Z comparisons may be case-insensitive, but arbitrary original octets cannot be decoded as Unicode or normalized away. The new A01-case synthetic PCAP uses upper-case wire names while its textual fixture records remain lower-case to match the current auditor's `ToLowerInvariant()` behavior. Full independent binary-wire checks remain gated on Stage 1–5 RED/GREEN. A17+ development should not silently change the frozen V1 data or the existing R102 confidence floors.

**Human and privacy boundary:** Even if two sample sets are disjoint or their metadata fields exist, analyst review must still confirm independent originating devices and collection sessions. Validate recorded license and malicious-label evidence outside the synthetic harness. During a future authorized run, private output must not contain source IPs, destination IPs, reversible labels, raw DNS names or user-provided metadata; log sanitized error codes only. No V2 candidate is admitted or frozen (0/4).

**Next priority:** Author a versioned, strict private provenance schema (field names/types/limits/allowlists, fail-closed migrations, and rollback on any invalid multi-record input) and its regression contract. Production importer/auditor code changes wait for the owner's explicit test-time approval and a valid observed RED from the control-backed harness. The single manually gated GitHub Actions workflow remains unchanged.

**Future authorization boundary:** Only when the owner explicitly says “now it's test time” may a controlled CARTHAGE run of `powershell.exe -NoProfile -File .\scripts\verify-v2-auditor-enforcement.ps1 -TsharkPath 'C:\Program Files\Wireshark\tshark.exe' -AuthorizedTestTime` be considered. That command is documentation, **not** authorization. Preserve its private, temporary evidence handling and report outcomes in this ledger.


### 2026-10-29 — Stage 6D private provenance schema, test-first constraints and atomic publishing design (PARKED)

**Intended boundary:** Add a *new*, opt-in private provenance schema v2 and synthetic regression contract while preserving the existing `scripts/import-holdout-v2-r102.ps1` provenance **schemaVersion=1** and the Holdout V2 manifest's independent **schemaVersion=2**. Keep both production importer and auditor untouched pending owner-authorized RED/GREEN. No live capture, packet replay, TShark, PowerShell test script, xUnit, build, benchmark, CI dispatch, third-party acquisition or holdout evaluation was performed.

| Step | Git commit | File | Reviewable change | Test / gate |
| --- | --- | --- | --- | --- |
| S6D-01 | `163a11b` | `docs/contracts/holdout-v2-private-provenance-v2.schema.json` | Author proposed JSON Schema Draft 2020-12 private sidecar v2: exactly 30 mandatory properties, `additionalProperties: false`, typed bounded capture SHA/frame/questions/identity/license metadata, separate pending-review state, no embedded reversible original labels. | Static schema authored; schema-validity and real PCAP provenance **not tested**. |
| S6D-02 | `9e29ab7` | `scripts/verify-v2-provenance-schema-contract.ps1` | Prepare isolated in-memory four-candidate contract based on actual manifest slot names; two schema-valid but unapproved controls and 24 negative cases for wrong types, fields, enums, count/ordinal misalignment, duplicate evidence, source/session/origin collision, false review and invalid URI. Future API `Confirm-HoldoutV2ProvenanceBatch` from missing `HoldoutV2Provenance.psm1`, not implemented. | `provenance-validator-not-implemented-red` is the expected missing-API checkpoint only when testing is authorized; **RED NOT RUN**. |
| S6D-03 | `fbab77d` | `scripts/verify-v2-provenance-schema-contract.ps1` | Avoid StrictMode masking the intentionally missing-field regression by inspecting optional PowerShell properties before checking that errors omit private evidence. | Authored static correction; **not executed**. |
| S6D-04 | `9778365` | `docs/STAGE6D_PRIVATE_PROVENANCE_SCHEMA_AND_ATOMICITY_20261029.md` | Document exact 30-field schema, 24-case matrix, cross-field requirements impossible in JSON Schema, DNS wire/ASCII privacy boundaries, legacy schema v1 compatibility, batch publisher's same-volume staged-directory commit/rollback and explicit source-approval separation. | Detailed design; transactional publication API **not implemented**. |

**Evidence boundaries:** Schema validity is only syntax; it cannot prove human license/classification review, authentic originating client/session, captured DNS wire label bytes, original PCAP SHA, or permissions. The proposed validator's output is a bounded **pending-review** result, not a V2 admission decision. `analystReviewedLabel` is a typed flag but a true value alone does not prove review. Both source and license HTTPS URLs require independent human corroboration; their syntax is not sufficient.

**Cross-candidate invariant:** `frameNumbers.Count == questionIndices.Count == selectedRecordCount == selected sample record count` plus globally unique `(capture SHA, frame number, question index)`; repeated frame with *different* ordinal may be structurally valid but still requires raw PCAP corroboration. Two benign and two malicious slots, no duplicates, no malicious source/session/origin collisions, no surrogate independence from differing source IPs. For binary DNS, compute length and entropy from original octets, never Base64 character length.

**Transactional boundary (future):** Validate whole four-slot batch before writing, stage all four samples plus sidecars in a uniquely named private sibling directory, close/flush/verify, rename directory to a fresh final batch path on the same filesystem, and clean only the invocation's staging directory on precommit failure. No overwrite, no deletion of existing evidence, no implicit freeze, no upload. Actual filesystem crash behavior must be tested before claiming atomic durability.

**Parked command (NOT permission):** `powershell.exe -NoProfile -File .\scripts\verify-v2-provenance-schema-contract.ps1 -AuthorizedTestTime`. Run only after explicit owner phrase **“now it's test time”** on the verified CARTHAGE Windows environment. At that point first confirm the schema, synthetic fixtures and helper RED; after minimal implementation record GREEN for exact failure code and non-disclosing output. Later author and validate separate publisher fault-injection tests. Never treat a broken fixture/missing interpreter as a successful security RED.

**Preserved:** Frozen V1 failed 4/6 with R102 attribution miss; V2 remains `PENDING_EXTERNAL_CAPTURE_AND_REVIEW`, **0/4** external R102 candidate approvals; R102 confidence 80%, R118 86%, R163 84%, candidate floor 0.75, Shadow/Disabled/cooldown/baseline privacy controls. Only `feature/carthago-reliability-hardening` was changed; no runner workflow YAML modified.

**Next development priority:** Inspect the test vector and schema for correctness during authorized validation, then implement the pure validator after observed RED. Prepare independent atomic batch-publisher fault-injection contract before any real source candidate publication. All outputs/logs remain private and evidence-driven.


### 2026-10-29 — Stage 6E fault-injection contract for atomic private V2 candidate publication

**Execution gate:** PARKED. The owner has not authorized test time; no tests, PowerShell scripts, original/real PCAP reads, packet decoders, TShark, builds, holdout evaluations, CI jobs, runner operations or private artifact uploads have been run. All changes are authored source/design on feature/carthago-reliability-hardening.

| Step | Commit | Path | Reviewable development and decision | Status |
| --- | --- | --- | --- | --- |
| S6E-01 | 30ebeac | scripts/verify-v2-atomic-publication-contract.ps1 | Added a synthetic four-pair private batch fault-injection contract for a future non-existent publisher module. One control and eight precommit injection milestones, one postcommit uncertain outcome, existing-target failure, four unsafe-name cases and an incomplete batch, all with specific error identifiers. | Authored, **not executed** |
| S6E-02 | c2e010c | scripts/verify-v2-atomic-publication-contract.ps1 | Security-corrected the unsafe-path test: pass traversal/reserved names only to a pure module-private Assert-HoldoutV2BatchName checker, never to the actual writer. Prevents the test itself creating out-of-root files if production path checks are flawed. | Static correction, **not executed** |
| S6E-03 | 1f7888c | scripts/verify-v2-atomic-publication-contract.ps1 | Verify exact semantic content of all eight committed files; add duplicate sample and legacy provenance v1 regression; ensure private test-root contains only expected folders/sentinel, preserving existing batch SHA-256 on collision. | Static expansion, **not executed** |
| S6E-04 | 1b8d4b6 | docs/STAGE6E_ATOMIC_V2_PUBLICATION_FAULT_CONTRACT_20261029.md | In-depth transaction architecture, 18 planned outcomes, constant error code contract, failure states, no-replace Windows commit semantics, rollback, crash/recovery boundary, privacy, no-upload, human approval and phased test-first gates. | Documentation only |
| S6E-05 | 10b9f35 | docs/STAGE6D_PRIVATE_PROVENANCE_SCHEMA_AND_ATOMICITY_20261029.md | Link the existing strict private schema/validator design to the newly authored publisher regression, preserving dependency sequencing and explicit untested status. | Documentation only |

**Source-informed underlying risk:** Existing scripts/import-holdout-v2-r102.ps1 uses separate sample and provenance WriteAllText operations; interruption may leave an incomplete pair. The new Stage 6E harness does **not** modify that importer or fix the risk. It prepares a test-first design for a future private batch publisher with all-or-nothing namespace visibility.

**Proposed test input:** four manifest-matched synthetic candidates (two benign, two malicious), three dummy TXT records each and 30-field proposed provenance schema v2, example-only URLs, RFC 5737 documentation IPs, analystReviewedLabel=false, capturedTransportEvidence=false, and reviewState=PENDING_EXTERNAL_CAPTURE_AND_REVIEW. No real original capture or external malicious ground truth is represented. The **existing importer provenance schema v1** and **Holdout V2 manifest schema v2** are separate and must not be conflated.

**Prepared inventory:** one pending-only successful private publication and **17 negative/exception cases**: eight pre-rename stage faults; one post-rename uncertain commit (must retain complete final folder); one existing-batch no-overwrite collision; four pure unsafe-batch-name tests; and three invalid batch inputs (three slots, duplicate candidate name, legacy version 1 sidecar). No tests have been executed.

**Key acceptance invariants (future, not observed):** exactly eight correctly identified sample/provenance JSON files; complete content equivalence; client/private output suppressed; no sampled DNS or source IP data in errors; candidate input remains unchanged; .pending-* cleaned after precommit failure; unrelated sentinel SHA and preexisting batch files unchanged; postcommit exception leaves final directory intact; no automatic reviewer decision or holdout freeze.

**Missing by design:** scripts/HoldoutV2CandidatePublisher.psm1 with private Invoke-HoldoutV2AtomicPublishCore and pure Assert-HoldoutV2BatchName, plus Stage 6D pure provenance validator scripts/HoldoutV2Provenance.psm1. Their absent-module RED is an implementation checkpoint only, not proof the harness generates valid fixture bytes. No public fault-injection arguments may be exposed in production. Reuse existing pure validator instead of duplicating code.

**Explicitly deferred, not claimed GREEN:** real filesystem no-replace rename semantics under simultaneous writers; ACL/permissions faults; malicious reparse-point paths and symlinks; actual Windows crash durability; orphan-stage recovery and reconciliation; original PCAP corroboration; licensed source/right/label review. Each needs separate controlled tests once the owner authorizes. The current script is a deterministic parked contract only.

**Exact future command (NOT authorization):**
~~~powershell
powershell.exe -NoProfile -File .\scripts\verify-v2-atomic-publication-contract.ps1 -AuthorizedTestTime
~~~

At test time, verify CARTHAGE hostname, exact commit/schema SHA, Windows PowerShell version, private file root and the owner's explicit "now it's test time" approval. First verify synthetic fixture/control soundness, then observe missing API RED, implement minimally, rerun identical suite for GREEN, and separately plan concurrency/crash/ACL tests. Record outcome/exit/sanitized error code/expected file count/hashes and warnings in this central ledger.

**Preserved scope:** frozen V1 FAILED 4/6, no retroactive fixes; V2 PENDING_EXTERNAL_CAPTURE_AND_REVIEW with **0/4** R102 candidates approved; R102 confidence 80%, R118 86%, R163 84%, R102 holdout floor 0.75 and all privacy, baseline, Shadow/Disabled and cooldown controls unchanged. Single centralized GitHub Actions workflow remains manual-only. No merge, branch cleanup, captured evidence upload or production-code rewrite.


### 2026-10-29 — Stage 6F concurrent private publication and recovery (PREPARED / PARKED)

**Owner authorization:** Testing remains explicitly withheld until "now it's test time". **No code, test, TShark, PowerShell script, Start-Job worker, network capture, replay, build, Windows runner, GitHub Actions dispatch, or recovery/cleanup process was executed.** All source changes are confined to the existing feature/carthago-reliability-hardening branch. No production publisher was implemented.

| Step | Commit | File | Authored change | Observed status |
| --- | --- | --- | --- | --- |
| S6F-01 | bf4a27e | scripts/verify-v2-recovery-planner-contract.ps1 | Path-free, in-memory recovery planner contract with 15 individual entries covering active writers, young/old orphaned stages, foreign/missing ownership, reparse point, partial/complete final, uncertain commit, unsupported schema, collision, and unknown state. Every result must be review-only with AutoDeleteAllowed=false. | Authored; RED/GREEN NOT RUN |
| S6F-02 | 7743740 | scripts/verify-v2-recovery-planner-contract.ps1 | Correct private module-scope call and regex used for output-safety assertions. | Static correction; NOT RUN |
| S6F-03 | e8cf7f3 | scripts/verify-v2-two-writer-race-contract.ps1 | Prepare 3 synchronized Start-Job contention rounds with 2 separate child processes per round, each targeting a newly owned fixed-safe synthetic batch name. Required: exactly one WIN, one TARGET_EXISTS, 8 complete consistent files, no lingering .pending-* directory. | Authored; 0 of 3 rounds executed |
| S6F-04 | fd8a992 | scripts/verify-v2-two-writer-race-contract.ps1 | Preserve four-candidate array as one child argument, suppress worker warning/information/verbose streams, return sanitized status and numeric PID only. | Static correction; NOT RUN |
| S6F-05 | 7974219 | docs/STAGE6F_CONCURRENT_V2_PUBLICATION_AND_RECOVERY_20261029.md | Full threat model, 15-case disposition matrix, 3-round concurrency expectations, Windows/NTFS and no-replace limitations, privacy, sample isolation, test-first prerequisites and non-destructive recovery design. | Documentation committed |
| S6F-06 | dfc75c1 | docs/STAGE6E_ATOMIC_V2_PUBLICATION_FAULT_CONTRACT_20261029.md | Link Stage 6E sequential transaction validation to Stage 6F concurrency/recovery contracts; preserve required RED/GREEN order and pending-state semantics. | Documentation committed |
| S6F-07 | bf1045e | scripts/verify-v2-two-writer-race-contract.ps1 | Before any future recursive cleanup, inspect a test-owned folder tree without following nested reparse points; fail closed if redirected content is present. | Static safety correction; NOT RUN |
| S6F-08 | 8dd42c2 | docs/STAGE6F_CONCURRENT_V2_PUBLICATION_AND_RECOVERY_20261029.md | Document additional reparse/cleanup safeguard, worker-array behavior, remaining Windows validation caveats and full change register. | Documentation committed |

**Pure recovery API missing by design:** future scripts/HoldoutV2CandidatePublisher.psm1 must implement a module-private Get-HoldoutV2PrivateRecoveryPlan -Entries that returns metadata-only EntryCount, RequiresManualReview=true, AutoDeleteAllowed=false and a disposition/reason code for each entry. It must not take filesystem paths or perform cleanup. Stage 6F's R01–R15 input is synthetic metadata and cannot verify real owner rights, file hashes or safe path resolution.

**Two-writer race API missing by design:** future public Publish-HoldoutV2CandidateBatch wrapper accepts four synthetic candidate pairs with a trusted private root, name and strict schema path; it must NOT expose a fault-injection hook. Start-Job workers use local ready/signal files to establish a contention window. Three rounds / six process workers are **planned**, not executed. This is not proof of true simultaneous rename, actual Windows no-replace atomicity, reader visibility, ACL safety, or crash/power-loss durability.

**Expected RED/GREEN gates, in order:** (1) Stage 6D pure provenance validator RED then GREEN; (2) Stage 6E single-writer transactional publisher RED then GREEN; (3) Stage 6F-A pure recovery planner red/green; (4) Stage 6F-B two-process race red/green; (5) later, independent reader poll, repeated multi-process stress, permission failures, symlink race and crash recovery. A missing module, broken fixture or wrong PowerShell parameter binding is an implementation/harness setup observation, not evidence of a security vulnerability.

**Privacy/safety:** only synthetic labels and documentation IPs; all future test files under a freshly generated ignored build-verify child; no raw source PCAP, reversible DNS Base64 labels, private license review, user traffic or original clients. The planned cleanup routine checks nested reparse points and refuses traversal; no cleanup was run now. Do not add a GitHub workflow or CI artifacts. No automatic deletion of unknown orphan stages based on filename or age; any real cleanup requires separately authorized ownership/path/audit safeguards.

**Preserve governance:** frozen V1 remains historical FAILED 4/6. V2 remains PENDING_EXTERNAL_CAPTURE_AND_REVIEW with **0/4** approved R102 candidates. R102/R118/R163 confidence thresholds 80/86/84%, candidate confidence floor 0.75 and Shadow/Disabled, cooldown, journal, baseline and privacy controls unchanged. No merge, branch deletion, source replacement, production importer or auditor alteration.

**Next development priority:** static audit and prepare a separate reader-visibility / cross-process stress test contract, with no captured source or destructive actions. Before implementing recovery or publisher production modules, observe each current RED on an owner-authorized safe CARTHAGE test window. All newly authored Stage 6F assertions are **PARKED, not validated**.


### 2026-10-29 — Stage 6G third-reader visibility and bounded contention stress (PARKED)

**Scope and test authorization:** User said "continue", not "now it's test time." Preserve the previous no-test instruction, the currently active feature/carthago-reliability-hardening branch, frozen V1, pending V2 and one manually gated GitHub Actions workflow. No PowerShell, TShark, PCAP, .NET, replay, self-hosted runner, concurrent job, actual filesystem fault or performance test was run. This is static source authoring, GitHub commit/readback and documentation only.

| Step | Commit | Changed file | Intended improvement | Execution/evidence status |
| --- | --- | --- | --- | --- |
| S6G-01 | bb8a458 | scripts/verify-v2-two-writer-race-contract.ps1 | Extend the existing Stage 6F race harness with an **opt-in third reader job** behind the same GO barrier; inspect only the final safe batch directory, never pending scratch, and require absent or complete eight-JSON-file views. Reader checks names, classifications, provenance schema v2 and pending-review state; returns metadata-only counters and independent PID. | Source authored; no workers launched, no observed visibility result. |
| S6G-02 | 2dccb79 | scripts/verify-v2-two-writer-race-contract.ps1 | Serialize expected sample-name array as one JSON positional argument to avoid Start-Job array-binding ambiguity; distinguish visible incomplete snapshots from JSON read/IO errors. | Static correction only; Windows PowerShell 5.1 compatibility not executed. |
| S6G-03 | 6af2424 | scripts/verify-v2-two-writer-race-contract.ps1 | Add explicit ReaderStressRounds (3–12, default 6 only if IncludeReaderVisibility); keep original Stage 6F default at three two-writer rounds when the switch is absent. Check final inventory dynamically for N complete batches plus the unrelated sentinel. | Static design; no performance or race stress executed. |
| S6G-04 | 815a064 | docs/STAGE6G_CONCURRENT_READER_VISIBILITY_20261029.md | In-depth lifecycle, exact Absent/Complete/Partial/IoErrors conditions, process isolation, privacy rules, status/error matrix, bounded stress, known sampled-polling blind spots, future deterministic negative probe and authorisation. | Documentation committed; zero passing/failing test results. |
| S6G-05 | 79186ad | docs/STAGE6F_CONCURRENT_V2_PUBLICATION_AND_RECOVERY_20261029.md | Cross-reference and distinguish Stage 6G third-reader visibility from Stage 6F writer race and recovery-planner results; preserve original runner/test boundary. | Documentation committed only. |

**Prepared verification:** With explicit future permission, invoking the existing two-writer source with -IncludeReaderVisibility starts a **third separate reader worker per round**, after a reader-ready barrier, with bounded polling. The future reader must never see a final directory with missing/extra files, malformed or inaccessible JSON, wrong sample/provenance cross-references, unsupported schemaVersion or a falsely approved reviewState. Parent requires exactly one WIN, one TARGET_EXISTS, one READER_DONE, distinct PIDs, at least one legitimate absent and complete view, zero partial/read errors, and intact full batch contents. All observer outputs are numeric counts or constant codes only.

**Stress limit:** If IncludeReaderVisibility is omitted, remain exactly three two-writer rounds. With it, default six writer-writer-reader rounds, with explicit bound 3..12. The prepared 12-round configuration would plan **24 writer jobs + 12 reader jobs**, run sequentially by round rather than as one unbounded concurrent swarm. These are authored counts, not executions.

**Known false-negative limitation:** A 4 ms polling loop cannot prove that partial visibility never occurs in shorter intervals. No deterministic broken-publisher/partial-final negative control has been implemented. Do not label GREEN until the controlled negative probe demonstrates the reader detects incomplete final JSON. No-replace rename semantics, NTFS power-loss durability, symlink races, ACL fault tolerance, crash recovery and genuine source licensing/malicious-label review remain separate and untested.

**Safety isolation:** Continue to use manifest-specified four R102 placeholder names and documentation-only IPs; random ignored build-verify test root, fixed safe batch basenames, no packet capture or network contact, unique sentinel SHA and only owned test cleanup. Existing reader/writer helpers remain test-only; no production module, workflow profile or public fault-injection option was added. Any future test failure due to broken ready/go job synchronization, PowerShell serialization or a missing publisher module is setup RED/FAIL, *not evidence of a validated security defect*.

**Parked syntax, not approval:**

~~~powershell
powershell.exe -NoProfile -File .\scripts\verify-v2-two-writer-race-contract.ps1 -AuthorizedTestTime -IncludeReaderVisibility -ReaderStressRounds 3
# Later, only if specifically approved and successful:
powershell.exe -NoProfile -File .\scripts\verify-v2-two-writer-race-contract.ps1 -AuthorizedTestTime -IncludeReaderVisibility -ReaderStressRounds 12
~~~

**Next gating order:** Stage 6D pure provenance RED→GREEN; Stage 6E transactional publisher RED→GREEN; Stage 6F initial writer race and recovery RED→GREEN; controlled reader negative probe; then Stage 6G opt-in 3/6/12 rounds. Human review and four-slot V2 admission remain pending. Current Holdout V2: PENDING_EXTERNAL_CAPTURE_AND_REVIEW, **0/4 approved**. Frozen V1 historical FAILED 4/6, R102/R118/R163 confidence 80/86/84% and candidate floor 0.75 unchanged.

**Do not infer PASS/RED/GREEN or detection precision/recall/F1 from the code committed in this step.**


### 2026-10-29 — Stage 6H deterministic third-reader sensitivity contract (AUTHORED / PARKED)

**Owner decision boundary:** "Continue please" authorizes further source preparation but NOT execution. The owner has prohibited all tests until explicitly saying "now it's test time". No PowerShell parser, script, job, TShark, build, replay, PCAP read, network capture, self-hosted runner job or CI workflow was launched. Changes are on the existing feature/carthago-reliability-hardening branch only.

| Step | Commit | Changed file | Engineering work | Evidence status |
| --- | --- | --- | --- | --- |
| S6H-01 | f8c1ec5 | scripts/verify-v2-two-writer-race-contract.ps1 | Refactored the Stage 6G reader into one shared script-scoped PrivateBatchReaderJob and allowed a reader-only negative-control mode without the future publisher module. Optional causal acknowledgment markers; existing Stage 6F/G invocation modes preserved. | Source authored, no Start-Job executed. |
| S6H-02 | d6a848e | scripts/verify-v2-two-writer-race-contract.ps1 | Added private fixture generator, bounded marker wait, per-case isolated invalid final-folder injection and metadata-only result check, using the exact same observer as Stage 6G; no production writer API invoked. | Authored only; no filesystem fault injected. |
| S6H-03 | fd4ce67 | scripts/verify-v2-two-writer-race-contract.ps1 | Wired six negative fixtures (H01–H06) in OnlyReaderNegativeControl mode; kept Stage 6F three-round default and Stage 6G 3–12 opt-in behavior; synthetic root under ignored build-verify. | Static preparation only. |
| S6H-04 | 6c5ec83 | scripts/verify-v2-two-writer-race-contract.ps1 | Removed a duplicate former Stage 6F race-only tail that referenced race variables outside its branch, avoiding misleading negative-mode failures. | Static correction; no parser/run evidence. |
| S6H-05 | 402003f | docs/STAGE6H_DETERMINISTIC_READER_NEGATIVE_CONTROLS_20261029.md | In-depth six-case input/expected-signal matrix, shared-observer design, causal markers, safety, error classification, review and owner test-first gates. | Documentation committed. |
| S6H-06 | e977067 | scripts/verify-v2-two-writer-race-contract.ps1 | Fail closed if the intended ignored build-verify parent is a ReparsePoint before creating new test-owned scratch; retain nested reparse-point guards for cleanup. | Static protection, not Windows race proof. |
| S6H-07 | b791d5d | docs/STAGE6H_DETERMINISTIC_READER_NEGATIVE_CONTROLS_20261029.md | Record final parent-root safety requirement and all source commits, with explicit zero-execution status. | Documentation committed. |
| S6H-08 | 6092c7d | docs/STAGE6G_CONCURRENT_READER_VISIBILITY_20261029.md | Link Stage 6H sensitivity precondition to Stage 6G sampled concurrent-reader results; preserve Stage 6F/G behavior, false-GREEN warnings and manual gating. | Documentation committed. |

**Six planned negative probes (0 executed):**
- H01: final directory contains no files -> require actual shared reader Partial > 0, IoErrors = 0.
- H02: seven of eight sample/provenance JSON files -> require Partial > 0, IoErrors = 0.
- H03: eight expected filenames but one malformed JSON file -> require IoErrors > 0, Partial = 0.
- H04: eight readable files but one provenance reviewState='APPROVED' -> require Partial > 0, IoErrors = 0.
- H05: eight readable files plus extra debug file -> require Partial > 0, IoErrors = 0.
- H06: eight readable files, inconsistent sample/provenance classification -> require Partial > 0, IoErrors = 0.

**Causal test mechanism:** Single Stage 6G/H reader scriptblock used by both actual two-writer race and six negative probes; independent Windows PowerShell reader job; unique safe test name; parent waits for real post-GO ABSENT marker; builds invalid fixture privately in a .pending-probe-<id> test directory; reveals it to the reader with a same-volume local Directory.Move; waits for actual reader PARTIAL or IOERROR acknowledgment; then stops and joins only that reader job. The final metadata result has exactly seven allowed fields (Code, ProcessId, Polls, Absent, Complete, Partial, IoErrors), a distinct PID and no private packet contents. Waits are bounded and use fixed markers. All files are synthetic; no publisher, original capture, network, real client identity or detector involved.

**Safe removal boundary (future):** stage and final folders have fixed generated basenames beneath one newly owned ignored build-verify child; the root and nested folders are checked for reparse-point redirection before recursive cleanup; only the owning reader job and generated marker files are removed. A redirected build-verify parent is rejected before creation. These checks do NOT prove absence of a Windows TOCTOU filesystem attack; no execution or true OS-level no-follow test has been performed.

**Static source checks, not runtime tests:** GitHub readback after 6c5ec83 confirmed one shared reader definition, two Start-Job call sites, optional ABSENT/PARTIAL/IOERROR acknowledgment paths, six independent fixture descriptions, module bypass for negative-only mode, legacy default preservation, no real publisher API call inside negative-case helper, and one correctly scoped final root inventory check. Windows PowerShell 5.1 parsing and serialization remain unverified. Source checks are not RED/GREEN, performance metrics, or detection quality.

**Next engineering decision:** Stage 6H concludes the planned source-only reader-sensitivity preparation. Avoid extending the test-contract backlog without runtime feedback. After explicit separate owner approval, verify CARTHAGE and exact SHAs; execute Stage 6H reader-only H01–H06 first to establish observer sensitivity, then Stage 6D pure provenance validator RED/GREEN, Stage 6E transactional publisher RED/GREEN, Stage 6F two-writer and read-only recovery RED/GREEN, and Stage 6G bounded reader stress. Implement only the missing minimal modules after sound observed RED; preserve approved code. Source/license/client and R102 accuracy evidence are separate human-reviewed gates.

**Parked command (NOT permission):**

~~~powershell
powershell.exe -NoProfile -File .\scripts\verify-v2-two-writer-race-contract.ps1 -AuthorizedTestTime -OnlyReaderNegativeControl
~~~

**Preserved:** Original importer and auditor untouched; single centralized GitHub Actions workflow manual-only; V1 historical FAILED 4/6 remains immutable, V2 PENDING_EXTERNAL_CAPTURE_AND_REVIEW with **0/4** approved R102 samples; rule confidence floors R102 80%, R118 86%, R163 84% and external R102 sample floor 0.75, Shadow/Disabled, baseline, cooldown, journals and privacy requirements unchanged. No branch merge, deletion or PCAP upload. No tests executed.


### 2026-10-29 — Stage 7 missing V2 implementation modules authored (NO TEST AUTHORIZATION)

**User directive:** "Complete the missing implementation." Interpreted as permission to edit the exact missing modules and documentation on feature/carthago-reliability-hardening; **NOT** permission to execute test suites or use CARTHAGE. Existing user directive to wait for the exact phrase "now it's test time" remains binding. No test runner, PowerShell parser/command, TShark process, .NET build, PCAP capture/replay, evaluator, CI dispatch or performance measurement was executed.

| Step | Commit | File | Change | Verification |
| --- | --- | --- | --- | --- |
| S7-01 | a7bc0dc | scripts/HoldoutV2Provenance.psm1 | Implement strict 30-field provenance v2 schema validation, exact four manifest slots, typed values, capture hash/frame/question cardinality, duplicate evidence and malicious origin/session/source collision, pending-review-only result. | GitHub source authored, untested. |
| S7-02 | 15d3ea1 | scripts/HoldoutV2Provenance.psm1 | Correct schemaVersion mismatch code to PROV_SCHEMA_VERSION. | Static review only. |
| S7-03 | 18f69b4 | scripts/HoldoutV2CandidatePublisher.psm1 | Implement private staged eight-file batch publisher reusing S7 validator; bounded private root/name, CreateNew + flush/reread, no-replace same-volume Directory.Move, isolated precommit rollback, postcommit uncertainty. Public wrapper does not expose fault injection. | GitHub source authored, untested. |
| S7-04 | 2e9a447 | scripts/DnsWirePcap.psm1 | Implement selected original DNS question-byte decoder (compressed/backward pointers; multi-question ordinals; canonical RFC4648 labels), source frame/hash/QTYPE/IP/port binding, and non-approving logical-source independence risk review. | GitHub source authored, no TShark run. |
| S7-05 | 85e4cbf | scripts/DnsWirePcap.psm1 | Correct original DNS multiple-question array output shape for the ordinal selector. | Static correction only. |
| S7-06 | 5d199c8 | scripts/HoldoutV2CandidatePublisher.psm1 | Add private path-free Get-HoldoutV2PrivateRecoveryPlan implementing R01–R15 advisory classifications with AutoDeleteAllowed=false, RequiresManualReview=true; no path inputs or filesystem mutations. | GitHub source authored, no recovery execution. |
| S7-07 | abbe6b0 | scripts/HoldoutV2CandidatePublisher.psm1 | Repair accidental duplicate publisher text inside recovery planner regex introduced during source string replacement. Verified one public wrapper, one planner and one module export by GitHub readback. | Static integrity correction; no PowerShell execution. |
| S7-08 | f527538 | scripts/DnsWirePcap.psm1 | Sanitize missing capture/resolve/TShark failures into stable private-safe error identifiers. | Static hardening. |
| S7-09 | 8eb3a35 | docs/STAGE7_V2_SOURCE_MODULE_IMPLEMENTATION_20261029.md | In-depth architecture, public/private API contracts, migration boundaries, stage publication/rollback, source provenance privacy, known test/Windows caveats and future authorization order. | Documentation only. |
| S7-10 | 3be70ee | scripts/DnsWirePcap.psm1 | Sanitize original-capture SHA-256 reading failures without exposing raw local paths. | Static hardening. |

**Missing-module state changed:** scripts/DnsWirePcap.psm1, scripts/HoldoutV2Provenance.psm1, and scripts/HoldoutV2CandidatePublisher.psm1 **now exist**. They are source implementations, not observed passing code. Publisher also carries the previously missing private recovery planner. No new branch or workflow was created.

**Defined public interfaces:**
- Read-DnsWireQuestion, Confirm-DnsWireCandidateBinding, Measure-DnsWireMaliciousSourceIndependence;
- Confirm-HoldoutV2ProvenanceBatch;
- Publish-HoldoutV2CandidateBatch.

**Private/unexported:** Assert-HoldoutV2BatchName; Invoke-HoldoutV2AtomicPublishCore with test-only OnMilestone; Get-HoldoutV2PrivateRecoveryPlan. Stage 6E/6F parked contracts access these within module scope; public callers cannot pass fault-injection hooks.

**Preserved core functionality:** scripts/import-holdout-v2-r102.ps1 continues to emit legacy private provenance schemaVersion=1 and is **unchanged**. scripts/audit-holdout-v2-candidates.ps1 remains unchanged; its printable-QNAME attribution is NOT upgraded by mere existence of a new binary-wire module. Stage 7 library uses strict private schemaVersion=2, separate from Holdout V2 manifest version 2; explicit opt-in integration is still required. All four external V2 candidates are pending (0/4); private batch publication never approves source rights, attribution, classification or rule promotion.

**Unresolved security/performance caveats:** PowerShell 5.1 syntax and array binding unverified, TShark jsonraw dns_raw and selected-frame port behavior unverified, TCP reassembly/IPv6 support unverified, exact same-volume Windows no-replace Directory.Move races unverified, ACL/reparse race and power-failure durability unverified, provenance license truth and independent logical-client proof require human review, and original source packet compatibility with real PCAP datasets remains untested. The DNS source binder uses selected-question reads per record and may need batched decoding for larger candidate sets. No standalone end-to-end V2 importer cutover was performed.

**Required staged verification upon explicit owner approval:**
1. Confirm CARTHAGE, checkout SHA, local private scratch path, Windows PowerShell and installed TShark version;
2. Stage 6H observer-negative H01–H06 (reader sensitivity, no publisher required);
3. Stage 5/6 original-wire synthetic PCAP/TShark reference contract plus malicious-source review;
4. Stage 6D two pending-review controls + 24 negative provenance cases;
5. Stage 6E one complete batch + 17 fault scenarios;
6. Stage 6F 15 recovery-planner cases and three two-writer races; Stage 6G third-reader visibility 3/6/12 rounds;
7. Once source modules are GREEN, design a separately reviewed **opt-in** importer/auditor v2 integration preserving legacy v1 and all frozen evidence;
8. Obtain four human-reviewed external R102 cases; only then calculate precision/recall/F1 against qualified evidence and consider V2 admission.

**Current test state:** NOT EXECUTED, no PASS/FAIL/RED/GREEN. Historic V1 remains FAILED 4/6; V2 remains PENDING_EXTERNAL_CAPTURE_AND_REVIEW, **0/4** external candidates approved. R102 threshold 80%, R118 86%, R163 84%, R102 external acceptance floor 0.75 and all Shadow/Disabled, cooldown, journal, baseline/privacy controls unchanged. The centralized workflow remains manual-only, with no schedule or push/PR trigger.

**Hard boundary:** No automated branch merging, cleaning, dataset modification, original capture upload or customer-facing claim of verified detection quality. The next work is test-based integration under express owner authorization, not another speculative unverified contract series.


### 2026-10-29 — First owner-authorized local Stage 6H / 6D testing; blocked gates

**Authorization:** The owner explicitly authorized testing and ran the two synthetic scripts using Windows PowerShell on the CARTHAGO Windows workspace after fast-forwarding the existing feature/carthago-reliability-hardening branch to exact commit 4a08d0f. These are **owner-provided observed outputs**, not tests independently run by the assistant. Existing local ignored/untracked build-verify evidence was retained. No original capture, TShark, live network interface, rule evaluation, GitHub Actions job, performance test, or automated dataset promotion was reported as executed in this step.

| Test gate | Exact command profile | Observed result | Classification |
| --- | --- | --- | --- |
| Stage 6H reader-sensitivity, six negative probes | verify-v2-two-writer-race-contract.ps1 -AuthorizedTestTime -OnlyReaderNegativeControl | STAGE6H_NEGATIVE_CONTRACT: ready-reader-exited-early at the first reader-ready barrier. **No H01–H06 positive detection result established.** | Blocked: child Start-Job exited before ready marker, cause not yet identified on Windows. Not a security RED. |
| Stage 6D provenance, two positive plus 24 negative prepared cases | verify-v2-provenance-schema-contract.ps1 -AuthorizedTestTime | PROV_BATCH_SHAPE emitted by HoldoutV2Provenance.psm1 before suite summary, no successful baseline announced. **No 24-negative-case result established.** | Blocked: input/manifest/slot/classification shape, exact phase initially ambiguous. Not a detection-quality result. |

**Committed source corrections before any re-execution:**

| Commit | File | Fix / diagnostic |
| --- | --- | --- |
| 9863429 | scripts/verify-v2-provenance-schema-contract.ps1 | Normalize JSON clone output into an explicit four-element PSCustomObject[] on Windows PowerShell; require four-item baseline before validation, without logging private candidate metadata. |
| 2c219a3 | scripts/HoldoutV2Provenance.psm1 | Add privacy-safe PROV_BATCH_SHAPE phase suffixes INPUT_COUNT, MANIFEST_STATE, MANIFEST_SLOTS, SLOT_MAPPING and CLASS_COUNTS. Existing contract's expected PROV_BATCH_SHAPE still matches; source identities are never logged. |
| f930e06 | scripts/verify-v2-two-writer-race-contract.ps1 | Use a scalar delimiter-joined token of four validated synthetic manifest basenames instead of Start-Job JSON-array binding; on premature reader completion, display only a whitelisted constant child status code or NO_READER_RESULT, never child exception/paths. |

**Critical limits:** These commits are fixes to scripts and diagnostics, **not validated corrections on CARTHAGO yet**. The original underlying cause of both gates is not definitively established until the owner reruns the exact two commands and reports their sanitized output. If either gate remains blocked, do not advance to Stage 6E/F/G, TShark, original PCAP evaluation, full .NET regression or commercial release claims. Do not discard, git-clean, reset or overwrite existing user's untracked build-verify artifacts. The feature branch is the only branch changed; no new workflow, CI dispatch or running processes from the assistant.

**Required next evidence:** owner fast-forward git pull to these commits and rerun only Stage 6H reader-only negative probe and Stage 6D provenance schema contract. Record exact Git SHA; for Stage 6H capture the newly sanitized constant reader exit code and H01–H06 case outcomes; for Stage 6D capture the exact phase-marked PROV_BATCH_SHAPE or specific PROV_* code and baseline/negative counts. Only mark GREEN after the full planned cases pass, not merely after the first exception is suppressed.

**Preserved governance:** frozen V1 historical FAILED 4/6; Holdout V2 still PENDING_EXTERNAL_CAPTURE_AND_REVIEW with 0/4 external R102 source approvals, detection confidence floors R102 80%, R118 86%, R163 84% and R102 external 0.75. All existing production importer, source auditor, rules, and the manual-only GitHub Actions workflow remain unchanged.

**Follow-up static compatibility correction:** commit `c991e83` changed only the synthetic Stage 6H/G reader name parser to `@(([string]$NamesJson).Split([char]'|'))` for explicit Windows PowerShell 5.1 character splitting. It continues accepting only the four validated synthetic manifest names. This correction was committed **after** the first blocked owner-reported results; it has not been run locally by the assistant or validated on CARTHAGE.


### 2026-10-29 — Second authorized Windows verification at 88dd526 (both gates blocked)

Owner-provided CARTHAGE PowerShell transcript confirms a clean fast-forward to **88dd526**, followed by two more synthetic tests. Original captured data and ignored build-verify files were not removed. These results concern synthetic contract infrastructure, **not** R102 accuracy, approval, or frozen V1 outcomes.

| Gate | Command profile | Observed at 88dd526 | Interpretation |
| --- | --- | --- | --- |
| Stage 6H | verify-v2-two-writer-race-contract.ps1 -AuthorizedTestTime -OnlyReaderNegativeControl | STAGE6F_RACE_CONTRACT: negative-leaked-output-fields | Reader reached job result evaluation; Windows Receive-Job envelope properties need to be distinguished from unexpected business fields. No six-case GREEN established. |
| Stage 6D | verify-v2-provenance-schema-contract.ps1 -AuthorizedTestTime | V2 private provenance contract: wrong-rejection-reason | Negative-case expected-versus-actual rejection mismatch; no 24-case GREEN established. |

**Subsequent targeted, source-only corrections (not yet rerun by owner):**

- **8f58a89** updates Stage 6H's property-shape assertion to accept only the seven expected business fields plus the three known Windows PowerShell remoting envelope properties (`PSComputerName`, `RunspaceId`, `PSShowComputerName`), rejecting all others.
- **91aca2e** updates the strict provenance validator to reject mismatched frame/question/count cardinality before applying standalone per-array minimum bounds, preserving stricter schema checks.
- **a3c447f** makes Stage 6D negative-case failures show only the fixed synthetic case name, expected code, and allowlisted actual PROV_* code (or NON_CONTRACT_EXCEPTION), without printing private source values.

**No post-fix runtime evidence:** owner transcript still reports HEAD **88dd526** and precedes these changes. Before interpreting any new outcome, owner must `git pull --ff-only origin feature/carthago-reliability-hardening`, record new HEAD, then rerun Stage 6H and—only after its success—Stage 6D. If Stage 6D reports another case mismatch, use the sanitized case/actual code to fix the smallest issue. Do not advance to real PCAP, TShark, publisher/concurrency, full .NET suites or Holdout V2 admission while the two gates remain blocked.

**Preservation:** V1 historical FAILED 4/6 unchanged; V2 PENDING_EXTERNAL_CAPTURE_AND_REVIEW, 0/4 external R102 candidates approved; existing rule thresholds, importer, auditor, manually gated workflow and private build-verify evidence untouched.


### 2026-10-29 — Third owner-authorized CARTHAGE verification: 6H GREEN / 6D parser-blocked

**Checkout observed:** feature/carthago-reliability-hardening at **8882f1c**, after a successful fast-forward. User ran the existing synthetic scripts using Windows PowerShell on their local machine; this is user-provided test evidence and has not been independently rerun in this assistant environment.

| Gate | Observed local result | Evidence and interpretation |
| --- | --- | --- |
| Stage 6H reader-negative sensitivity | **PASS 6/6**: h01 PARTIAL, h02 PARTIAL, h03 IOERROR, h04 PARTIAL, h05 PARTIAL, h06 PARTIAL; final summary explicitly reported six completed synthetic sensitivity cases | Reader sensitivity demonstrated for all six deliberately malformed **synthetic** final batches on Windows. No publisher, live capture, genuine source approval or frozen holdout touched. |
| Stage 6D provenance validator | **BLOCKED by PowerShell parser error**: UnexpectedToken at source line 104, followed by unmatched parentheses and duplicate file-section errors | The provenance negative suite did not execute. This is a damaged test-script source artifact, **not** a validator failure, not RED/GREEN and not a detection-quality measurement. |

**Confirmed source-edit defect:** the prior diagnostic edit (commit a3c447f) corrupted scripts/verify-v2-provenance-schema-contract.ps1 by accidentally expanding inserted replacement text into duplicate trailing program sections. The GitHub blob at 8882f1c contained **602 lines / 41,708 characters** rather than the intact 176-line previous script. The inserted regex anchors at lines 94 and 105 were visibly truncated, explaining the parser's cascading UnexpectedToken errors. This is a source authoring mistake, not an issue attributable to the owner's Windows installation.

**Corrective commit:** **8261716** restores the intact test fixture/24 negative cases and two positive controls from its known-good 88dd526 blob, adds one carefully scoped four-argument rejection handler and privacy-safe per-case expected/actual diagnostic, and changes only the negative-case call site. GitHub static verification before commit confirmed **188 lines**, exactly **24 cases**, one Assert-Rejected function and one diagnostic; historical array-clone compatibility and synthetic fixture assertions were retained. No original production import, packet auditor, V1/V2 manifest, rule threshold or GitHub Actions workflow was changed. The published repaired script has not yet been parsed or executed on Windows.

**Execution gating:** Do not retest Stage 6H merely to prove its already observed 6/6 success, and do not proceed to Stage 6E/F/G/TShark while 6D remains blocked. Owner should fast-forward the same branch to a commit containing 8261716, run **parse-only** using System.Management.Automation.Language.Parser.ParseFile for scripts/verify-v2-provenance-schema-contract.ps1, and run the 6D synthetic contract only if that check returns zero parser errors. If 6D then reports wrong-rejection-reason:<fixed case>:expected=...:actual=..., fix the precise behavioral mismatch rather than editing unrelated rules or private source data. Local build-verify evidence and all untracked logs remain untouched.

**Status to preserve:** 6H observed GREEN at 8882f1c; 6D NOT RUN due to parser failure at 8882f1c; repaired 6D code committed but NOT VERIFIED ON WINDOWS. V2 remains PENDING_EXTERNAL_CAPTURE_AND_REVIEW with 0/4 external R102 approvals; frozen V1 historical FAILED 4/6, R102 80%, R118 86%, R163 84% and all privacy/journal/cooldown controls remain unchanged.


### 2026-10-29 — Fourth owner-authorized Windows verification: provenance case 23 of 24 blocked by unexpected exception

**Observed checkout:** feature/carthago-reliability-hardening at **cf5fb12**, after user fast-forward. Windows PowerShell Parser.ParseFile reported **PowerShell syntax: PASS** for the 188-line Stage 6D contract; owner then executed only verify-v2-provenance-schema-contract.ps1 -AuthorizedTestTime.

**Observed result:** \`V2 private provenance contract: wrong-rejection-reason:wrong-count-type:expected=PROV_SCHEMA_TYPE:actual=NON_CONTRACT_EXCEPTION\`. The failure occurred while testing the synthetic mutation \`selectedRecordCount='3'\` (a string rather than a JSON integer). As this is the **23rd of 24** sequential negative cases, the two valid pending-review controls and preceding 22 negative-case checks were reached without a terminating assertion in that run. **Do not claim full 24/24 GREEN:** the final not-four-candidates negative case was not reached, and the unexpected exception's original message was intentionally suppressed for privacy. No original PCAP, detector rule, publisher or holdout admission was exercised. The Stage 6H six-case reader-sensitivity result remains **GREEN 6/6** from the earlier authorized test; no rerun needed.

**Targeted code corrections (source committed but NOT rerun on Windows):**

| Commit | Change | Rationale |
| --- | --- | --- |
| e0c038a | scripts/HoldoutV2Provenance.psm1 | Add explicit \`selectedRecordCount\` scalar type guard **before** cross-field frame/question count checks. Prevent invalid scalar count from reaching a numeric comparison before generating \`PROV_SCHEMA_TYPE\`. Preserve minimum-length cardinality check behavior for other cases. |
| 0470470 | scripts/verify-v2-provenance-schema-contract.ps1 | Require the wrong-count-type fixture mutation to remain exactly string \`'3'\` in the candidate, preventing a false assumption about PowerShell property coercion. All 24 original negative scenarios remain unchanged. |
| e147304 | scripts/HoldoutV2Provenance.psm1 | Explicitly reject string-valued count at that preflight boundary prior to using the generic integer predicate. No source identity, packet field, license claim, holdout reference or output payload added. |

**Remaining uncertainty:** The original \`NON_CONTRACT_EXCEPTION\` is not yet classified beyond the suppressed message. The new scalar guard targets the exact malformed type, but **only a new Windows runtime result** can demonstrate the root cause was resolved. If the next run still returns NON_CONTRACT_EXCEPTION, inspect only a sanitized PowerShell exception type and fixed source-phase marker; do not print raw private source metadata.

**Next gate:** Fast-forward to latest branch SHA, parse-check **both** scripts/HoldoutV2Provenance.psm1 and scripts/verify-v2-provenance-schema-contract.ps1, then rerun only Stage 6D. Preserve all untracked build-verify evidence. Only after a complete positive-controls plus 24-negative-case pass should Stage 6D be marked GREEN and Stage 6E publisher testing be considered.

**Holdout governance unchanged:** V1 historic failed 4/6; V2 pending 0/4 approved external R102 candidates. Rules R102/R118/R163 confidence 80/86/84%, privacy, Shadow/Disabled, cooldowns, journal and existing manually gated workflow untouched.


### 2026-10-29 — Fifth owner-authorized CARTHAGE verification: Stage 6D GREEN, Stage 6E preflight hardening

**Observed user checkout:** feature/carthago-reliability-hardening at **3ae94ba**. The owner performed a fast-forward pull, then used System.Management.Automation.Language.Parser.ParseFile on both scripts/HoldoutV2Provenance.psm1 and scripts/verify-v2-provenance-schema-contract.ps1. Both returned **Syntax PASS** with no parse errors. The owner then executed the authorized Stage 6D private synthetic schema regression contract.

**Observed Stage 6D result: GREEN.** Final output explicitly reported: "Private provenance schema contract: 2 structurally-valid, pending-review controls and 24 negative cases. All candidate identities remain synthetic." This is the complete 2-positive/24-negative contract at commit 3ae94ba, **not** a real PCAP, independent evidence, licensing or detection-accuracy evaluation. Preserve the prior observed Stage 6H GREEN (six of six synthetic reader-sensitivity controls). Only these two local gates have owner-provided positive evidence so far. No Stage 6E execution result exists yet.

**Before requesting Stage 6E**, static review compared scripts/verify-v2-atomic-publication-contract.ps1 to scripts/HoldoutV2CandidatePublisher.psm1 and identified a synthetic fixture type mismatch: the test constructed DNS records using OrderedDictionary ([ordered]@{...}), while the publisher's strict eleven-property record allowlist relies on PSObject.Properties. Converting the **test fixture** to explicit PSCustomObject avoids falsely treating this as an invalid production batch. No publisher validation rules, schema limits or privacy guarantees were relaxed. The test now asserts the synthetic record shape and exactly three records per pair before invoking the publisher.

| Commit | File | Source-only change | Evidence |
| --- | --- | --- | --- |
| cfddb9f | scripts/verify-v2-atomic-publication-contract.ps1 | Construct test DNS records as PSCustomObject rather than OrderedDictionary; assert eleven properties per record and three records per sample before the synthetic publication gate | Authored, not Windows-tested |
| d8ca444 | scripts/verify-v2-atomic-publication-contract.ps1 | Refuse redirected build-verify parent and check every nested owned test entry for Windows ReparsePoint before recursive cleanup | Authored, no OS/filesystem assurance implied |

**Stage 6E next gate:** Have owner pull the latest feature branch, parse-check both scripts/verify-v2-atomic-publication-contract.ps1 and scripts/HoldoutV2CandidatePublisher.psm1, then run only the explicitly authorized Stage 6E contract on a safe local Windows filesystem. Expect 1 pending-only control, 8 injected precommit rollback failures, 1 uncertain postcommit result, 1 target-exists check, 4 pure non-writing unsafe basename checks, and 3 rejected invalid batches (18 total scenarios). Only the new GUID-named stage6e-atomicity test scratch directory under the already-existing build-verify parent may be cleaned. The existing untracked accuracy logs, holdout-v2-sources and other local evidence must remain untouched. No live capture, TShark, original dataset modification or workflow/runner execution is part of this gate.

**Caution:** Script source verification is NOT Windows PowerShell syntax, runtime, durability, race, privilege or security proof. Any new Stage 6E error should be investigated as a specific test or implementation defect; do not claim passed until owner shares final complete summary. V2 remains PENDING_EXTERNAL_CAPTURE_AND_REVIEW with 0/4 reviewed external R102 approvals; immutable V1 retains historical FAILED 4/6. R102/R118/R163 floors, journal, Shadow/Disabled, cooldown, baseline and privacy controls unchanged.


### 2026-10-29 — Sixth owner-authorized CARTHAGE verification: Stage 6E control rejected at preflight

**Observed checkout:** user fast-forwarded feature/carthago-reliability-hardening to **a478674**, ran Windows PowerShell Parser.ParseFile for scripts/HoldoutV2CandidatePublisher.psm1 and scripts/verify-v2-atomic-publication-contract.ps1; **both returned Syntax PASS**. Owner then executed verify-v2-atomic-publication-contract.ps1 -AuthorizedTestTime. The first positive synthetic publication control failed immediately with **PUBLISH_INVALID_BATCH** at publisher Fail-Publisher line 8. No Stage 6E rollback/uncertain-commit, no-replace or negative-publisher result can be claimed from this run. This is a preflight blocker, not evidence of a failed atomic rename, concurrency weakness or detector result. Stage 6H remains GREEN 6/6; Stage 6D remains GREEN (2 controls + 24 negatives), each observed separately on CARTHAGE.

**Static root-cause review:** Stage 6E's fixture creates valid benign samples with **zero expected positive matches** (expectedMatches is a typed empty string array). The source publisher's Assert-PublisherSamplePairs preflight used Compare-Object with the piped output of Sort-Object over this empty array. On Windows PowerShell, those pipeline expressions emit no argument, which can throw during Compare-Object parameter binding; the enclosing preflight catch masks all exceptions as PUBLISH_INVALID_BATCH. This explains a plausible source of the immediate preflight rejection; confirmation still requires a new Windows test. No production import, auditor, source/capture data or existing test artifacts were changed.

**Corrective source commit:** **6501a08**, scripts/HoldoutV2CandidatePublisher.psm1:
- Introduce private Test-PublisherExactRuleSet with strict case-sensitive ordinal HashSet checks, including legal **empty expectedMatches** for benign samples. It rejects duplicates, missing/extra identifiers, non-string members and case-altered rule IDs. Preserve expected R102 match/nonmatch lists and malicious minimum confidence (0.75) without changing threshold values.
- Replace only the Compare-Object calls on expectedMatches/expectedNonMatches inside Assert-PublisherSamplePairs. Other nonempty field allowlists remain unchanged.
- Keep the general private publisher rejection code PUBLISH_INVALID_BATCH but add only fixed preflight suffixes ROOT, PROVENANCE or SAMPLE. The suffix is a non-sensitive phase marker: no path, client/source identity, QNAME, reversible DNS label, hash or raw exception is emitted. Existing tests that look for PUBLISH_INVALID_BATCH still match.
- No new public export, no added fault-injection production parameter, no change to 8-file publication, rollback, commit outcome or filename/ownership validation.

**Next action:** user should fast-forward the existing branch to commit containing 6501a08, parse-check the publisher and Stage 6E contract (no need to rerun already verified Stage 6D/6H) and rerun **only Stage 6E synthetic publication**. Record the full expected final control+fault summary if it passes. If preflight remains blocked, record only the newly bounded PUBLISH_INVALID_BATCH phase, fix that exact contract mismatch and avoid progressing to Stage 6F/G or source PCAP/TShark validation. This source correction has not been runtime-verified by the assistant.

**Safety:** Only the test-owned GUID scratch folder under the existing build-verify root may be created/cleaned during authorized tests. Untracked accuracy logs, holdout-v2-sources and all other original private data untouched. Historical frozen V1 FAILED 4/6 and V2 PENDING_EXTERNAL_CAPTURE_AND_REVIEW with 0/4 externally approved R102 cases remain unchanged; R102/R118/R163 confidence floors 80/86/84%, Shadow/Disabled, cooldown, baseline, privacy and journals preserved.


### 2026-10-29 — Seventh owner-authorized CARTHAGE verification: Stage 6E atomic publication GREEN

**Observed checkout:** owner fast-forwarded feature/carthago-reliability-hardening to commit **c5174da**. Windows PowerShell's System.Management.Automation.Language.Parser.ParseFile reported **Syntax PASS** for both scripts/HoldoutV2CandidatePublisher.psm1 and scripts/verify-v2-atomic-publication-contract.ps1. The owner then executed the existing Stage 6E synthetic contract under explicit AuthorizedTestTime and supplied the terminal output.

**Observed full Stage 6E result: GREEN.** The final summary was: "Stage 6E contract: 1 pending-only control, 8 precommit rollbacks, 1 uncertain commit, 1 existing target, 4 pure unsafe-name cases and 3 invalid batches. No approval." This is **18/18 contract scenarios** at commit c5174da: an intact eight-file private commit; eight deliberately injected precommit failures leaving no partial final or orphaned pending stage; preservation of complete committed files on a simulated response failure after rename; rejection of overwriting existing target; pure non-writing unsafe-name checks; and invalid-batch rejection. All fixtures were synthetic, used only a uniquely owned GUID scratch child beneath build-verify and contained only documentation IP addresses and artificial names. **Not** an independent Windows race, crash-durability, original-source/TShark, detector precision/recall or external evidence approval result.

**Existing verified gates:** Stage 6H reader sensitivity **6/6 GREEN** (owner-observed at 8882f1c); Stage 6D private provenance **2 valid pending controls + 24 negative cases GREEN** (owner-observed at 3ae94ba); Stage 6E **18/18 GREEN** (owner-observed at c5174da). Do not conflate the 44 synthetic assertions with end-to-end R102 field accuracy or release readiness.

**Stage 6F source review (nonexecuting, preceding the next local test):** scripts/verify-v2-recovery-planner-contract.ps1 creates 15 distinct path-free in-memory metadata entries R01–R15, imports the existing publisher module, invokes its module-private Get-HoldoutV2PrivateRecoveryPlan, requires a single four-field result and one three-field decision per case, verifies the input was not mutated and rejects any advisory automation that deletes, promotes, freezes or approves. A separate script, scripts/verify-v2-two-writer-race-contract.ps1, starts separate Windows PowerShell jobs and writes only into an owned ignored scratch folder; leave this **unexecuted** until the pure recovery gate passes. Static source review has not established Windows parser, Start-Job serialization or runtime success.

**Next owner-approved sequence:** (1) fast-forward the same branch and record SHA; (2) use Parser.ParseFile on scripts/verify-v2-recovery-planner-contract.ps1 and scripts/HoldoutV2CandidatePublisher.psm1; (3) if syntax passes, run **only** scripts/verify-v2-recovery-planner-contract.ps1 -AuthorizedTestTime and report the complete result. Expect 15 fixed R01–R15 review-only cases and a final summary. If it fails, stop and record the exact constant rejection code, fixing only the failing contract or planner behavior. (4) Only after this gate is GREEN, proceed to a separate three-round two-writer competition (Stage 6F) with an explicit owner command, followed later by Stage 6G reader visibility stress. Do not run PCAP/TShark/full replay or CI as part of this step.

**Preserved:** Historical V1 FAILED 4/6 immutable. V2 manifest PENDING_EXTERNAL_CAPTURE_AND_REVIEW with **0/4 approved** external candidates. R102 80%, R118 86%, R163 84% confidence floors, R102 holdout minimum 0.75, privacy, Shadow/Disabled, cooldowns, baseline, journal integrity, importer, auditor and manual-only workflow remain unchanged. Local untracked accuracy logs, original evidence and holdout-v2-sources are not touched or deleted.


### 2026-10-29 — Eighth owner-authorized CARTHAGE verification: Stage 6F read-only recovery GREEN, writer race prepared

**Owner-provided test evidence:** On the Windows CARTHAGE workspace, the user fast-forwarded branch feature/carthago-reliability-hardening to exact commit **1ab3290**. Both scripts/HoldoutV2CandidatePublisher.psm1 and scripts/verify-v2-recovery-planner-contract.ps1 passed Windows PowerShell ParseFile syntax checks. The owner executed verify-v2-recovery-planner-contract.ps1 -AuthorizedTestTime and supplied all fifteen individual recovery case results **R01 through R15**, followed by the exact final summary: "Stage 6F recovery contract contains 15 in-memory, review-only scenarios. No filesystem action authorized."

**Observed outcome: Stage 6F recovery GREEN 15/15.** All scenarios reached their expected advisory disposition/reason; metadata-only output retained RequiresManualReview=true and AutoDeleteAllowed=false. The test uses in-memory artificial metadata and did not execute real disk recovery, delete pending folders, promote source labels or approve a V2 candidate. This result does **not** establish two-writer concurrency, filesystem durability, source authentication or R102 precision/recall/F1.

**Verified baseline after this test:**
- Stage 6H third-reader negative sensitivity: GREEN 6/6 at 8882f1c.
- Stage 6D strict provenance: GREEN 2 pending-only controls + 24 negative cases at 3ae94ba.
- Stage 6E atomic publisher synthetic single-writer contract: GREEN 18/18 at c5174da.
- Stage 6F path-free recovery planner: GREEN 15/15 at 1ab3290.
- Stage 6F independent **two-writer** race: **NOT YET EXECUTED**; Stage 6G three-process reader visibility: NOT YET EXECUTED.

**Preflight static hardening before two-writer test:** Commit **6d1bb4e** modifies only scripts/verify-v2-two-writer-race-contract.ps1. Writer Start-Job arguments now carry the four complete synthetic candidate pairs as **one JSON scalar string** rather than a nested PowerShell array, avoiding positional array flattening. Each independent worker deserializes the string and fails closed with a constant BAD_JOB_FIXTURE status if it does not contain four Sample/Provenance pairs. The caller continues to invoke the unchanged public Publish-HoldoutV2CandidateBatch wrapper. No application, publisher, workflow, provenance, original importer/auditor or data was changed by this compatibility fix. The source edit has not been parsed or run on CARTHAGE; its behavior remains unverified.

**Next test — separate from reader stress:** Owner should fast-forward to the latest branch checkpoint, verify parse-only syntax for scripts/verify-v2-two-writer-race-contract.ps1, scripts/HoldoutV2CandidatePublisher.psm1 and scripts/HoldoutV2Provenance.psm1, then run verify-v2-two-writer-race-contract.ps1 -AuthorizedTestTime **without** IncludeReaderVisibility or OnlyReaderNegativeControl. This invokes exactly three sequential competing two-writer rounds; each new round uses a fixed safe batch name and the unique GUID-owned ignored build-verify scratch root. Require exactly one winner and one target-exists loser per round, distinct worker PIDs, all eight complete unchanged pending-only files, no leftover stage, unaffected sentinel and guarded private scratch cleanup. A failure is NOT evidence of final concurrency integrity until cause is resolved. User's existing untracked build-verify/accuracy-logs, holdout-v2-sources, rule-batches, text logs and all other data must not be touched.

**Holdout governance:** Original V1 immutable historical FAILED 4/6; V2 remains PENDING_EXTERNAL_CAPTURE_AND_REVIEW with **0/4 approved external R102 cases**. R102 confidence 80%, R118 86%, R163 84%, external R102 minimum 0.75 and privacy, disabled/shadow, cooldown, journal/baseline controls preserved. No changes to the manually gated GitHub Actions workflow or branch merge.


### 2026-10-29 — Ninth owner-authorized CARTHAGE verification: Stage 6F two-writer race BLOCKED (outcomes not yet known)

**Observed checkout:** owner fast-forwarded feature/carthago-reliability-hardening to exact commit **0f45279**. Windows PowerShell Parser.ParseFile reported **Syntax PASS** for scripts/verify-v2-two-writer-race-contract.ps1, scripts/HoldoutV2CandidatePublisher.psm1 and scripts/HoldoutV2Provenance.psm1. Owner executed only verify-v2-two-writer-race-contract.ps1 -AuthorizedTestTime (default **3 rounds**, no IncludeReaderVisibility). The harness terminated with **STAGE6F_RACE_CONTRACT: race-did-not-have-exactly-one-winner** at the first failing round, without printing individual writer status codes. The test summary did not complete; the specific pair of outcomes is **unknown**.

**What this evidence establishes:** The combined gate requiring exactly one WIN and one TARGET_EXISTS outcome did **not** pass at 0f45279. It does **not** establish whether two writers committed, neither committed, one writer failed fixture validation, a competing target was rejected through an unexpected Windows exception, or the Start-Job worker encountered an unrelated serialization error. The original test catches almost every worker exception as an opaque UNEXPECTED_ERROR; advancing to Stage 6G without classifying the precise failure would be unsafe.

**Source-only diagnostic commit:** **c2ea369**, only scripts/verify-v2-two-writer-race-contract.ps1 changed. Both workers continue to publish four artificial candidates to a uniquely owned build-verify scratch folder and use the unchanged publisher. On catching an exception, each worker now emits exactly one allowlisted *constant* code: TARGET_EXISTS, INVALID_ROOT, INVALID_PROVENANCE, INVALID_SAMPLE, INVALID_BATCH, PRECOMMIT_ABORT, COMMIT_UNCERTAIN or UNEXPECTED_ERROR, as applicable. The parent validates both codes against the full fixed allowlist (also WIN, BAD_JOB_FIXTURE, BAD_SUCCESS_SHAPE, BARRIER_TIMEOUT) and logs only the two sorted codes for the current safe race label, **before** asserting exactly one winner and exactly one target-exists loser. There is no logging of exception messages, paths, original DNS QNAME/labels, capture hashes, IP addresses, JSON or job output objects. The one-WIN/one-TARGET_EXISTS condition was **not relaxed**.

**Next accepted action:** owner fast-forward the existing feature branch to the new checkpoint, parse-check the modified harness, and rerun **only Stage 6F two-writer competition**, stopping on the first failure. Capture the first line beginning "STAGE6F RACE race-01 sanitized worker statuses:" (or the first failing round) and sanitized error code. Use those codes to distinguish test-worker fixture errors from actual publisher collision behavior before changing the production publisher. Do not prematurely rerun Stage 6D/E/H (already GREEN), enable Stage 6G stress, run TShark/live traffic, or approve V2 sources.

**Preserved results:** Stage 6H 6/6 GREEN; Stage 6D 2 pending controls +24 negative GREEN; Stage 6E 18 synthetic publication cases GREEN; Stage 6F path-free recovery R01–R15 GREEN. Two-writer contention is **BLOCKED / NOT GREEN**. V1 historical FAILED 4/6 immutable; V2 PENDING_EXTERNAL_CAPTURE_AND_REVIEW with 0/4 approved external R102 cases, thresholds R102 80%, R118 86%, R163 84%, external R102 0.75, privacy and manually gated workflow unchanged. Existing untracked local build-verify evidence remains untouched.


### 2026-10-29 — Tenth owner-authorized CARTHAGE verification: Stage 6F workers both BAD_JOB_FIXTURE

**Owner-provided observation:** After fast-forward to exact commit **28a4b29**, Windows PowerShell Parser.ParseFile reported **Syntax PASS** for the Stage 6F two-writer script. The owner ran the explicitly authorized default three-round synthetic test. The first round printed **STAGE6F RACE race-01 sanitized worker statuses: BAD_JOB_FIXTURE,BAD_JOB_FIXTURE** and stopped at STAGE6F_RACE_CONTRACT: race-did-not-have-exactly-one-winner. No second/third round executed to completion. No publisher WIN, no TARGET_EXISTS or valid eight-file committed final was established in this test run.

**Interpretation:** The two worker scriptblocks returned BAD_JOB_FIXTURE from the explicit pre-publication candidate-shape check, before invoking Publish-HoldoutV2CandidateBatch. This is a confirmed **job fixture boundary failure**. The race cannot yet demonstrate a winner/loser or any real atomicity/concurrent-reader property. Previous Stage 6E single-writer publication GREEN at c5174da remains supported; a defect in the production publisher is **not established** by this failure.

**Repair, test harness only:** Commit **c8dc84e** changes scripts/verify-v2-two-writer-race-contract.ps1:
1. Parent wraps the four synthetic pairs into one PSCustomObject envelope with property Pairs, then converts the object to a single compact JSON string. The earlier top-level JSON array was vulnerable to version-dependent PowerShell pipeline enumeration when ConvertFrom-Json output was surrounded by \`@(...)\`, resulting in unexpected nested/flattened input shapes.
2. Parent checks the JSON round-trip has an array-valued Pairs property of exactly four before any jobs start, with a fixed error code writer-fixture-parent-roundtrip.
3. Each Windows child deserializes **one JSON object**, verifies that Pairs is an array with four objects each exposing Sample and Provenance properties, then casts the embedded Pairs array to object[] and invokes the **unchanged** publisher. On any mismatch it still returns only BAD_JOB_FIXTURE; no raw source identity, JSON or local path is logged.
4. The original sanitizer, exact 1 WIN + 1 TARGET_EXISTS acceptance, distinct independent worker PIDs, all-eight-file readback, no-leftover-stage check, reparse-point cleanup, own-guid scratch isolation, manually gated execution, and Stage 6H observer-negative branch remain untouched. No production publisher, provenance, importer, auditor, manifest, detector rule, CI/workflow or original private evidence is changed.

**Source-only validation:** The committed edit was checked for unique anchors, intact stage flags and acceptance gates; it has **not yet passed parser or runtime tests on the owner's Windows machine**.

**Next owner test:** Pull the feature branch to the newest commit, verify Syntax PASS with Parser.ParseFile for the modified two-writer script, then run only \`powershell.exe -NoProfile -File .\scripts\verify-v2-two-writer-race-contract.ps1 -AuthorizedTestTime\`. Expect for each of race-01, race-02 and race-03 one sanitized WIN and one TARGET_EXISTS, eight valid pending-only files, no lingering .pending stage and no source approval. **If any case fails, capture the sanitized statuses and stop** before Stage 6G. Do not run real PCAP/TShark, full .NET regression or promotions as part of this gate.

**Preserved baseline:** Stage 6H reader-negative GREEN 6/6; Stage 6D provenance GREEN 2 pending +24 negative; Stage 6E atomic publisher GREEN 18 scenarios; Stage 6F path-free recovery GREEN R01–R15. Stage 6F two-writer race BLOCKED at 28a4b29; Stage 6G reader stress UNTESTED. V1 historical FAILED 4/6 immutable, V2 PENDING_EXTERNAL_CAPTURE_AND_REVIEW with 0/4 approved external R102 candidates. Confidence floors R102 80%, R118 86%, R163 84%, external R102 0.75, Shadow/Disabled, cooldowns, baseline, journal and privacy unchanged.
