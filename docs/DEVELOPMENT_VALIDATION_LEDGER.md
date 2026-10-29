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


### 2026-10-29 — Eleventh owner-authorized Windows verification: Stage 6F two-writer contention GREEN 3/3; Stage 6G first opt-in ready

**Actual observed local checkout:** The owner ran git status --short (only pre-existing untracked build-verify accuracy logs, holdout-v2-sources, rule-batches, error reports and the old carthago-verification transcript were present), confirmed original SHA 28a4b29, then fast-forwarded the same feature branch to **adf421f**. The owner verified the new \`writer-fixture-parent-roundtrip\` check exists in scripts/verify-v2-two-writer-race-contract.ps1. The owner then ran \`powershell.exe -NoProfile -File .\scripts\verify-v2-two-writer-race-contract.ps1 -AuthorizedTestTime\` under the existing explicit test-time authorization.

**Observed complete result: Stage 6F two-writer GREEN 3/3.** The actual Windows output reported:
- \`race-01 sanitized worker statuses: TARGET_EXISTS,WIN\` and one successful private publisher, one target-exists loser.
- \`race-02 sanitized worker statuses: TARGET_EXISTS,WIN\` and one successful private publisher, one target-exists loser.
- \`race-03 sanitized worker statuses: TARGET_EXISTS,WIN\` and one successful private publisher, one target-exists loser.
- Final \`Stage 6F race contract: three two-process contention rounds prepared; results do not certify crash durability or source review.\`

The script's full successful completion also implies its own unchanged assertions for independent writer PIDs, eight complete unmodified sample/sidecar files in each final folder, pending review state, zero \`.pending-*\` directories, expected owned-scratch inventory and unchanged sentinel SHA were not raised. This is **not** a formal linearizability, power-loss durability, or third-reader-visibility result.

**Verification baseline, strictly separated:** Stage 6H synthetic reader-negative H01–H06 GREEN 6/6 (8882f1c); Stage 6D private provenance 2 structurally valid pending controls + 24 negative cases GREEN (3ae94ba); Stage 6E fault-injected atomic single-writer publication 18/18 GREEN (c5174da); Stage 6F in-memory recovery planner R01–R15 GREEN 15/15 (1ab3290); **Stage 6F two-process contention GREEN 3/3 (adf421f)**. All evidence comes from owner-supplied Windows PowerShell transcripts; the assistant did not run Windows tests.

**Stage 6G source review for the next test:** The existing, shared \`scripts/verify-v2-two-writer-race-contract.ps1\` supports \`-IncludeReaderVisibility -ReaderStressRounds 3\`, adding one independent third reader job while retaining the unchanged one-winner/one-target-exists writer requirement. The third reader checks final path is either absent or an exactly eight-file pending-review batch with correct matched sample/provenance identities; the parent requires at least one complete snapshot, at least one absence observation, zero partial snapshots, zero read/parse errors and a reader process ID distinct from both writers. The deterministic **same observer implementation** already passed Stage 6H's six malformed-final negative probes. A three-round initial run is preferable before larger six- or twelve-round stress to classify any timing or job-barrier blocker without conflating it with product atomicity.

**Recommended owner-run next gate:** Record latest branch SHA; parse-check the shared two-writer script; run **only** \`powershell.exe -NoProfile -File .\scripts\verify-v2-two-writer-race-contract.ps1 -AuthorizedTestTime -IncludeReaderVisibility -ReaderStressRounds 3\`. Expect three pairs of \`STAGE6G READER: race-0N saw absent/complete states only; no partial view.\` and \`STAGE6F RACE race-0N: one private writer won; one received target-exists; no approval.\` plus final Stage 6G opt-in completion. **Do not mark 6G GREEN before owner output establishes every round passed.** On a failure, stop, capture only the fixed sanitized code and address harness or publisher evidence at that specific stage.

**Assurance and privacy:** Reader samples are periodic and can miss brief transient states, even after three successful rounds. Neither Stage 6G nor the previously passed contracts claim NTFS crash durability, human source rights review, original TShark corroboration or R102 field accuracy. The user’s original ignored/untracked evidence is not deleted, overwritten or staged. Preserve immutable V1 historic FAILED 4/6, V2 PENDING_EXTERNAL_CAPTURE_AND_REVIEW **0/4 approved external candidates**, R102 80%, R118 86%, R163 84% and external R102 0.75 confidence floor, Shadow/Disabled, cooldowns, baseline, privacy and journal integrity. Existing importer, auditor, manually gated workflow, production publisher and detection rules remain unchanged by this documentation-only update.


### 2026-10-29 — Twelfth owner-authorized CARTHAGE verification: Stage 6G 3-process visibility GREEN (3/3 initial rounds)

**Verified checkout and syntax:** The owner fast-forwarded the existing `feature/carthago-reliability-hardening` branch from `adf421f` to exact SHA **0135998** and reported **Syntax PASS** using Windows PowerShell `System.Management.Automation.Language.Parser.ParseFile` for `scripts/verify-v2-two-writer-race-contract.ps1`.

**Exact authorized execution:** `powershell.exe -NoProfile -File .\scripts\verify-v2-two-writer-race-contract.ps1 -AuthorizedTestTime -IncludeReaderVisibility -ReaderStressRounds 3`. The owner supplied the complete output (not independently executed by the assistant).

**Observed result: Stage 6G initial GREEN, 3/3 complete rounds.** For every race-01, race-02, and race-03 the harness printed `TARGET_EXISTS,WIN`; then the independent observer confirmed `saw absent/complete states only; no partial view`; the writer race concluded `one private writer won; one received target-exists; no approval.` Final summary: `Stage 6G opt-in: 3 2-writer/1-reader visibility rounds completed; no durability or source approval.`

**Acceptance checks reached without an assertion:** one winning and one losing *independent writer process* in every round, a reader with a distinct process ID, at least one observed absent snapshot and one complete pending-review snapshot, **zero partial reads**, **zero IO/parse errors**, the full eight-file final sample/sidecar pair integrity, no uncommitted pending stage, unique scratch ownership/inventory and preserved canary hash. These properties describe the existing harness's contractual assertions and its successful exit; the transcript does not separately disclose numeric reader poll counts or every intermediate check. The same reader implementation independently passed all six synthetic malformed-final negative controls under Stage 6H.

**Scope and caveats:** This is a **sampled Windows concurrency contract** using synthetic test data under a newly GUID-owned child of `build-verify`. It is not a formal linearizability proof, not a power-loss/NTFS durability certification, not an original PCAP or independent TShark source check, and not R102 detection precision/recall evidence. Reader scheduling could miss a transient condition between polls; therefore the contracted initial Stage 6G result is GREEN at **3/3 only**, not full stress completion.

**Current separately verified gates:** Stage 6H negative sensitivity **6/6**; Stage 6D provenance **2 pending positive controls + 24 negatives**; Stage 6E atomic publication **18 scenarios**; Stage 6F recovery planner **15/15**; Stage 6F two-writer contention **3/3**; Stage 6G initial two-writer plus reader **3/3**. Every pass above is grounded in owner-supplied CARTHAGE output at its recorded SHA; no additional test is inferred.

**Next gated escalation:** Reuse the same unchanged script and its `-AuthorizedTestTime -IncludeReaderVisibility` switches for exactly **six** rounds (`-ReaderStressRounds 6`) at the current documented branch SHA. Verify all rounds report one WIN and one TARGET_EXISTS, only absent/complete reader views, zero partial/IO errors and final completion. Stop on the first failure. Only after six rounds are owner-confirmed GREEN should twelve bounded rounds be considered. Do not run six and twelve simultaneously; avoid unrequested CI, packet/TShark, live network, PCAP replay and source admission.

**Preservation:** No application code or harness changes were needed or made for this three-round result. Existing untracked `build-verify` accuracy logs, holdout-v2-sources, rule-batches, diagnostic text files and original captures are untouched. Historical frozen V1 FAILED 4/6 persists, Holdout V2 remains PENDING_EXTERNAL_CAPTURE_AND_REVIEW with **0/4 external source approvals**, thresholds R102 80%, R118 86%, R163 84%, external R102 minimum 0.75, Shadow/Disabled, cooldown, privacy, journal and baseline controls unchanged.


### 2026-10-29 — Thirteenth owner-authorized Windows verification: Stage 6G six-round concurrent-reader stress GREEN (6/6)

**Observed command and result:** The owner executed `powershell.exe -NoProfile -File .\scripts\verify-v2-two-writer-race-contract.ps1 -AuthorizedTestTime -IncludeReaderVisibility -ReaderStressRounds 6` in the Windows Carthago working directory and supplied complete terminal output. There was **no new git rev-parse output in this specific transcript**, so do not assign this run a newly verified exact checkout SHA. The last owner-confirmed checkout in this conversation was `0135998`; the intervening repository commit `1340acb` edited only this documentation ledger, not the race harness.

**Observed gate: Stage 6G extended visibility GREEN 6/6.** For each of race-01 through race-06, output reported `TARGET_EXISTS,WIN`, the independent reader reported `saw absent/complete states only; no partial view`, and the round reported `one private writer won; one received target-exists; no approval.` The final summary was exactly `Stage 6G opt-in: 6 2-writer/1-reader visibility rounds completed; no durability or source approval.` The command's complete successful exit also implies its scripted assertions for independent worker PIDs, unique third reader PID, at least one absent and complete observed view, zero Partial and IoErrors, complete eight-file pending-only payload integrity, zero leftover pending stages, scratch-only inventory, and unchanged canary hash were not raised. It does **not** establish formal linearizability or every possible interleaving; read polling can miss transient states.

**Cumulative explicitly verified local gates:** Stage 6H deterministic reader-negative 6/6; Stage 6D strict provenance 2 pending positive controls + 24 negatives; Stage 6E fault-injected atomic single-writer 18/18; Stage 6F path-free recovery planner R01–R15 15/15; Stage 6F two-writer only race 3/3; Stage 6G writer/reader initial 3/3 and extended **6/6**. These are separate synthetic contracts, not a combined commercial-release certification.

**Next and final bounded Stage 6G stress escalation:** Existing source supports `-ReaderStressRounds 12` (maximum accepted by ValidateRange(3,12)); no source changes are required. Owner should first verify `git rev-parse --short HEAD`, optionally fast-forward the feature branch, and run only `powershell.exe -NoProfile -File .\scripts\verify-v2-two-writer-race-contract.ps1 -AuthorizedTestTime -IncludeReaderVisibility -ReaderStressRounds 12`. Require every round 01–12 to have exactly one WIN and TARGET_EXISTS, no partial/unreadable views, and a final 12-round completion summary. On any failure, stop at that gate, keep privacy-safe diagnostics and do not run packet capture/TShark/detector quality or any automatic CI.

**Preservation:** The six-round stress harness writes only a GUID-owned child of existing `build-verify` and contains synthetic sample data; user-owned untracked `build-verify/accuracy-logs`, `build-verify/holdout-v2-sources`, `build-verify/rule-batches` and all other evidence were not modified by assistant operations. V1 frozen FAILED 4/6 unchanged; V2 still PENDING_EXTERNAL_CAPTURE_AND_REVIEW, **0/4 genuine source approvals**. R102/R118/R163 floors 80/86/84%, external R102 0.75, Shadow/Disabled, cooldowns, journal, baseline, privacy, original importer/auditor and manual-only workflow unchanged. Concurrency test results do not approve any source, certify filesystem durability or establish detection quality.


### 2026-10-29 — Fourteenth owner-authorized Windows verification: Stage 6G 12-round bounded stress GREEN, closed within synthetic scope

**Observed exact checkout:** user fast-forwarded feature/carthago-reliability-hardening from 1340acb to **566f746** with \`git pull --ff-only origin feature/carthago-reliability-hardening\`, then \`git rev-parse --short HEAD\` reported **566f746**. The only fetched change was this central ledger, not the test harness. Before the pull, the owner also repeated the six-round synthetic stress test and supplied all six passing round logs; treat that as an **additional six-round run**, not a substitute for the separately confirmed 12-round test.

**Authorized 12-round execution:** \`powershell.exe -NoProfile -File .\scripts\verify-v2-two-writer-race-contract.ps1 -AuthorizedTestTime -IncludeReaderVisibility -ReaderStressRounds 12\`. The owner supplied the complete Windows PowerShell output.

**Observed Stage 6G maximum bounded stress: GREEN 12/12.** All twelve consecutive rounds (race-01 through race-12) individually reported \`STAGE6F RACE race-NN sanitized worker statuses: TARGET_EXISTS,WIN\`, \`STAGE6G READER: race-NN saw absent/complete states only; no partial view.\` and \`STAGE6F RACE race-NN: one private writer won; one received target-exists; no approval.\` Final summary: \`Stage 6G opt-in: 12 2-writer/1-reader visibility rounds completed; no durability or source approval.\` The completed harness therefore met its own assertions for exact one-winner/no-replace outcome, three independent processes, reader absence and complete observations, zero observed partial/IO-error states, eight correct pending-only sample/provenance files, no orphan stages, valid scratch inventory and unchanged canary. This was **24 writer jobs and 12 reader jobs across sequential rounds** (not 36 simultaneously).

**Stage 6G disposition: CLOSED GREEN for the predefined bounded synthetic regression matrix** (3/3, 6/6, 12/12 owner-verified separately). Stage 6H separate deterministic observer-failure negative sensitivity 6/6 remains GREEN, Stage 6D two positive+24 negative provenance remains GREEN, Stage 6E 18/18 fault-injection GREEN, Stage 6F recovery 15/15 GREEN and Stage 6F two-writer-only race 3/3 GREEN. Do not rerun these gates reflexively. This is **not** a formal linearizability proof, post-crash filesystem durability proof, real external-source approval or evidence that detection R102 reaches field-confidence floors. Sampling may miss short-lived visibility errors between polls.

**Repository audit for the next priority, source-only (no test execution):** Existing \`scripts/DnsWirePcap.psm1\` contains read-only extraction of exact \`dns_raw\` question bytes via TShark, Base64-per-label preservation and frame-index/ordinal/source-port/transport binding. Existing \`scripts/verify-dns-wire-source-contract.ps1\` synthesizes a temporary local PCAP, compares raw wire bytes to independent TShark readings and checks four source-bound selections, five negative/ambiguous selections; optional \`-IncludeV2Provenance\` exercises candidate-binding tampering and seven synthetic source-independence review cases. **Do not duplicate this code.** The test requires local TShark availability and writes only its uniquely generated temporary synthetic fixture (no capture of public/network traffic); inspect any unexpected command error before continuing. Its header describes it as parked; owner authorization applies before executing.

**Material migration gap discovered:** Legacy \`scripts/import-holdout-v2-r102.ps1\` and \`scripts/audit-holdout-v2-candidates.ps1\` still use TShark \`dns.qry.name\` text (which is potentially lossy for original binary labels), frame-only identity and an older \`schemaVersion=1\` provenance layout in the importer, whereas the separately authored private Stage 6D+ wire-source contract uses \`labels-base64-v1\`, original frame+question ordinal, schema version 2 and pending-review state. Passing the synthetic DNS source contract **does not make these legacy importer/auditor paths safe or compatible** with the new private V2 contract. Park any real external-source import, admission, freeze or promotion until the owner explicitly approves a narrowly scoped migration with tests and independent TShark corroboration. No original capture data or legacy scripts were modified by this review.

**Recommended next owner-confirmable gate:** Verify checkout SHA and \`Get-Command tshark -ErrorAction Stop\` + \`& tshark -v | Select-Object -First 1\`, parse-check \`scripts/DnsWirePcap.psm1\` and \`scripts/verify-dns-wire-source-contract.ps1\`, then (if locally authorized) run only the synthetic DNS contract first **without** \`-IncludeV2Provenance\`. Stop on a mismatch, document the exact constant error reason without printing real PCAP content. Run the optional V2 provenance extension only after the base synthetic comparison is GREEN. Do not invoke the legacy importer/auditor, live capture, packet replay against real sources or any third-party dataset in this stage.

**Preservation:** Existing ignored/untracked build-verify logs, sources, rule batches and user data untouched. Immutable historical V1 failed 4/6; Holdout V2 remains PENDING_EXTERNAL_CAPTURE_AND_REVIEW with **0/4 approved external R102 candidates**. R102 80%, R118 86%, R163 84% floors, R102 holdout min 0.75, Shadow/Disabled, cooldowns, privacy, baseline and journal integrity unchanged. No production code, publisher, DNS parser, existing importer, auditor, workflow or test script modified by this ledger-only update.


### 2026-10-29 — Fifteenth owner verification: DNS wire/TShark contract blocked by missing command

**Owner-supplied Windows checkout:** git pull --ff-only origin feature/carthago-reliability-hardening fast-forwarded 566f746 to **1fc6b49**; git rev-parse --short HEAD confirmed **1fc6b49**. Only this central ledger was updated by that pull. The owner attempted Get-Command tshark -ErrorAction Stop and then tshark -v. Both returned **CommandNotFoundException** / "The term 'tshark' is not recognized". **No Stage 5 DNS wire PCAP test, optional Stage 6 source-provenance extension, real-source import or capture was executed. No decoder GREEN/RED outcome is justified.**

**Meaning and scope:** tshark is not currently resolvable from that Windows PowerShell session's PATH. This does **not** prove Wireshark is absent from disk, installed incorrectly or incompatible. Check the conventional Wireshark installations under Program Files and Program Files (x86) before installing software. The existing scripts/verify-dns-wire-source-contract.ps1 and scripts/DnsWirePcap.psm1 both accept a TsharkPath parameter; supplying an absolute path is preferable to modifying PATH or downloading an unverified executable. Do not alter the publisher, DNS parser, importer, auditor, manifest or workflow to solve an environment discovery problem.

**Safe diagnosis:** Use Test-Path -LiteralPath -PathType Leaf against the usual Wireshark\\tshark.exe program directories. If present, invoke the absolute executable path with -v; check first line and exit code. If not found, use only the authentic official Wireshark distribution after explicit owner action; ensure the TShark command-line component is selected. The contract's PowerShell syntax can be validated independently, but **do not execute the synthetic DNS/TShark contract until the executable resolves**. Once present, run only the synthetic contract with -TsharkPath <absolute executable>, initially without -IncludeV2Provenance. Stop on any error and avoid private-data logging.

**Preserved baseline:** Stage 6G bounded visibility stress 12/12 GREEN at 566f746; Stage 6H 6/6, Stage 6D two pending controls+24 negatives, Stage 6E 18/18, Stage 6F recovery 15/15 and writer-only race 3/3 remain separately verified. The pending DNS/TShark corroboration remains **NOT RUN / ENVIRONMENT BLOCKED**. Historical V1 FAILED 4/6 immutable; V2 PENDING_EXTERNAL_CAPTURE_AND_REVIEW 0/4 externally approved. Original untracked build-verify evidence, source captures, privacy, thresholds and ledger integrity untouched.


### 2026-10-29 — Sixteenth owner-authorized CARTHAGE verification: DNS wire synthetic contract BLOCKED at TShark jsonraw frame cardinality

**Observed checkout and executable:** owner fast-forwarded feature/carthago-reliability-hardening to **317917a**, verified installed \`C:\Program Files\Wireshark\tshark.exe\` version **TShark (Wireshark) 4.6.9**, and reported **Syntax PASS** for both scripts/DnsWirePcap.psm1 and scripts/verify-dns-wire-source-contract.ps1. Owner ran \`powershell.exe -NoProfile -File .\scripts\verify-dns-wire-source-contract.ps1 -TsharkPath $tsharkPath\`. The test stopped at its first TShark raw-frame count assertion with **DNS wire source contract: tshark-frame-count-mismatch**. This was *before* verifying the binary DNS labels, question ordinal, transport, or optional candidate provenance. No downstream DNS decoding correctness or source acceptance can be asserted from this run.

**Scope of failure:** The test successfully reached the \`-T jsonraw\` external call and its following frame-count check. That check originally assigned \`$rawFrames = @(ConvertFrom-Json -InputObject ($rawOutput -join [Environment]::NewLine))\` and then required a count of three. Windows PowerShell 5.1 can return a top-level deserialized JSON array as one pipeline output object or enumerate its contents differently, making this contract-sensitive array expression ambiguous. This is a **source-level hypothesis**, NOT a verified Windows root cause or confirmed TShark 4.6.9 defect: an actual number of returned capture frames other than three would give the same assertion.

**Focused test-only corrective commit:** **db6c108**, scripts/verify-dns-wire-source-contract.ps1 only:
- Confirm \`-T jsonraw\` output is a JSON array, by checking its surrounding delimiters; never print the raw response, original DNS names, addresses or reversible label bytes.
- Parse by nesting the *unchanged* raw JSON in a single-object \`{"Frames":[...]}\` envelope so PowerShell reliably exposes the \`Frames\` property as an array. Explicitly require a non-null array and assign it to typed \`[object[]]$rawFrames\` before checking **exactly three** entries.
- Retain the exact original binary Base64 comparisons, independent TShark type/transport checks, malicious pointer rejection, provenance mismatch checks, temporary synthetic PCAP generation/cleanup and every existing acceptance criterion. No relaxing expected counts or skipping a failed frame.
- No changes to scripts/DnsWirePcap.psm1 (production/parser), source importer, source auditor, publisher, test fixture vectors, frozen holdout, workflows or confidence floors. No PS runtime test was run by the assistant; this source change is **NOT YET GREEN**.

**Next owner-only authorized gate:** Fast-forward the existing branch to the correction checkpoint; Parser.ParseFile the changed verify-dns-wire-source-contract.ps1 (the module was already syntax-checked); rerun ONLY \`powershell.exe -NoProfile -File .\scripts\verify-dns-wire-source-contract.ps1 -TsharkPath 'C:\Program Files\Wireshark\tshark.exe'\` without IncludeV2Provenance. If the cardinality assertion still fails, stop: collect only sanitized frame counts/constant failure codes with separate minimal synthetic-local diagnostics, never real capture content. If the next assertion fails, classify it at that exact stage before modifying production code. Only after the core DNS synthetic contract is owner-verified GREEN consider the optional V2 source-binding extension.

**Preserved:** Stage 6G three/six/twelve-round bounded synthetic stress CLOSED GREEN; Stage 6H reader negative 6/6, Stage 6D provenance 26/26, Stage 6E atomic publication 18/18, Stage 6F recovery 15/15 and writer-only 3/3 remain separately verified. DNS original-wire/TShark synthetic contract currently **BLOCKED / NOT GREEN**. Historical V1 FAILED 4/6 immutable; V2 PENDING_EXTERNAL_CAPTURE_AND_REVIEW with 0/4 human-approved external R102 sources. Existing user-owned untracked build-verify PCAPs and logs, privacy controls, original source evidence and all thresholds remain untouched.


### 2026-10-29 — Seventeenth owner-authorized CARTHAGE verification: DNS raw bytes disagreement after frame shape repair

**Owner-observed environment and exact checkout:** Feature branch fast-forwarded from 317917a to **f7a0968** and confirmed by git rev-parse --short HEAD. Windows PowerShell Parser.ParseFile reported **Syntax PASS** for scripts/verify-dns-wire-source-contract.ps1. Owner ran the existing synthetic-only command with explicit \`-TsharkPath "C:\Program Files\Wireshark\tshark.exe"\` (TShark 4.6.9). The test advanced beyond the prior JSON array shape and three-frame count gate, but stopped with **DNS wire source contract: tshark-dns-wire-mismatch** on its initial byte comparison. This means the synthetic raw-frame extraction test is **BLOCKED** and no subsequent wire-label, transport, pointer, multi-question or provenance check completed in this run.

**Static root-cause analysis, not yet runtime established:** The test previously used \`foreach ($reference in @(@(0, $dns1), @(1, $dns2), @(2, $dns5)))\`, read index 0 as the expected frame index and index 1 as expected byte[]. Nested PowerShell array expressions can be enumerated/reshaped at the pipeline boundary; if one tuple is flattened into scalars, the comparison may use the wrong expected reference vector even when TShark exposes correct \`dns_raw\` bytes. The observed mismatch alone cannot establish whether this tuple shape, raw TShark semantics (including TCP framing), or the original synthetic PCAP contributes. Do **not** describe this as proven DNS decoder RED.

**Isolated, source-only regression correction commit:** **2f1a713**, scripts/verify-dns-wire-source-contract.ps1 ONLY:
- Replace implicit nested two-element array tuples with three explicit PSCustomObject reference descriptors, each containing original FrameNumber, JSON result Index and a typed **byte[] Bytes** field, for the original unchanged DNS test vectors dns1/dns2/dns5.
- Require exactly three descriptors and that their typed reference lengths match the original fixture vectors before any comparison. No byte input or TShark output is modified.
- Continue strict Base64-encoded byte-for-byte comparison (a reversible equality method within the process only; values **not logged**). On failure, report a fixed \`tshark-dns-wire-mismatch-frame-N-expected-length-M-actual-length-K\` code derived only from the known synthetic frame number and byte lengths. No raw QNAME, IP, path, raw JSON, hex, base64 or source metadata leaves the test.
- Preserve independent \`dns_raw\` check, the three-frame count, all DNS QTYPE and original transport checks, invalid-pointer cases, source-binding test switch, unique synthetic temp PCAP and cleanup. No change to DnsWirePcap.psm1, live capture, legacy R102 importer/auditor, publisher, original external evidence, rules, CI or approval state.

**Next owner test gate:** Pull branch to the latest checkpoint and confirm SHA; syntax-parse only the edited contract with Parser.ParseFile; run **only** \`powershell.exe -NoProfile -File .\scripts\verify-dns-wire-source-contract.ps1 -TsharkPath "C:\Program Files\Wireshark\tshark.exe"\` (without IncludeV2Provenance). If byte mismatch persists, use the synthetic frame+length code to decide the next targeted diagnostic rather than weakening the comparison. Do not execute optional V2 source-binding until core corroboration is observed GREEN. Current correction is reviewed at source level but **NOT RUNTIME VERIFIED**.

**Governance:** Stage 6G 12/12 stress remains verified and closed within bounded synthetic scope; Stage 6D/E/F/H prior passes remain unchanged. Historical V1 FAILED 4/6 immutable; V2 remains PENDING_EXTERNAL_CAPTURE_AND_REVIEW with 0/4 approved real R102 sources. Production DNS parser, existing local private/untracked \`build-verify\` evidence, confidence thresholds, Shadow/Disabled, cooldowns, baseline and privacy controls untouched.


### 2026-10-29 — Eighteenth owner-authorized Windows verification: exact DNS-over-TCP framing defect identified and patched (runtime RED remains)

**Owner evidence and exact SHA:** The owner fast-forwarded the feature branch from f7a0968 to **fbe1cfb**, confirmed it with git rev-parse --short HEAD, and ran Windows PowerShell Parser.ParseFile: **Syntax PASS** for scripts/verify-dns-wire-source-contract.ps1. Owner then ran the **synthetic-only** wire-source contract under installed TShark **4.6.9** using \`-TsharkPath "C:\Program Files\Wireshark\tshark.exe"\`, with optional V2 provenance OFF. The output failed at **DNS wire source contract: tshark-dns-wire-mismatch-frame-5-expected-length-29-actual-length-31**. No subsequent source-bound question, negative selection or original V2 source validation ran to completion.

**Confirmed protocol analysis:** The original synthetic DNS payload for **frame 5** has exactly **29 bytes** and was already wrapped by New-TcpDnsFrame with a **two-byte big-endian length prefix** (\`0x00 0x1d\`, representing 29), yielding 31 TCP application data bytes. This is the DNS-over-TCP framing defined in RFC 7766 §8; TShark 4.6.9 \`-T jsonraw\` returns that full 31-byte DNS protocol raw value for the synthetic frame. Frames 1 and 2 (UDP, no prefix) passed the previous strictly equal raw-DNS comparison. The earlier test compared the 31 bytes including TCP framing directly against only 29 DNS-message bytes, causing the exact observed 2-byte disagreement. This is **not** evidence of a corruption in original DNS labels. Moreover, static examination uncovered a **genuine decoder-order defect**: scripts/DnsWirePcap.psm1 previously invoked Read-DnsQuestionsFromRaw on \`dns_raw\` bytes before reading transport fields, which would interpret a TCP length prefix as the DNS transaction ID and corrupt the subsequent parsing offset. This production/source-attribution code path needed correction; merely changing the test would be insufficient.

**Production parser correction commit 9601a3e (DnsWirePcap.psm1 only):**
1. Add a **module-private**, non-exported Get-DnsMessageFromTransportRaw helper, explicitly separating UDP (preserve original bytes unchanged, DNS header min 12 bytes) from TCP.
2. For TCP, require at least the two-byte prefix, read its length as big-endian, require a DNS payload of at least 12 bytes and require the declared length to match **exactly** all remaining bytes. Reject missing prefix with constant DNS_WIRE_TCP_PREFIX_TRUNCATED, zero/short/oversized/trailing data with DNS_WIRE_TCP_LENGTH_MISMATCH. Never simply ignore two octets, accept appended message bytes, reinterpret transport, or downgrade a malformed frame.
3. Perform independently decoded source/destination address, port and UDP/TCP checks **before** DNS-header/question decoding; only after transport determination normalize the raw bytes and parse QNAME labels, preserving each original byte (including binary octets), question ordinal and captured frame identity.
4. Correct its independent single-frame TShark \`jsonraw\` deserialization to wrap the original top-level array in a single \`{"Frames": [...]}\` object before requiring **exactly one** frame; this avoids the previously observed Windows PowerShell 5.1 array enumeration ambiguity. No unknown TShark format is silently accepted.
5. Keep the original exported public API and privacy-safe fixed-code failures, original PCAP SHA-256, frame-number/ordinal and transport matching unchanged.

**Regression test changes, committed independently:**
- **b42f87e:** in scripts/verify-dns-wire-source-contract.ps1, for known synthetic frame 5 only, require \`dns_raw\` length **exactly expected 29 + 2**, require the first two bytes to declare **exactly 29**, compare the remaining 29 bytes unchanged with the independently authored DNS fixture, and maintain strict full-wire equality on UDP frames 1 and 2. Original fixture DNS bytes, complete frame count, QTYPE checks, TCP source attribution and invalid-question cases remain unchanged.
- **d4ccfd6:** in the same test script, add a deterministic **module-private** TCP-framing regression invoked inside DnsWirePcap's own module scope; assert a valid 12-byte DNS payload passes both TCP framed and UDP unframed preservation, and require five malformed length-prefix vectors to be rejected with the exact expected constant codes: one-byte prefix truncation, zero length, oversized declaration, undersized declaration and extra trailing byte. No new public test-only API, original PCAP reading or new test files.
- This staged source audit confirmed only these two existing code files changed; the legacy R102 importer/auditor, manifests, snapshots, Windows security monitoring code, CI workflow, frozen holdout and existing untracked user-owned build-verify evidence were not touched.

**Verification scope / honesty:** The assistant reproduced the synthetic fixture's **29-byte DNS + two-byte 0x001d framing = 31-byte TCP raw** relationship with an independent byte-level reference calculation and reviewed GitHub readback. **Neither newly edited PowerShell file has been parser-checked or run on CARTHAGE after these commits.** Do not mark Stage 5 core DNS corroboration GREEN until owner output confirms its full four-positive/five-negative + TCP-negative assertions. The previously observed frame-5 mismatch remains the last runtime result.

**Required next bounded owner-run gate:** Fast-forward the same feature branch to the new documentation checkpoint. Syntax-check BOTH scripts/DnsWirePcap.psm1 and scripts/verify-dns-wire-source-contract.ps1 using Windows Parser.ParseFile (must be zero errors). With user-authorized test time and TShark installed, run ONLY the original synthetic no-live-capture contract:
\`powershell.exe -NoProfile -File .\scripts\verify-dns-wire-source-contract.ps1 -TsharkPath "C:\Program Files\Wireshark\tshark.exe"\`
(no IncludeV2Provenance). Expected valid completion logs include the TCP framing preservation + five negative lengths, then four source-bound questions corroborated + five invalid/ambiguous selections rejected. If any stage fails, stop and record its exact fixed error reason; do not run optional V2 provenance extension or real source admission.

**Preserved gates and governance:** Stage 6G 3/6/12-round publication visibility and Stage 6H 6/6 reader negative remain GREEN; Stage 6D 26/26 provenance, Stage 6E 18/18 atomic publication, Stage 6F recovery 15/15 and writer contention 3/3 remain previously verified. Immutable V1 FAILED 4/6 unchanged. V2 PENDING_EXTERNAL_CAPTURE_AND_REVIEW, **0/4 externally approved original R102 sources**. Original thresholds R102 80%, R118 86%, R163 84%, external R102 min 0.75, Shadow/Disabled, cooldowns, journal, baseline and privacy invariant preserved. Synthetic validation never certifies commercial release, crash durability, true source independence, legal source rights or real R102 detector accuracy.

**Reference:** RFC 7766, section 8: https://www.rfc-editor.org/rfc/rfc7766.html#section-8


### 2026-10-29 — Nineteenth owner-authorized CARTHAGE verification: Wireshark jsonraw descriptor parsing, correctly classified (runtime pending)

**Observed exact Windows checkout and tool:** The owner fast-forwarded the feature branch from fbe1cfb to **849431b**, then verified that SHA with git rev-parse --short HEAD. Windows PowerShell Parser.ParseFile reported **Syntax PASS** for both the changed scripts/DnsWirePcap.psm1 and scripts/verify-dns-wire-source-contract.ps1. The owner executed the exact locally generated synthetic-PCAP DNS contract with TShark **4.6.9**, using its installed absolute executable path, and WITHOUT optional -IncludeV2Provenance.

**Runtime result at 849431b:** The independent TCP framing regression printed **"DNS TCP framing: unmodified UDP and exact TCP payload preserved; five invalid length prefixes rejected."** This confirms the newly implemented strict TCP-prefix helper's 2 positive preservation cases and five negative cases succeeded in the Windows test. Immediately afterward, the first original-PCAP question extraction failed with constant **DNS_WIRE_RAW_AMBIGUOUS** from scripts/DnsWirePcap.psm1. Consequently, the complete DNS source-bound question test and optional V2 provenance tests **have NOT passed**; do not claim four/five original DNS validations GREEN.

**Root cause confirmed by source review and official Wireshark format documentation:** Wireshark \`-T jsonraw\` encodes one raw protocol field as a **single 5- or 6-item descriptor** of the form [hexadecimal octets, original frame offset, field byte length, bitmask, field type, optional data-source index]. Those entries are not five or six distinct DNS messages. For example, Wireshark-generated DNS jsonraw contains \`"dns_raw": ["...", 42, 28, 0, 1]\`; recent Wireshark 4.6.x baseline files also show the sixth source-index item. The prior module performed \`$rawValues=@($rawProperty.Value)\` followed by \`if($rawValues.Count -ne 1) { Fail-Wire 'DNS_WIRE_RAW_AMBIGUOUS' }\`. That incorrectly treated the descriptor's five/six metadata fields as repeated DNS protocol payloads and rejected the correctly formed TShark result. The earlier synthetic top-level test used the first hex field only, which explains why the TCP framing tests could pass while the source-bound module still failed.

**Narrow production correction, commit 4cf6a78 (scripts/DnsWirePcap.psm1 only):**
1. Add one **module-private** \`Convert-DnsJsonRawDescriptor\` helper, requiring exactly one array descriptor of **5 or 6** members. Require the first member to be a hex string, the remaining members to be nonnegative integer metadata, and protocol-level bitmask to be zero. Reject unexpected array/object/scalar/nested formats with the unchanged constant \`DNS_WIRE_RAW_AMBIGUOUS\`.
2. Convert **only** the descriptor's first hex string to bytes using the existing strict Convert-WireHex routine. Require its decoded byte length to equal the descriptor's declared length (item 3, zero-based index 2); otherwise fail with fixed code \`DNS_WIRE_RAW_LENGTH_MISMATCH\`. The byte count is metadata, not captured content.
3. Feed those exact bytes into the previously implemented transport-specific decoder, preserving mandatory TCP length-prefix validation, identity of every UDP octet, original frame and question-ordinal binding, source/destination/port and SHA-256 checks. **No fallback to presentation-form \`dns.qry.name\`, no implicit acceptance of multiple DNS records and no output of reversible DNS bytes or private paths.**
4. Keep all exported API signatures and default strict-fail behavior; do not change unrelated production modules, importer/auditor, holds, application monitoring, source capture or CI.

**Regression changes, commit a3a6255 (scripts/verify-dns-wire-source-contract.ps1 only):** Reuse the existing module-private test context and artificial twelve-byte DNS fixture. Assert that both real jsonraw descriptor layouts (5-member and 6-member) return the exact same twelve DNS bytes. Reject **ten** artificial malformed cases with strict fixed codes: too few/many members, mismatched declared length, multiple nested descriptors, nonzero bitmask, negative offset, wrong hex field type, string instead of numeric metadata, invalid hex and scalar instead of an array. The existing five invalid TCP length prefix regressions and four source-bound positive/five negative question contracts are **preserved**. No real PCAP, captured IP, original DNS label, URL, path or payload is emitted into stdout. Note that a source-only review cannot substitute for Windows runtime testing.

**Verification status:** Branch commits 4cf6a78 and a3a6255 have been successfully written and read back, with no production public API changes. **Parser checks and full synthetic runtime validation of these new edits are still PENDING** on CARTHAGE. Stage 5 DNS corroboration remains BLOCKED, not GREEN. The last owner runtime output confirms TCP framing valid and isolates the subsequent raw-descriptor parsing failure, but does not certify the new descriptor fix.

**Next owner-only action:** Fast-forward existing feature branch, record exact git SHA, Parser.ParseFile syntax-check BOTH edited PowerShell files and rerun only:
\`powershell.exe -NoProfile -File .\scripts\verify-dns-wire-source-contract.ps1 -TsharkPath "C:\Program Files\Wireshark\tshark.exe"\`
Do not add \`-IncludeV2Provenance\` yet. Require:
- TCP framing summary: two positive byte-preservation checks + five malformed-prefix rejections.
- TShark descriptor summary: two positive 5/6-field descriptor checks + ten malformed descriptor rejections.
- Core original synthetic PCAP summary: four source-bound question selections corroborated + five invalid/ambiguous selections rejected.
Stop on the first non-PASS or constant failure code and record it before any other changes. No live packet capture, public-network scans, old importer, private evidence examination or real-source approval.

**Governance and previously closed gates:** Stage 6G concurrent reader maximum stress 12/12 GREEN, Stage 6H negative reader sensitivity 6/6, Stage 6D private provenance 26/26, Stage 6E atomic publication 18/18, Stage 6F recovery planner 15/15 and writer competition 3/3 remain owner-verified, unaffected. Original V1 FAILED 4/6 remains immutable. V2 PENDING_EXTERNAL_CAPTURE_AND_REVIEW 0/4 approved. R102/R118/R163 floors (80/86/84%), R102 holdout minimum 0.75, Shadow/Disabled, cooldowns, baseline, journal and privacy unchanged.

**External format references (read-only):**
- Wireshark official \`tshark -T jsonraw\`: https://www.wireshark.org/docs/man-pages/tshark
- Wireshark JSON-to-PCAP raw descriptor structure and DNS example: https://www.h21lab.com/tools/json-to-pcap/
- Wireshark 4.6.x jsonraw baseline six-member descriptor: https://fossies.org/linux/wireshark/test/baseline/dhcp.jsonraw


### 2026-10-29 — Twentieth owner-authorized CARTHAGE verification: core DNS original-wire/TShark corroboration GREEN

**Observed exact revision and PowerShell syntax:** Owner fast-forwarded feature/carthago-reliability-hardening to **a5bc69f**, and confirmed it using git rev-parse --short HEAD. Windows PowerShell Parser.ParseFile reported **Syntax PASS** for both \`scripts/DnsWirePcap.psm1\` and \`scripts/verify-dns-wire-source-contract.ps1\`. The owner ran the existing **synthetic-only** generated-PCAP contract with locally installed **TShark 4.6.9**, explicit \`-TsharkPath "C:\Program Files\Wireshark\tshark.exe"\`, and **without** \`-IncludeV2Provenance\`.

**Complete, successful owner-supplied output:**
\`\`\`text
DNS TCP framing: unmodified UDP and exact TCP payload preserved; five invalid length prefixes rejected.
TShark jsonraw descriptor: 5/6-member formats preserved; ten ambiguous or invalid descriptors rejected.
DNS wire source contract: four source-bound questions corroborated; five invalid/ambiguous selections rejected. Synthetic evidence only.
\`\`\`
The command returned to the PowerShell prompt without a contract exception. The previous observed failure \`DNS_WIRE_RAW_AMBIGUOUS\` no longer occurred in this run.

**Verified scope and counts, from the executed script and observed stdout:**
- DNS-over-TCP length prefix: two positive data-preservation checks (TCP framed DNS and unchanged UDP) with five intentionally malformed TCP framing vectors rejected.
- Independent TShark JSON raw descriptor extraction: **two positive layouts** (five-field and six-field) preserve the same synthetic byte payload; **ten malformed/ambiguous descriptor vectors** rejected with fixed error codes, including inappropriate structure/metadata/byte lengths.
- Synthetic-PCAP original-frame DNS comparison: **four original-bound question selections** preserved binary label octets, frame index, selected question ordinal, DNS type and IPv4/UDP/TCP source/destination port attribution; **five invalid/ambiguous cases** rejected (out-of-range ordinal, forward pointer, cycle, truncated question, absent frame).
- Original selected synthetic PCAP SHA-256 integrity verified, byte-for-byte DNS payload comparisons against separately derived \`dns_raw\` and TShark QTYPE checks were reached without exceptions. The test creates and removes only its uniquely named synthetic temporary fixture.
- The two parser and regression files passed syntax on the owner's actual Windows PowerShell installation. The assistant did not execute TShark or Windows tests.

**Disposition:** Core DNS wire representation + original frame/TShark corroboration regression is now **GREEN within its fully synthetic Stage 5 scope** at a5bc69f. The earlier 4 failure iterations are retained historically in this ledger, not overwritten. This is meaningful verification of handling binary DNS label bytes, DNS-over-TCP framing and strict \`jsonraw\` descriptors; it does **not** validate rights/labels/origin of third-party PCAP evidence, prove field detector accuracy or authorize any holdout admission.

**Next distinct, already-authored gate (not yet executed):** \`scripts/verify-dns-wire-source-contract.ps1 -IncludeV2Provenance\`. Its source already defines:
1. Two synthetic frame+question-ordinal-bound candidate records compared against the **same original synthetic PCAP** with SHA-256 provenance.
2. Eighteen deliberate provenance/record tampering mutations plus a missing-original-capture case: **nineteen negative checks**. These include changed capture hash/frame/ordinal, duplicated question, missing cardinality, invalid encoding, altered binary labels, QTYPE/IP/port/protocol, missing client attribution, unsafe metadata, and extra record field.
3. Seven synthetic logical-source comparison cases (mirrored name sets despite ASCII case/order, disjoint and partial overlap, reused session, reused originating client, reused original frame and non-ASCII bytes remaining distinct). This is **review-risk classification only**: every case must set \`RequiresAnalystReview=true\`, \`IndependenceApproved=false\`.

**Source-only preflight:** The optional switch exists, is false by default and reuses the identical synthesized temporary PCAP; it does not invoke the old importer/auditor or touch private user sources. The existing candidate binder uses strict fail-closed identity matching and strips source metadata from its success result. This optional extension is **NOT YET GREEN**; its output must be observed before reporting approval of the extra checks.

**Recommended owner-run follow-up:** Pull latest documentation checkpoint, confirm HEAD, then run ONLY \`powershell.exe -NoProfile -File .\scripts\verify-dns-wire-source-contract.ps1 -TsharkPath "C:\Program Files\Wireshark\tshark.exe" -IncludeV2Provenance\`. Expect the three already-verified core logs followed by \`V2 frame/question binding contract: two source-bound records; nineteen tampering/missing-original cases rejected. Source syntax only.\` and \`V2 logical-source contract: seven mirror, overlap, session, origin, frame-reuse and non-ASCII review scenarios defined. No source approved.\` If any stage fails, stop at the exact constant code and do not rerun closed concurrency gates or change application behavior speculatively. The optional extension uses exclusively synthetic local data; no live capture, public network probe, old importer, source admission or CI is authorized by this gate.

**Frozen and pending evidence unchanged:** Historical immutable V1 FAILED 4/6; V2 PENDING_EXTERNAL_CAPTURE_AND_REVIEW with **0/4 approved external R102 samples**. Stage 6G bounded 3/6/12 concurrent-reader tests GREEN, 6H reader negative 6/6 GREEN, 6D provenance 26/26 GREEN, 6E atomic publisher 18/18 GREEN and 6F recovery and race GREEN. Thresholds R102 80%, R118 86%, R163 84%, external R102 0.75, privacy, Shadow/Disabled, cooldowns, baseline and journal integrity remain unchanged. The assistant changed **only this centralized ledger** in response to the owner PASS.


### 2026-10-29 — Twenty-first owner-authorized CARTHAGE run: V2 candidate field-schema Compare-Object entered interactive binding; fail-closed fix authored

**Owner-observed checkout and execution:** The owner fast-forwarded the existing feature branch from a5bc69f to **e4c84e8**, updating only this centralized ledger. They then ran \`powershell.exe -NoProfile -File .\scripts\verify-dns-wire-source-contract.ps1 -TsharkPath "C:\Program Files\Wireshark\tshark.exe" -IncludeV2Provenance\`. The THREE core DNS validation logs **repeatedly passed**: (1) TCP/UDP framing and five malformed length prefixes, (2) five/six-field TShark jsonraw descriptors and ten malformed descriptors, and (3) four original-frame synthetic DNS questions and five invalid selections. Immediately on entering the optional V2 source-candidate check, Windows PowerShell issued an **interactive mandatory-parameter prompt**:
\`\`\`text
cmdlet Compare-Object at command pipeline position 1
Supply values for the following parameters:
DifferenceObject[0]:
\`\`\`
The user has been instructed to press **Ctrl+C**, leave the prompt unanswered and stop the run. Because the extension never completed, **optional V2 source binding and seven source-independence controls remain NOT VERIFIED**; the hang is a harness/validator interactivity defect, not evidence of source admission, detector performance, or malformed original capture.

**Source-level root cause:** \`Confirm-DnsWireCandidateBinding\` in \`scripts/DnsWirePcap.psm1\` tried to validate its nine-field record allowlist using a positional \`Compare-Object\` call fed by two \`Sort-Object\` pipeline expressions. The Windows runtime entered mandatory positional parameter collection instead of returning a deterministic schema result. The exact upstream pipeline argument that was absent is not separately observed, but this interactive use is unsafe in a fail-closed verifier. The same class of empty-array command-binding failure had previously been corrected in Stage 6E's publisher; no other \`Compare-Object\` call remains in the DNS module after this change.

**Source-only repair commits:**
1. **8a4cf59**, \`scripts/DnsWirePcap.psm1\`: replace only the positional \`Compare-Object\` schema comparison with a **module-private** \`Test-DnsExactRecordFields\` validator, using \`HashSet[string]\` and \`StringComparer.Ordinal\`. Require every input field to be a PowerShell NoteProperty; collect actual field names with no pipeline, require equal cardinality, and require every allowlisted name to match **case-sensitively**. This returns a strict boolean for empty, partial, unexpected or mis-cased records without prompts. The prior \`DNS_WIRE_RECORD_SCHEMA\` fail-closed error, strict UDP/TCP boolean typing, original candidate checks and existing public exports are unchanged.
2. **f5347bc**, \`scripts/verify-dns-wire-source-contract.ps1\`: add an explicit module-private schema-sensitivity preflight **only behind the already-existing \`-IncludeV2Provenance\` switch**. Require a valid two-field synthetic record accepted and exactly four malformed synthetic records (empty, missing, extra, case-mismatched) rejected. The regression gate is \`record-schema-exact-field-regression\` with privacy-safe summary \`V2 record schema: one exact layout accepted; four malformed layouts rejected.\` Preserve the prior two valid original-frame candidate checks, **all 19** tamper/missing-original negative cases, seven logical-source review scenarios, and three already-passing core DNS summaries.
3. **4b0d144**, \`scripts/DnsWirePcap.psm1\`: use the full \`System.Management.Automation.PSMemberTypes\` enum qualification for Windows PowerShell type resolution. No behavior change intended.

**Static review and safety:** Original PCAP synthesis, raw-byte TShark corroboration, original SHA-256 binding, field-level attribution and private binary DNS label representation are unchanged. No second duplicate V2 module, extra documentation file, workflow, branch, production capture, R102 import, source approval or original evidence manipulation. The importer/auditor remain parked and unchanged. This is **not** a production data migration and does not authorize an external sample as valid.

**Next single owner test:** Confirm Ctrl+C terminated the hung optional verification; fast-forward the feature branch to latest documentation checkpoint; \`git rev-parse --short HEAD\`; parser-check **both changed PowerShell files** with Parser.ParseFile and then run only \`powershell.exe -NoProfile -File .\scripts\verify-dns-wire-source-contract.ps1 -TsharkPath "C:\Program Files\Wireshark\tshark.exe" -IncludeV2Provenance\`. Expect the existing three core DNS passes, new \`V2 record schema: one exact layout accepted; four malformed layouts rejected.\`, and finally V2 original frame/question binding two-positive/19-negative and the seven logical source-review scenarios, without any interactive prompt. If another prompt appears, press Ctrl+C and stop. If any fixed-code assertion fails, report it and stop; do not add acceptance bypasses.

**Verification status:** All three core DNS synthetic output lines remain **GREEN at e4c84e8**. Optional V2 binding/risk extension remains **BLOCKED / NOT VERIFIED** until the owner's Windows runtime executes the repaired code successfully. Stage 6G bounded 12/12, Stage 6H 6/6, Stage 6D 26/26, Stage 6E 18/18, Stage 6F recovery 15/15 and writer race 3/3 previously verified, not rerun. Historical frozen V1 FAILED 4/6 unchanged; V2 PENDING_EXTERNAL_CAPTURE_AND_REVIEW with 0/4 approved external R102 candidates. Confidence floors R102 80%, R118 86%, R163 84%, external R102 0.75, Shadow/Disabled, cooldowns, privacy and journal integrity preserved.


### 2026-10-29 — Twenty-second owner-authorized CARTHAGE verification: optional V2 original-frame binding + logical-source review GREEN

**Owner-proven exact checkout:** Owner fast-forwarded feature/carthago-reliability-hardening from e4c84e8 to **e412c2a** and explicitly reported \`git rev-parse --short HEAD\` = **e412c2a**. Their Windows PowerShell Parser.ParseFile separately checked **scripts/DnsWirePcap.psm1** and **scripts/verify-dns-wire-source-contract.ps1**, both reporting **Syntax PASS**. The same user then ran \`powershell.exe -NoProfile -NonInteractive -File .\scripts\verify-dns-wire-source-contract.ps1 -TsharkPath "C:\Program Files\Wireshark\tshark.exe" -IncludeV2Provenance\` under installed TShark 4.6.9. No live capture, third-party PCAP or private user-owned evidence was provided or accessed for this test.

**Full owner-observed stdout, with clean return to prompt (no exception or interactive query):**
\`\`\`text
DNS TCP framing: unmodified UDP and exact TCP payload preserved; five invalid length prefixes rejected.
TShark jsonraw descriptor: 5/6-member formats preserved; ten ambiguous or invalid descriptors rejected.
DNS wire source contract: four source-bound questions corroborated; five invalid/ambiguous selections rejected. Synthetic evidence only.
V2 record schema: one exact layout accepted; four malformed layouts rejected.
V2 frame/question binding contract: two source-bound records; nineteen tampering/missing-original cases rejected. Source syntax only.
V2 logical-source contract: seven mirror, overlap, session, origin, frame-reuse and non-ASCII review scenarios defined. No source approved.
\`\`\`

**Verified synthetic gate accounting:**
1. TCP/UDP exact-byte preservation: valid framed TCP and unframed UDP retained identical DNS messages; **five** intentionally invalid TCP-prefix forms rejected.
2. TShark \`jsonraw\` 5/6-field raw-descriptor decoding preserved the bytes of **two** valid layouts and rejected **ten** malformed, contradictory or ambiguous descriptors.
3. Original-frame DNS-source contract: **four** packet-bound question selections (including original binary label octets, compressed DNS question ordinal, selected transport and IPv4/port attribution) corroborated against TShark; **five** malformed/missing selections rejected.
4. Private record-field schema matcher: one valid ordered-independent/case-exact field set accepted and **four** invalid field layouts (empty, missing, extra, case altered) rejected; the previously observed Windows \`Compare-Object\` mandatory-parameter prompt did not recur in this noninteractive run.
5. Synthetic V2 candidate evidence: **two** captured-frame-and-question-ordinal-bound records validated against the unchanged generated PCAP SHA-256; **nineteen** tampered or missing-original cases rejected. Accepted result did not disclose raw label bytes or original source address.
6. Seven logical-source review-risk scenarios completed, covering mirrored DNS label sets despite name-case/permutation differences, fully disjoint sets, partial overlap, same collection session, same client identity, reused original capture frame and distinct non-ASCII octets. Each review result retains \`RequiresAnalystReview=true\` and \`IndependenceApproved=false\`. Completion is NOT an assertion of independent real sources or analyst approvals.

**Gate disposition:** Core DNS original-wire/TShark contract **GREEN**, optional Stage 6 original-frame/ordinal candidate binding **GREEN**, optional synthetic source-independence risk classification **GREEN**, all verified at exact owner-executed SHA e412c2a. The assistant did not run Windows PowerShell or TShark; code-review checks and owner stdout are distinct evidence. The 2026-10-29 failed JSON-cardinality, TCP-prefix, jsonraw-descriptor and noninteractive field-shape attempts remain in earlier ledger entries as immutable investigative history. **Do not reflexively rerun these already-closed synthetic tests** unless a relevant code change makes their verification necessary.

**Source-only integration/migration audit, verified at the feature branch after test:**
- \`scripts/DnsWirePcap.psm1\` provides correct canonical private wire label byte representation \`dnsWireLabelsBase64\` and \`Confirm-DnsWireCandidateBinding\` binds each selected original PCAP SHA-256 + **frame number and question ordinal** to the exact transport/IP/port, question type and binary label bytes. The helper does not itself provide a complete real-source licensing, confidentiality or independent-label review workflow.
- \`scripts/import-holdout-v2-r102.ps1\` is a separate **legacy producer**. It invokes TShark \`-T fields\` and reads \`dns.qry.name\`, trims trailing dots, lowercases QNAME text, and serializes 11-field records with \`dnsQname\` but **without** \`dnsWireLabelsBase64\`. It records \`frameNumbers\` only, not \`questionIndices\`, and emits \`schemaVersion=1\` provenance. It currently writes JSON directly to a private output folder. This format is **not equivalent** to the verified wire-exact, frame+ordinal candidate evidence model; silently mapping lowercased \`dnsQname\` back to bytes would be lossy and forbidden.
- \`scripts/audit-holdout-v2-candidates.ps1\` likewise checks 11-field \`dnsQname\`, uses frame-only keys and the presentation-form TShark \`dns.qry.name\` comparison. It includes important source/license, classification, confidence and capture-hash checks, which must be **preserved**; however, it is not wired to the new byte-exact \`Confirm-DnsWireCandidateBinding\` proof or multi-question source identity.
- \`scripts/HoldoutV2CandidatePublisher.psm1\` retains strict **eleven-field legacy sample** expectations (including \`dnsQname\`) and existing batch-level provenance/atomic-publication controls. Its already-proven Stage 6D–6H behavior must not be casually modified to accept nine-field binary-only records; doing so could break the verified batch, recovery and privacy contracts. This is an **end-to-end schema/interface migration** for producer, audit, publisher and downstream replay/evaluation consumers, not a one-line import upgrade.
- \`docs/holdout-evaluation-v2-manifest.json\` still declares the four external R102 slots with null pinned Git blobs and global \`approvalState=PENDING_EXTERNAL_CAPTURE_AND_REVIEW\`. No observed synthetic tests fill those slots or establish external label truth.

**Next engineering priority (designed, not implemented/authorized by this PASS): versioned, fail-closed integration plan.** Do not duplicate DnsWirePcap parsing code or overwrite legacy evidence. First enumerate all downstream consumers of 11-field \`dnsQname\` and source-audit approvals, and pin an explicit **versioned pending-only private candidate schema** with exact byte labels and question ordinal plus existing privacy/license/analyst/source-risk requirements. Next design deterministic synthetic compatibility and negative tests for malformed labels, case-sensitive field allowlists, duplicate frame+ordinal keys, multi-question frames, TCP framing, repeated or shared real-source identity, blocked source/licensing states, and no automatic promotion. Prove a *separate*, read-only/scratch-only migration adapter if necessary; never infer irreversible binary bytes from old presentation strings. Only then consider changing the legacy importer/auditor/publisher or evaluation format in tightly scoped, tested commits, preserving published batch atomicity and legacy V1 holdout immutability. The safest immediate follow-up is **source-only contract inventory and parked tests**, not importing real captures.

**Preserved controls:** Stage 6G 3/6/12 three-process concurrency CLOSED GREEN; Stage 6H negative reader 6/6; Stage 6D provenance 2 pending positives+24 negatives; Stage 6E atomic publication 18/18; Stage 6F recovery R01–R15 and two-writer race 3/3. Historical V1 FAILED 4/6 immutable; Holdout V2 **PENDING_EXTERNAL_CAPTURE_AND_REVIEW, 0/4 externally approved**. R102 80%, R118 86%, R163 84%, external R102 minimum 0.75, Shadow/Disabled, cooldowns, baseline, privacy, journal, and original user-owned private/ignored build-verify evidence unchanged. **This commit only updates the single central ledger.**


### 2026-10-30 — Stage 8 versioned DNS wire-to-legacy replay migration boundary: source implemented, tests PARKED / NOT RUN

**Scope and provenance of work:** Owner requested continuation to the next milestone after CARTHAGE successfully validated the complete synthetic DNS/TShark wire-source, frame+question, provenance-tamper and source-risk contract at exact test SHA e412c2a. That previous GREEN outcome is documented above and **was not rerun**. The user previously requested deep, single-ledger documentation and that all subsequent tests and validation remain explicitly parked until owner test time. This milestone is deliberately a **new, read-only compatibility boundary**; it is NOT a migration of existing private evidence, NOT a production importer/auditor release, NOT a source approval or a replacement for the approved synthetic concurrency and provenance gates.

**Source inventory completed before editing:** Exact repository state inspected across the original DNS parser/binder; 30-field private V2 provenance schema and four-slot validator; atomic publisher; legacy R102 producer/auditor; frozen holdout manifest; V2 freeze tool; V2 benchmark/replay evaluator; and the existing synthetic DNS/TShark test script. These consumers are NOT mutually compatible today, and the dependency matrix is explicit:
- Original byte reader and binder: scripts/DnsWirePcap.psm1 — accepts nine strict private fields including dnsWireLabelsBase64, frameNumbers PLUS zero-based questionIndices, source capture SHA-256, independent TShark source/IP/port/transport/type binding. Original binary bytes are reconstructible from canonical Base64, including non-ASCII bytes. Tested GREEN at e412c2a; **untouched**.
- Pending-only batch sidecar: scripts/HoldoutV2Provenance.psm1 with docs/contracts/holdout-v2-private-provenance-v2.schema.json — EXACT 30-field schemaVersion=2, four declared V2 R102 slots (two benign/two malicious), original frame/question tuple uniqueness and pending-only approval outcome. Validating one compatible record is NOT a substitute for this four-slot review. **Untouched**.
- Legacy importer: scripts/import-holdout-v2-r102.ps1 — TShark presentation dns.qry.name, lowercasing, 11-field dnsQname records, frameNumbers only and historical provenance schemaVersion=1; currently writes private candidate JSON to build-verify. **Untouched and NOT invoked**.
- Legacy auditor: scripts/audit-holdout-v2-candidates.ps1 — compares lowercased text QNAME, frame-only references and typed 11-field records; retains nontrivial license, source attribution and class checks that MUST be preserved in any later migration. **Untouched and NOT invoked**.
- Private publisher: scripts/HoldoutV2CandidatePublisher.psm1 — expects the 11-field old replay schema and four sidecars; Stage 6D–6H atomicity and concurrent visibility already checked against this interface. A new nine-field sample must NOT be routed into it without a separate versioned adapter and renewed negative/atomicity tests. **Untouched and NOT invoked**.
- Freeze and evaluator: scripts/freeze-holdout-v2.ps1 and scripts/evaluate-holdout-v2.ps1 — rely on old QNAME-format fixtures and frame-only provenance; V2 manifest still explicitly PENDING_EXTERNAL_CAPTURE_AND_REVIEW and four external R102 Git blobs are null. Neither freezes nor replay runs can be authorized by a text-compatibility result. **Untouched and NOT invoked**.
- Source acquisition from external repositories, public PCAP inspection, third-party data rights, independent labels and live detector scoring are **not in this milestone**.

**New implementation in existing feature branch:** Created scripts/HoldoutV2WireReplayBridge.psm1 in commit **551afd4** (new source blob 7cf84da3d5d9f53caf21ae508e1e103ee85b53f1). It exports ONLY Confirm-HoldoutV2WireReplayCompatibility:
1. Requires proposed PRIVATE schemaVersion=2, historical sourceKind token external-pcap-reviewed (NOT legal approval), exact dnsWireNameEncoding=labels-base64-v1, reviewState=PENDING_EXTERNAL_CAPTURE_AND_REVIEW, typed review flags, privacyReviewRequired=true and exactly 3..500 source records with consistent declared count. Rejects legacy schemaVersion=1 and any claim of an approved state. Requires a canonical, lowercase, multi-label queryRoot.
2. Calls the already verified Confirm-DnsWireCandidateBinding on the explicitly provided **original local capture**, without publishing or writing any data. This rechecks original SHA-256, exact frame AND question ordinal, binary name labels, DNS QTYPE, captured UDP/TCP/IP/ports and strict nine-field record schema. Maps all underlying source failures to the metadata-only constant BRIDGE_SOURCE_BINDING_FAILED, avoiding incidental path/QNAME disclosure.
3. The PRIVATE Convert-BridgeWireLabelsToLegacyName helper constructs a temporary in-memory dotted name from **canonical RFC 4648 Base64 per original DNS label** only if ALL bytes are already lowercase ASCII a–z, digits, hyphen or underscore. It requires at least two nonempty labels, maximum 63 octets per label, maximum 255 expanded wire octets and maximum 253 printable characters. It does NOT Unicode-decode, strip dots, lower-case bytes, normalize trailing dots or reinterpret binary data. It rejects 0xff, NUL, embedded dot, case-sensitive uppercase, invalid/noncanonical Base64 or other nonreversible input with BRIDGE_NAME_NOT_LOSSLESS. The resulting dotted name must match or end with the exact original queryRoot with ordinal case-sensitive suffix matching; otherwise BRIDGE_ROOT_MISMATCH. Legacy representation is therefore a deliberately restricted, byte-identical subset; **most binary names remain ineligible for old replay**.
4. The only success output is nine safe metadata properties: OriginalFrameQuestionsBound=true, TextProjectionPossible=true, ProjectionProduced=false, RecordCount, ReviewState=PENDING_EXTERNAL_CAPTURE_AND_REVIEW, RequiresHumanReview=true, IsApproved=false, CanPublish=false and CanFreeze=false. It NEVER emits source addresses, names, reversible labels, capture paths, hashes, source URLs or a printable replay sample. It has NO filesystem writes, active network operations, external-source acquisition or approval/promotion/publication/freeze APIs.
5. This is expressly a **one-candidate compatibility diagnostic**, not the four-candidate 30-field provenance validator, source-rights review, ground-truth labeling, 11-field output adapter or V2 detector accuracy test. A TRUE value cannot be treated as consent or proof of release readiness.

**Existing synthetic suite extended behind a separate explicit owner gate:** Commit **3b00e69** modified only scripts/verify-dns-wire-source-contract.ps1 by adding optional IncludeReplayCompatibility plus AuthorizedTestTime. Later source-only fixture hardening **a315ced** uses strongly typed List[byte[]] to prevent Windows PowerShell nested-array flattening, and **91441c3** counts metadata output field names without relying on collection enumeration. The existing default three DNS summaries and existing optional IncludeV2Provenance branch remain logically untouched; Stage 8 code is not entered unless the new switch is explicitly set, and that switch refuses execution without AuthorizedTestTime.

**Stage 8 regression inventory, all PARKED / NOT EXECUTED:**
- Pure in-memory helper sensitivity: two valid printable lower-case synthetic names (plain and with underscore), and **ten** independent fixed-code rejections for uppercase, embedded dot, 0xff, NUL, invalid Base64 padding, overlong label, single label, empty label array, oversized expanded name and scalar/non-array input.
- An additional locally generated four-frame synthetic PCAP written only within the test's unique temporary folder: three source-bound alpha/beta/gamma.example.test original DNS questions, where two are UDP and the third TCP; one extra UDP frame has an actual 0xff binary label. No private or external capture is used, even if one happens to exist on disk.
- Positive bridge integration: three original PCAP SHA/frame/zero-based-ordinal/UDP-TCP source-bound records matched by the existing DnsWire binder, root-exact and text-exact, returning only nine privacy-safe pending-review metadata fields, never projected fixture contents. Publisher and freeze flags MUST remain false.
- **Eleven** negative source, format and approval controls: mismatched query root, forged approved state, old provenance schemaVersion=1, lossy text encoding token, selected count mismatch, tampered source label, missing original PCAP, noncanonical root capitalization, disabled required privacy flag, duplicate frame/ordinal reuse, and original binary 0xff label that binds successfully at its real frame but MUST be refused as legacy text. No projected bytes or private values are printed.
- Tests expect stable metadata-only pass summaries: (a) two exact printable names / ten non-lossless rejected, and (b) three original frame/question records bound / eleven negative source/schema/binary/review cases rejected / no projected samples or approvals. A runtime exception or prompt is a RED result, not an implied PASS.
- The script maintains its original GUID-owned temporary fixture cleanup in the finally block. No CI workflow, default test suite, scheduled runner or live network operation was modified.

**Test-time policy:** The owner has NOT yet supplied a Windows transcript for the new bridge code. All source edits are **SOURCE COMMITTED / WINDOWS PARSER AND RUNTIME PENDING**. No source-level review, returned commit SHA or synthetic test construction proves PASS. The existing complete DNS/TShark + optional V2 provenance GREEN remains independently grounded in owner output at e412c2a, and concurrent publication gates 6D–6H remain unchanged. Do not automatically rerun old gates.

**Single next owner-gated Windows test (do NOT execute without user authorization):** First fast-forward feature/carthago-reliability-hardening and confirm git rev-parse --short HEAD, then invoke Parser.ParseFile on BOTH scripts/HoldoutV2WireReplayBridge.psm1 and scripts/verify-dns-wire-source-contract.ps1; require zero errors. At an explicitly approved test window, run ONLY the synthetic local opt-in extension under Windows PowerShell 5.1, using the already installed absolute TShark:
powershell.exe -NoProfile -NonInteractive -File .\scripts\verify-dns-wire-source-contract.ps1 -TsharkPath "C:\Program Files\Wireshark\tshark.exe" -IncludeReplayCompatibility -AuthorizedTestTime
Stop on the first unexpected code, log sanitized exact output plus SHA and diagnose BEFORE any source admission, importer/auditor change, live capture, CI or production release.

**Next integration sequence after this milestone is owner-verified GREEN (NOT YET IMPLEMENTED):**
- M1: Complete full 30-field four-slot schema and licensing/independent-label/analyst review in the source workflow, independent of printable legacy compatibility. Do not allow synthetic claims to certify external-source approval.
- M2: Author a separately versioned, non-publishing/private sample adapter only for the proved printable ASCII subset. Store original binary wire labels and frame+ordinal binding privately as mandatory review-only evidence, never reconstruct them from lowercased dnsQname text.
- M3: Update source importer and auditor with opt-in new-version feature gating, preserving original license/privacy checks and testing ambiguity, multiple questions per frame, overlap and source/session independence. Keep current 11-field version stable until regression.
- M4: Evolve publisher and recovery protocols only after independent atomicity, reader consistency, fault injection and exact-byte privacy tests for the new schema. Previously GREEN Stage 6D–6H applies ONLY to their previously tested version, never automatically to new record formats.
- M5: Evaluate freeze and benchmark replay semantics against a separately reviewed and pinned external R102 corpus with explicit owner approval; preserve prior V1 FAILED 4/6 and V2 default pending state, no confidence-floor reductions.

**Preservation:** Historical immutable V1 FAILED 4/6 and V2 PENDING_EXTERNAL_CAPTURE_AND_REVIEW (0/4 approved) remain unchanged. R102 80%, R118 86%, R163 84% confidence floors, external R102 minimum 0.75, Shadow/Disabled behavior, cooldowns, journal integrity, privacy and original untracked build-verify evidence remain untouched. This stage changed ONLY one new read-only bridge module, one opted-in synthetic test script and this one central ledger. No external approval, detection accuracy or production security-monitoring behavior was changed.


### 2026-10-30 — Stage 8 owner test attempt: parameter binding failed BEFORE script execution (not a regression result)

**Owner transcript:** Ran \`powershell.exe -NoProfile -NonInteractive -File .\scripts\verify-dns-wire-source-contract.ps1 -TsharkPath "C:\Program Files\Wireshark\tshark.exe" -IncludeReplayCompatibility -AuthorizedTestTime\`. PowerShell immediately returned \`A parameter cannot be found that matches parameter name 'IncludeReplayCompatibility'\`, \`FullyQualifiedErrorId: NamedParameterNotFound,verify-dns-wire-source-contract.ps1\`. **No synthetic Stage 8 test was run**, no TShark packet read executed in this attempt, and there is neither a Stage 8 PASS nor a Stage 8 RED assertion.

**Diagnosis:** The Stage 8 test parameter is confirmed present in the feature-branch \`scripts/verify-dns-wire-source-contract.ps1\` GitHub blob 9c9c3fbce2e296d23fed98967b68e5ecc87d223b, committed before checkpoint **04200b2**. The owner's transcript includes no preceding git pull or rev-parse output for this invocation. The most recent **owner-confirmed** local checkout SHA in the supplied conversation is e412c2a, predating Stage 8's new opt-in flag. A stale local checkout is therefore the strongly supported explanation; the exact current checkout SHA is **not reported**. This was an omitted update instruction in the assistant's previous test command, not evidence of a TShark or DNS decoder defect.

**Correct recovery:** Fast-forward the existing feature branch with \`git pull --ff-only origin feature/carthago-reliability-hardening\`, print \`git rev-parse --short HEAD\`, and confirm \`IncludeReplayCompatibility\` is present locally with \`Select-String -LiteralPath .\scripts\verify-dns-wire-source-contract.ps1 -Pattern 'IncludeReplayCompatibility'\`. Then Windows PowerShell Parser.ParseFile both \`scripts/HoldoutV2WireReplayBridge.psm1\` and \`scripts/verify-dns-wire-source-contract.ps1\`; only with both syntax checks clean, rerun the single already-owner-authorized synthetic opt-in Stage 8 command with \`-NonInteractive\`, \`-IncludeReplayCompatibility\`, \`-AuthorizedTestTime\`. Stop and report any subsequent fixed-code failure; no unreviewed test bypasses.

**Preserved:** No implementation files changed to respond to this checkout mismatch. Stage 8 source implemented but runtime NOT RUN. Previous core DNS + optional V2 original-frame/provenance and Stage 6D–6H GREEN unchanged. V1 frozen FAILED 4/6, V2 PENDING_EXTERNAL_CAPTURE_AND_REVIEW 0/4 approved; all thresholds, private untracked evidence, publication, freeze and external-source admission remain untouched.


### 2026-10-30 — Stage 8 Windows syntax preflight RED at 683da2e; corrected typed foreach in synthetic fixture (runtime still NOT RUN)

**Owner-observed checkout and preflight:** User ran \`git pull --ff-only origin feature/carthago-reliability-hardening\`, which returned \`Already up to date\`; \`git rev-parse --short HEAD\` returned **683da2e**. Select-String confirmed \`IncludeReplayCompatibility\` exists at script lines 11, 16 and 570. Windows PowerShell Parser.ParseFile reported **Syntax PASS** for \`scripts/HoldoutV2WireReplayBridge.psm1\` but **Syntax failure** for \`scripts/verify-dns-wire-source-contract.ps1\`. The owner's throw did not print the contents of \`$parseErrors\`, so the exact Windows parser diagnostic/line number remains **unobserved**. The test correctly did NOT run; no Stage 8 positive or negative cases executed, and no TShark data or original PCAP was read.

**Exact source-level defect identified:** In the recently added Stage 8 synthetic fixture \`New-BridgeDnsQuery\`, the test script declared \`foreach([byte[]]$bytes in $labels) { ... }\`. PowerShell \`foreach\` statement syntax requires an untyped iteration variable; the type annotation in this position is invalid syntax. This is an independently observed source defect and a strong explanation for Parser.ParseFile failing. The script was mistakenly described as source-reviewed before this actual Windows syntax gate, and the owner correctly stopped as directed. No separate Windows parse output with the diagnostic was provided; root-cause verification requires the next parse run.

**Correction commit 0606577, test-only:** Replace the invalid loop declaration with \`foreach($labelBytes in $labels) { [byte[]]$bytes=$labelBytes; ... }\`. Preserve the existing typed \`List[byte[]]\` container and the exact \`$msg.Add([byte]$bytes.Length)\` / \`$msg.AddRange($bytes)\` byte-writing semantics. No test vector, PCAP frame, private bridge API, existing DNS or V2 test, module export, publisher, importer, auditor, active runtime or privacy gate was changed. Source readback confirms the invalid \`foreach([byte[]]\` occurrence is absent.

**Next owner-only validation:** Fast-forward branch to latest ledger checkpoint, confirm SHA and rerun Parser.ParseFile on both \`scripts/HoldoutV2WireReplayBridge.psm1\` and \`scripts/verify-dns-wire-source-contract.ps1\`. IMPORTANT: print \`$parseErrors | Select-Object Message,Extent\` or equivalent location (line and column) **before** throwing, so any additional syntax defect is attributable without guesswork. Do NOT execute the opt-in test if either parser reports errors. Once both report zero errors, the already-authorized synthetic-only gate is:
\`powershell.exe -NoProfile -NonInteractive -File .\scripts\verify-dns-wire-source-contract.ps1 -TsharkPath "C:\Program Files\Wireshark\tshark.exe" -IncludeReplayCompatibility -AuthorizedTestTime\`
Stop on any runtime code; do not bypass source-binding, privacy or lossless-label checks. Any control result remains synthetic-only and cannot approve or publish real external evidence.

**Disposition:** Stage 8 bridge module parser GREEN at 683da2e; Stage 8 expanded test-script parser **RED at 683da2e**, patch **source committed** at 0606577, Windows parse of corrected code **PENDING**, runtime Stage 8 **NOT RUN**. Previous core DNS and optional V2 provenance synthetic gates GREEN at e412c2a. Historical V1 FAILED 4/6 and V2 PENDING_EXTERNAL_CAPTURE_AND_REVIEW 0/4 approved; Stage 6D–6H and all private evidence preserved. Only the test file and this central ledger changed.
