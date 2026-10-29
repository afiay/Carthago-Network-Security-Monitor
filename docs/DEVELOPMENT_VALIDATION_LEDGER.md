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
