# Carthago Development and Deferred Validation Ledger

**Current execution policy (2026-10-30):** Individual GA validation checks have already
been owner-authorized, run on CARTHAGE and recorded GREEN where stated below.
**New or repeated** builds, .NET/xUnit, benchmarks, replay, capture/source
checks and GitHub Actions jobs remain **manual and separately owner-authorized**.
The presence of a test script or manual workflow is not permission to run it.
A previous successful synthetic check does not certify a different code SHA,
real evidence admission or production readiness.

**Development track:** Complete the R102 binary-DNS wire-name and original
capture provenance foundation **before** expanding the remaining detector
rules. Keep the single existing branch
`feature/carthago-reliability-hardening`. Preserve the frozen V1 failure,
all R102 thresholds/confidence weights and benign controls, and V2
`PENDING_EXTERNAL_CAPTURE_AND_REVIEW` until separate authorization.

This is the **central GA ledger**, not a replacement for detailed design,
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

## Current GA verification snapshot — 2026-10-30

This section is the **current status**. Later dated entries below are an
append-only audit trail of what was known **at that earlier time**.
Historical statements such as "PARKED", "module missing", "RED" and
"NOT RUN" must not be read as today's status unless the current table
independently confirms them. Original source/test SHAs are retained.

| GA / validation area | Current verified result | Owner-tested SHA | Boundary |
| --- | --- | --- | --- |
| GA 6D — private V2 provenance | **GREEN 26/26**: 2 pending-only positives + 24 strict negatives | `3ae94ba` | Metadata syntax, not original source rights or labels |
| GA 6E — private atomic publication | **GREEN 18/18** synthetic publish/fault cases | `c5174da` | Synthetic private filesystem, not crash durability |
| GA 6F — recovery and writers | **GREEN 15/15** recovery + **3/3** two-writer contention | `1ab3290`, `adf421f` | Non-destructive advisory recovery; bounded contention |
| GA 6H — reader negative sensitivity | **GREEN 6/6** deliberately invalid synthetic final states | `8882f1c` | Detectability of known partial/malformed snapshots |
| GA 6G — writer/reader visibility | **GREEN 3/6/12** bounded separate-process rounds | `566f746` (12 max) | Sampled absent/complete snapshots, not linearizability |
| GA 7 — binary DNS/TShark and V2 source binding | **GREEN**: TCP/UDP/JSON raw; 4 source-bound questions/5 invalid; 2 bound records/19 tamper cases; 7 review scenarios | `e412c2a` | Entirely synthetic PCAP; no independent source approved |
| GA 8 — read-only replay compatibility | **GREEN**: 2 printable names/10 nonlossless negatives, 3 bound records/11 rejection cases | `9f709d0` | No projected sample, publication, freeze or approval |

**Still not verified or authorized by these passes:** GA 1–4 compiler-guarded
code-path contracts and untested rule batches; the separate legacy R102
importer/auditor-enforcement harness; the versioned migration to the existing
11-field publisher/replay/evaluator; complete current-revision xUnit and
application replay certification; real-field R102 precision, recall and F1;
cross-machine power-loss durability and adversarial ACL/reparse-point races.
The existing manual CI profiles were **not** dispatched merely because
their corresponding locally executed tests passed.

**Immutable evaluation state:** V1 frozen holdout **FAILED 4/6**; V2
`PENDING_EXTERNAL_CAPTURE_AND_REVIEW` with **0/4 externally approved R102
sources**. Preserve R102/R118/R163 floors 80%/86%/84%, R102 external
candidate 0.75 threshold, Shadow/Disabled, cooldowns, baseline readiness,
privacy, journal integrity and all original private/ignored evidence.

**Terminology:** New current-status documentation uses **GA**.
Historic filenames, source-code symbols, Git commit references and quoted
earlier records remain unchanged to protect navigation and audit history.

---

## Original 2026-10-29 design and execution plan — historical snapshot

The following matrix records the **initial parked plan**, not a live status
dashboard. Its initial RED/NOT RUN observations must be interpreted using
the current GA verification table and later owner-tested ledger entries.
Some still-pending compiler-guarded or CI-specific items remain pending.

## Evidence and decisions at the original planning checkpoint — 2026-10-29

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


### 2026-10-30 — Stage 8 owner Windows test GREEN: source-bound read-only wire-to-legacy compatibility verified

**Exact checkout and preflight observed:** Owner fast-forwarded the existing feature branch from **683da2e** to **9f709d0**. Windows PowerShell \`Parser.ParseFile\` checked both \`scripts/HoldoutV2WireReplayBridge.psm1\` and \`scripts/verify-dns-wire-source-contract.ps1\`: **Syntax PASS** for each. The previously invalid \`foreach([byte[]]$bytes in $labels)\` declaration was therefore corrected successfully. The owner then ran the explicitly authorized local synthetic test, without invoking private original source evidence:
\`\`\`powershell
powershell.exe -NoProfile -NonInteractive -File .\scripts\verify-dns-wire-source-contract.ps1 -TsharkPath "C:\Program Files\Wireshark\tshark.exe" -IncludeReplayCompatibility -AuthorizedTestTime
\`\`\`
The command completed and returned to the PowerShell prompt with no exception, no interactive prompt and no approval action. The test was executed on owner-controlled Windows and installed TShark, not on the assistant's environment.

**Complete owner-observed successful output:**
\`\`\`text
DNS TCP framing: unmodified UDP and exact TCP payload preserved; five invalid length prefixes rejected.
TShark jsonraw descriptor: 5/6-member formats preserved; ten ambiguous or invalid descriptors rejected.
DNS wire source contract: four source-bound questions corroborated; five invalid/ambiguous selections rejected. Synthetic evidence only.
V2 wire replay bridge: two exact printable names accepted; ten non-lossless names rejected.
V2 wire replay bridge: three original frame/question records bound; eleven source, schema, binary and review-state negatives rejected; no projected samples or approvals.
\`\`\`

**Interpretation and acceptance boundaries:**
1. The three existing synthetic core DNS/TShark contracts repeated GREEN. The new bridge-gated helper verified two byte-identical lower-case printable names and rejected ten unrepresentable/nonnormalizable label encodings, including invalid Base64, embedded dot, uppercase, non-ASCII, NUL and boundary violations.
2. The new synthetic-PCAP wire-to-legacy compatibility extension positively bound three original frame/question selections (including UDP and TCP) via the existing DNS source binder. Eleven negative cases were rejected, including forged review/encoding/schema state, tampered label or frame identity, missing original capture, incompatible root, cardinality mismatch and independently source-bound binary name ineligible for legacy printable text.
3. A passed bridge returns **only** a pending-review, metadata-only status: no legacy sample is produced; it never publishes, freezes or approves any fixture or real source. The third original binary-label case verifies that source authenticity does NOT make lossy serialization acceptable. The new test did not invoke the existing legacy importer, auditor, publisher, freeze mechanism or evaluator.
4. Stage 8's declared read-only compatibility goal is **CLOSED GREEN within exactly this synthetic scope** at owner test SHA **9f709d0**. The previous parser-RED transcript and correction are retained above, not overwritten. No previously GREEN Stage 6D–6H concurrency tests are rerun or reclassified.
5. This is NOT proof that the original R102 importer/auditor now accept canonical labels-base64-v1, nor that a production replay/evaluation consumer is byte-lossless. The user has not authorized real PCAP imports, third-party datasets, external capture-label approval or publication.

**Next engineering milestone, source-only until a distinct owner test window:** Design and implement an **explicitly versioned, private, non-publishing sample adapter** for the already-proven printable-ASCII subset, while retaining mandatory original PCAP SHA/frame/question/binary labels in separately scoped private evidence. The adapter must not infer original bytes from old lowercased \`dnsQname\` or mix nine-field wire records directly into eleven-field legacy publisher input. After adapter tests and rights/privacy/source checks, selectively migrate the producer/auditor; run separate tests before evolving existing publisher/recovery/benchmark consumers. Preserve old frozen V1 FAILED 4/6, V2 pending/0-of-4 approvals and confidence floors R102 80%, R118 86%, R163 84%, external R102 0.75, plus Shadow/Disabled, cooldown, baseline, privacy and journal controls.

**Repository change in response to this owner test:** Ledger-only: scripts and existing test fixtures are NOT modified, no new test is executed by the assistant.


### 2026-10-30 — Documentation-status reconciliation: confirmed GAs no longer labeled unexecuted

**Scope:** Documentation-only review requested by the project owner. Reconciled the README and the original GA 6D–6H and GA 7 design/status pages against the independently recorded CARTHAGE Windows transcripts, while preserving historical filename/commit identifiers. Added this ledger's prominent **Current GA verification snapshot** and distinguished the original dated plans from present status. The genuine legacy auditor-enforcement contract remains explicitly **PENDING**; read-only GA 8 source compatibility remains distinct from a production importer/auditor/publisher migration.

**Current confirmed results presented consistently:** GA 6D strict private provenance 26/26 at 3ae94ba; GA 6E atomic single-writer publisher 18/18 at c5174da; GA 6F path-free recovery 15/15 at 1ab3290 and two-writer contention 3/3 at adf421f; GA 6H reader-negative 6/6 at 8882f1c; GA 6G three/six/twelve sampled reader rounds GREEN, maximum at 566f746; GA 7 synthetic DNS/TShark and optional frame/question tamper/source-risk corroboration at e412c2a; GA 8 read-only compatibility at 9f709d0. All status labels describe the specific synthetic validation boundary, not source authorization or deployment readiness.

**Documents reconciled:** README.md; docs/DEVELOPMENT_VALIDATION_LEDGER.md; docs/STAGE6D_PRIVATE_PROVENANCE_SCHEMA_AND_ATOMICITY_20261029.md; docs/STAGE6E_ATOMIC_V2_PUBLICATION_FAULT_CONTRACT_20261029.md; docs/STAGE6F_CONCURRENT_V2_PUBLICATION_AND_RECOVERY_20261029.md; docs/STAGE6G_CONCURRENT_READER_VISIBILITY_20261029.md; docs/STAGE6H_DETERMINISTIC_READER_NEGATIVE_CONTROLS_20261029.md; docs/STAGE7_V2_SOURCE_MODULE_IMPLEMENTATION_20261029.md; docs/STAGE6_V2_AUDITOR_ENFORCEMENT_CONTRACT_20261029.md.

**Deliberately preserved historical record:** Earlier "PARKED", missing-module, syntax failure, failed test and RED/NOT RUN entries in this chronological ledger are retained as dated observations rather than rewritten or deleted. Older markdown filenames are unchanged so links, commit history and existing references remain navigable; new user-facing current-status terminology is **GA**. No source tests were executed during this cleanup and no code or data was migrated.

**Verified repository scope:** Readback confirms unchanged blobs for scripts/DnsWirePcap.psm1 (7b04363625ed5e033e79478cb16762922b680568), scripts/HoldoutV2Provenance.psm1 (b30abb5ff63e21ff79263366be5aebe2e4df7f60), scripts/HoldoutV2CandidatePublisher.psm1 (344a207f16e09790157628ce580cc4044593df99), scripts/HoldoutV2WireReplayBridge.psm1 (7cf84da3d5d9f53caf21ae508e1e103ee85b53f1), scripts/verify-dns-wire-source-contract.ps1 (d2412849463adec5c70cfd93e254376dc4607c3f), and original legacy importer/auditor. V2 manifest unchanged. No original PCAPs, ignored build-verify files, workflows or user-owned source evidence touched.

**Still open:** Legacy importer/auditor enforcement test, full versioned producer/publisher/evaluator cutover and all external R102 capture rights and independent labels; V2 0/4 approved and PENDING_EXTERNAL_CAPTURE_AND_REVIEW; immutable V1 FAILED 4/6. Full integration xUnit/replay/performance and R102 field metrics, real Windows crash/power-loss resilience, arbitrary ACL/rename attack classes and production acceptance cannot be inferred from the synthetic GA passes. Existing confidence floors, privacy, cooldowns, baseline and journal controls remain unchanged.


### 2026-11-02 — Owner Windows full solution regression: 9,691 passed, 42 failed; remediation unverified

**Owner-observed test checkpoint:** On Windows, after fast-forwarding the existing `feature/carthago-reliability-hardening` branch to `4dc058b6142606b249cceef369095d72013b02a4`, the owner ran `dotnet build -c Release` successfully for Carthago, Carthago.Benchmarks and Carthago.Tests (10 distinct build warnings). The owner then ran `dotnet test Carthago.Tests/Carthago.Tests.csproj -c Release --no-build --logger "trx;LogFileName=full-test.trx" --results-directory build-verify`. **Observed 9,733 total, 9,691 passed, 42 failed, zero skipped**. This is an executed RED regression checkpoint, not release verification or permission to publish/promote rules.

**Failure families and source remediations committed on the same branch after the RED run (all SOURCE CANDIDATE — UNVERIFIED until next owner execution):** Replace obsolete 544-core/954-available catalog assertions with dynamic current-registry counts (559 core and 410 additional content-pack registrations at the observed checkpoint), while retaining ordered core IDs and independent content-pack cardinality. Harmonize the R516 Cloudflare Tunnel no-match reason with the existing authenticated-session-provenance boundary, retaining fail-closed logic. Extend R381–R390 cloud-provider host privacy redaction to legacy and structured evidence. Update R551/R559 cooldown tests to assert suppressed matches, which have `Matched=true`, `Suppressed=true`, and zero emitted events. Use `HttpLight`-parsed token attribution in R359/R365 positive test fixtures rather than untrusted strings; parser recognition remains a required test gate. Preserve missing `Payload` telemetry as an explicit central precision-validation block for R553/R555/R556 instead of falsely authorizing alerts. Preserve R485's `BACNET_WRITEPROPERTY_CONFIRMED_REQUEST_UNAVAILABLE` block: the supplied BACnet replay Info text cannot attest a confirmed decoded WriteProperty APDU. Its malicious positive remains in replay labels and is still counted as a detector miss, not a fabricated true positive. Changes include test-contract files, R516 rule, and shared CloudDev evidence redaction; no frozen-holdout files or confidence floors were altered.

**Residual risks and next GA:** No post-remediation Windows build/xUnit, replay, independent capture, detection-quality or holdout test was run by the assistant. The 10 compiler/analyzer warnings remain. The test log also contained `LocalStore` disposal messages involving `ReaderWriterLockSlim`, requiring dedicated isolation before calling them a production defect. Runtime producer provenance for R485 and independent payload admission for R553/R555/R556 remain open. On the next owner-authorized window, record the exact new HEAD, run the full Release build and xUnit suite with TRX, inspect all failures and then separately evaluate detection-quality replay, source provenance and Holdout V2. Preserve frozen V1 FAILED 4/6, V2 PENDING_EXTERNAL_CAPTURE_AND_REVIEW/0 approved, Shadow candidate modes, journal/approval policy, and R102 80% / R118 86% / R163 84% floors. The previous 42-test RED checkpoint remains immutable historical evidence.


### 2026-11-02 — Owner Windows full regression retry: 9,730/9,733 passed at 6f701a3; R516 corrections pending

**Exact owner-tested commit:** `6f701a3960f11d8ad7507447784c016c1de635e9` on existing `feature/carthago-reliability-hardening`; clean working tree and fast-forward pull observed before test. The owner ran `dotnet build -c Release` and `dotnet test Carthago.Tests/Carthago.Tests.csproj -c Release --no-build --logger "trx;LogFileName=full-test.trx" --results-directory build-verify`. Build succeeded, with 17 warning occurrences reported (some duplicate across WPF temporary and normal build targets); owner-observed xUnit summary: **9,733 total, 9,730 passed, 3 failed, zero skipped**. This is a RED test checkpoint and confirms 39 fewer failing cases than the prior 42-failure checkpoint. No additional full test was run by the assistant.

**Remaining three test failures:** Two `NetworkBatch511520AccuracyTests` parameterized variants for R516 (`missing-source`, `missing-destination`) expected `MISSING_CORE_TELEMETRY` but received `CLOUDFLARED_TUNNEL_SESSION_PROVENANCE_UNAVAILABLE`. The third, `TuningBenchmarkTests.Evidence_Rich_Replays_Match_Their_Specific_Rules`, expected `cloudflared-tunnel` to match R516 even though the rule's separately documented trusted session provenance producer is unavailable. These are contract inconsistencies, not grounds to infer an authenticated Cloudflare Tunnel.

**Source-only corrections after this RED checkpoint, NOT EXECUTED:** `4b8551aa85fbc3bfb3b15b336e58e8f554f0f833` prioritizes missing source/destination telemetry in the existing R516 rule with `MISSING_CORE_TELEMETRY` before any tunnel corroboration check. `564ecc6e369362f733caf0f247eee26ae994aa2f` preserves the malicious `cloudflared-tunnel` replay's positive label, but explicitly expects `R516` to be absent from actual matches and present in missing-positive/diagnostic metrics with `CLOUDFLARED_TUNNEL_SESSION_PROVENANCE_UNAVAILABLE`. No benchmark labels, replay inputs, detection-quality counters, other rule implementation, telemetry producer, confidence floor, Shadow/Disabled policy, privacy controls, or frozen R102 holdouts were changed. **SOURCE CANDIDATE — UNVERIFIED:** next owner-authorized full Release build and xUnit run must verify these two source edits; a green xUnit suite would not certify R516 positive detection or production suitability.

**Other observations outside the three xUnit failures:** The owner log includes `LocalStore` attempts after a `ReaderWriterLockSlim` was disposed and an intentionally malformed incident-feedback JSON read; determine whether these are isolated negative-test diagnostics before calling them live failures. Previous 7 app-source and 3 test/analyzer warning locations remain to be reviewed. Historical V1 FAILED 4/6, V2 PENDING_EXTERNAL_CAPTURE_AND_REVIEW/0 approved and R102/R118/R163 floors remain unchanged.


### 2026-11-02 — Owner Windows regression retry: 9,732 passed / 1 failed at 11fa81f; R508/R437 benchmark correction pending

**Owner-observed exact checkpoint:** `11fa81f6d52f50ee752d42590151c8f4ce44f0f2` on `feature/carthago-reliability-hardening`. The owner executed the full `dotnet build -c Release` and `dotnet test Carthago.Tests/Carthago.Tests.csproj -c Release --no-build --logger "trx;LogFileName=full-test.trx" --results-directory build-verify` on Windows. All three projects compiled, with 17 reported warning occurrences. The owner-observed xUnit result was **9,733 executed, 9,732 passed, 1 failed, 0 skipped**. This is another RED checkpoint, not a release acceptance or evidence-proven detector certification.

**Last failed test:** `TuningBenchmarkTests.Evidence_Rich_Replays_Match_Their_Specific_Rules` expected the malicious-labeled `rclone-exfil` fixture to generate an R508 match, but actual R508 rejected the untrusted process name / client-supplied User-Agent and lacked independently attributed outbound transfer proof. The actual diagnostic was `RCLONE_PROCESS_USERAGENT_AND_EGRESS_PROVENANCE_UNAVAILABLE`. A same-file static audit also identified `redis-config-set` R437 as a subsequent definite mismatch: its request is only an `Info` string and port without parser-attributed Redis RESP CONFIG SET arguments, and `ServiceExposureEvidenceBoundary` returns `REDIS_RESP_CONFIG_SET_UNAVAILABLE`. Neither missing producer is implemented by this test correction.

**Source-only correction (NOT EXECUTED):** Commit `fb9bbd5575703d21dc0ed59d384da86197ac9db4` edits only `Carthago.Tests/TuningBenchmarkTests.cs` to require positive recognition only for the existing supported Modbus R240 and metadata R163 samples, while requiring the original malicious `rclone-exfil` R508 and `redis-config-set` R437 positive labels to remain in `ExpectedMatches` and `MissingExpectedMatches` and verifying their explicit missing-producer reason codes. Existing replay JSON, labels, summary/coverage counts, live rules, consumer, confidence floors, Shadow/Disabled rules, cooldowns, privacy, journal, Holdout V1 and V2 were not modified. This avoids conflating a green xUnit assertion with true-positive recognition. The independent replay detection-quality gate must still report these missed expectations and remains open.

**Non-xUnit observations:** Owner logs again showed `LocalStore` writes after disposed `ReaderWriterLockSlim`, a LiteDB discarded-page writeability error on disposal, a 403 for `PortServiceResolver` background refresh, and incident-feedback malformed JSON fallback. They did not appear among the sole reported xUnit failures but require isolated lifecycle, network-policy and storage-integrity diagnostics before production readiness. No such probes, full tests, Windows runtime tests, or source/external holdout operations were executed by the assistant. The seven app-source nullable warnings and three distinct test/analyzer warnings remain. Preserve frozen V1 FAILED 4/6, V2 PENDING_EXTERNAL_CAPTURE_AND_REVIEW / 0 approved, R102/R118/R163 confidence floors 80%/86%/84% and existing candidate policies.


### 2026-11-02 — Owner Windows full Release/xUnit GREEN: 9,759/9,759 at 18ce34b

**Exact owner-executed checkout:** `18ce34ba86b8f3561ea4dcf36d58f41e281a97d0`, existing `feature/carthago-reliability-hardening`; the owner observed clean `git status --short`, a fast-forward pull `11fa81f..18ce34b`, and recorded `git rev-parse HEAD`. The pulled tree included new **R560** rule/accuracy tests and the R508/R437 replay-expectation correction. **Windows build:** `dotnet build -c Release` succeeded for Carthago, Carthago.Benchmarks and Carthago.Tests (17 warning occurrences, including 7 app warnings printed in the WPF temporary build and again in the app build, plus 3 test/analyzer warnings). This is an observed successful compilation checkpoint, not zero-warning status.

**Owner-executed tests at the same exact commit:**
- Targeted `dotnet test Carthago.Tests/Carthago.Tests.csproj -c Release --no-build --filter "FullyQualifiedName~Evidence_Rich_Replays_Match_Their_Specific_Rules" --logger "trx;LogFileName=benchmark-recheck.trx" --results-directory build-verify`: **1/1 PASS**, 0 failed, 0 skipped.
- Full `dotnet test Carthago.Tests/Carthago.Tests.csproj -c Release --no-build --logger "trx;LogFileName=full-test.trx" --results-directory build-verify`: **9,759/9,759 PASS**, 0 failed, 0 skipped; owner console reports 61.8s test duration and 62.6s test command duration. The test runner overwrote the previous `build-verify/full-test.trx`; that file is the owner-local evidence artifact. No original frozen holdout or production source-capture operation was executed.

**GA disposition:** **GREEN for this exact-commit .NET Release compilation, the targeted benchmark assertion, and the full synthetic/unit/integration xUnit regression suite only.** Historical earlier RED checkpoints (42, then 3, then 1 failing xUnit cases) are retained. A green suite does **not** mean the benchmark's malicious-labeled R437/R485/R508/R516 positive expectations were recognized; their missing authenticated producers remain expressly recorded by the replay coverage/diagnostic contracts. R553/R555/R556 central `Payload` precision-policy gaps remain visible; no candidate was promoted to Alert and no confidence, sensor, replay labeling, scoring, holdout, or risk controls were lowered.

**Open reliability diagnostics (observed during GREEN xUnit, not asserted production defects):** `LocalStore` writes attempted with disposed `System.Threading.ReaderWriterLockSlim`, `IncidentFeedbackStore` fell back after malformed JSON, `PortServiceResolver` background refresh returned HTTP 403, and `SinkManager` logged an intentional-looking failing-sink error. Isolate test fixtures/disposal paths and verify negative-test intent before attributing these to real runtime. Review seven distinct app nullable warnings and three test/analyzer warnings (the build output totals 17 warning occurrences). Continue with independent detection-quality replay metrics, packet-producer provenance, journaling/incident persistence stress, resilience and original-source Holdout V2 eligibility under their own separately authorized gates. Frozen V1 remains FAILED 4/6 and immutable; V2 remains PENDING_EXTERNAL_CAPTURE_AND_REVIEW/0 approvals. Confidence floors R102 80%, R118 86%, R163 84% unchanged.

**Recording action:** Documentation-only ledger append after the owner-run transcript; no additional `dotnet`, replay, benchmark, CI, Windows runner or holdout tests were executed by the assistant. Future commits on this active automation branch are separately **CANDIDATE — UNVERIFIED** until tested by exact SHA.


### 2026-11-02 — GA runtime reliability: LocalStore disposal gate and compiler-warning hardening (source candidate)

**Baseline:** The owner executed `dotnet build -c Release` and the full `Carthago.Tests` xUnit suite on the existing `feature/carthago-reliability-hardening` branch at exact SHA `18ce34ba86b8f3561ea4dcf36d58f41e281a97d0`: successful build and **9,759 / 9,759 PASS**, zero failing or skipped (owner Windows transcript). This is the only certified green commit for this report; all subsequent source edits in this GA remain **SOURCE CANDIDATE — UNVERIFIED**. The original frozen holdout and independent detection-quality acceptance criteria are unchanged.

**Source audit of logged storage diagnostics:** `Carthago.Tests/AnalyticsPipelineTests.cs` deliberately closes `LocalStore` and calls `SaveIncident`/`SaveBaselineSnapshots` to assert failure signaling; a separate test closes the store before invoking an analytics host status update and verifies its persistence-failure counter. Therefore the observed post-disposal `ReaderWriterLockSlim` log lines can arise from expected negative-test fixtures; they are not by themselves evidence of a live production race. The old `LocalStore` allowed concurrent DB operations and `Dispose` without an instance gate.

**Implementation (not executed):** In `Carthago/Analytics/Services/LocalStore.cs`, added an instance-level `_dbGate` to serialize all ten public database operation methods with idempotent `Dispose()`. A disposed store returns empty results for read methods, false for bool persistence methods, and no-ops for legacy void methods without reentering disposed LiteDB state. Successful acknowledgements cannot race a `Dispose` within the same store instance. No retry, silent success, database deletion, journal bypass, or cross-instance/proc transaction is introduced. Source commit `06a42abe928c46c0af8a3ff35a2669c711b58f4f`.

**Authored validation only:** Added `Carthago.Tests/LocalStoreLifecycleTests.cs` with 3 xUnit `Fact` methods for idempotent/post-close behavior and concurrent incident/baseline writes racing disposal; the latter reopen the DB to compare every acknowledged ID to persisted records. Source commit `95850e5b92421831617f09b13b40f9674348c8fc`. **Zero new tests executed by assistant.** These tests do not prove multi-process durability or power-loss atomicity; those remain separate goals.

**Explicit nullability hardening (not executed):** R075 canonical typed WMI/DCOM key (avoid null dereference); R055 tests `LastThreatFeedUpdateUtc.HasValue` before formatting; R190 requires typed DNS TTL before numerical comparison; `SensitiveTelemetryContracts` compares a validated local Host snapshot; `NetworkBatch266270Evidence` requires both parsed IP endpoints and returns false for absent DNS response code. Test-only member data now uses `object?[]` for nullable parameters; `SyntheticHoldoutContractTests` replaces a boolean path-prefix assertion with equivalent `Assert.StartsWith` (no frozen holdout data changes). Source changed on the same branch via individual narrow commits; confidence floors, candidate policies, detection requirements, and R102 frozen V1/V2 evidence unchanged. Build warnings were 17 reported occurrences (7 distinct app locations repeated during temporary WPF build and 3 test/analyzer locations). **No claim of zero warnings until next owner build.**

**Port intelligence review:** `PortRefreshRetryPolicy` already treats HTTP 403 as non-retryable, with 24-hour cooldown; at most 3 attempts for retryable errors. Port lookups retain the deterministic hardcoded/heuristic fallback. No port-resolver code change was justified by a single recorded 403. Check data-source access separately if persistent.

**Next separately authorized GA:** Record current exact HEAD after clean fast-forward, build Release, run `LocalStoreLifecycleTests` and existing `AnalyticsPipelineTests` first, then full `Carthago.Tests` suite and TRX. Inspect persistent storage after concurrent disposal, verify no compiler/analyzer regressions, and retain the previous owner-green `18ce34b` checkpoint as the baseline if the next branch HEAD fails. Distinguish normal negative-test sink, feedback, or storage error logs from operational failures. Remain on the sole existing `feature/carthago-reliability-hardening` branch. Frozen V1 FAILED 4/6 remains untouched; V2 pending/0 approvals, and R102/R118/R163 minimum confidence 80%/86%/84% remain unchanged.


### 2026-11-02 — Owner Windows GA runtime reliability GREEN: 9,762/9,762 at 6ccb316; four test warnings follow-up

**Exact owner-verified SHA:** `6ccb316a95e9843ddfd68996f59c076e2f3c093c` on `feature/carthago-reliability-hardening`. The owner started from a clean working tree, fast-forwarded `18ce34b..6ccb316` and recorded `git rev-parse HEAD`. **Release build GREEN:** `dotnet build -c Release` succeeded for Carthago, Carthago.Benchmarks and Carthago.Tests in 56.4s; no application/benchmark warnings. Four xUnit1031 warnings, all from blocking `Task.Result` access in the newly authored concurrent `LocalStoreLifecycleTests.cs`, remained in the test project.

**Owner-executed evidence:**
- `dotnet test Carthago.Tests/Carthago.Tests.csproj -c Release --no-build --filter "FullyQualifiedName~LocalStoreLifecycleTests|FullyQualifiedName~AnalyticsPipelineTests" --logger "trx;LogFileName=storage-recheck.trx" --results-directory build-verify`: **49/49 PASS; 0 failed; 0 skipped; 9.2s**.
- `dotnet test Carthago.Tests/Carthago.Tests.csproj -c Release --no-build --logger "trx;LogFileName=full-test.trx" --results-directory build-verify`: **9,762/9,762 PASS; 0 failed; 0 skipped; 62.7s**. Exact owner-local TRX files under `build-verify`; full-test.trx overwritten from the previous run. The added three LocalStore tests were executed and are part of the expanded 9,762 total.

**Validated boundary:** The same-instance `LocalStore` lock/disposal gate, idempotent post-close behavior, and acknowledged persisted incident/baseline operations pass their authored unit/concurrency tests at this SHA. This does not demonstrate crash/power-loss durability, cross-process LiteDB transactions, full GUI capture, endpoint installation, or production readiness. The seven distinct prior app nullability warning locations no longer emitted build warnings at this SHA. No frozen holdout tests, production original capture review, or independent detection-quality recall benchmark were executed by the assistant.

**Observed diagnostics, scoped to tests:** `PortServiceResolver` fetched IANA data and received HTTP 403; `PortRefreshRetryPolicyTests` already assert 403 is non-retryable with a 24-hour cooldown. `AnalyticsPipelineTests.CorruptFeedbackStore_Does_Not_Crash` deliberately writes `{ definitely-not-json` and verifies empty fallback, accounting for malformed-feedback log output. `SinkManager` logged `FailingSink failed: sink failure`; investigate intent in sink-specific negative tests if operational issues occur. No `LocalStore` disposed-lock errors appeared in this owner's latest full regression console, consistent with the new lifecycle gate, but absence of those messages is not conclusive runtime race proof.

**Follow-up source only — SOURCE CANDIDATE, UNVERIFIED:** After this owner-green SHA, `Carthago.Tests/LocalStoreLifecycleTests.cs` was edited in commit `82a089e0e5841595a2bd4b0b528dd2c68a111448` to use the array returned from `await Task.WhenAll(writers)` rather than blocking on each completed task's `.Result`; its existing recognized/persisted set assertions and count remain. The four xUnit1031 warning corrections have **NOT** been rebuilt or retested. Record a new exact-HEAD owner build and targeted/full xUnit verification before claiming warning-free status. Keep prior 9,762 GREEN at 6ccb316 immutable. Frozen holdout V1 FAILED 4/6 remains untouched, V2 PENDING_EXTERNAL_CAPTURE_AND_REVIEW/0 approvals, R102/R118/R163 confidence floors 80%/86%/84% remain unchanged.

**Subsequent GA priorities:** Resolve reliability of the optional IANA refresh source without loosening retry/cooldown or changing the source silently; expand explicit isolated storage shutdown/incident durability investigations only if a production symptom arises; assess R437/R485/R508/R516 missed-positive replays under the separate detection-quality gate. The running rule/UI automation may advance branch HEAD; later commits are separately unverified until exact SHA is tested.


### 2026-11-02 — Owner Windows zero-warning full regression GREEN at e73650f: 9,762/9,762

**Exact owner-tested branch/SHA:** `feature/carthago-reliability-hardening` at `e73650fc594179d6c7c1db5d5b933a8eff4bd082`. Owner verified clean `git status --porcelain`, fast-forward `6ccb316..e73650f`, and printed `git rev-parse HEAD` before and after execution. Pull changed only `Carthago.Tests/LocalStoreLifecycleTests.cs` and this validation ledger. The new asynchronous concurrency assertions introduced in `82a089e0e5841595a2bd4b0b528dd2c68a111448` are now included in this owner-run.

**GREEN executed on Windows at that exact SHA:** `dotnet build -c Release` returned successful Carthago, Carthago.Benchmarks and Carthago.Tests builds in **16.1s with zero reported build or analyzer warnings**. `dotnet test Carthago.Tests/Carthago.Tests.csproj -c Release --no-build --logger "trx;LogFileName=full-test.trx" --results-directory build-verify` completed with **9,762 tests, 9,762 passed, 0 failed, 0 skipped**, 59.8s test duration (60.4s command). Results saved to owner-local `build-verify/full-test.trx`, overwriting the prior file. This verifies the previous four xUnit1031 analyzer warning corrections, the existing LocalStore concurrency regression, and the full suite at this SHA. The historical 9,762/9,762 at `6ccb316` with four test warnings remains accurately recorded above.

**Diagnostic interpretation and limits:** `AnalyticsPipelineTests.CorruptFeedbackStore_Does_Not_Crash` intentionally writes malformed feedback JSON and asserts empty fallback; that can account for the emitted IncidentFeedbackStore parsing diagnostic. The test console also logged `[SinkManager] FailingSink failed: sink failure`, a synthetic DNS R006 alert, and temporary RuleEngine configuration loads; these did not fail the suite, but console output is not itself a production-system certification. No disposed-LiteDB-lock errors and no IANA 403 appeared in this run's console; their earlier observations remain historically recorded and the absence of log lines in one run does not establish permanent resolution.

**GA disposition:** **GREEN for zero-warning Release compilation and the full xUnit suite only**, at exact SHA `e73650fc594179d6c7c1db5d5b933a8eff4bd082`. This is NOT an independent real-traffic detection accuracy, external holdout, multi-process storage, crash/power-loss persistence, installer, or production-readiness claim. The malicious replay missed-positive labels for R437, R485, R508 and R516 remain visible and unresolved until independent attributed telemetry producers can corroborate their evidence. Frozen holdout V1 FAILED 4/6 remains immutable; V2 PENDING_EXTERNAL_CAPTURE_AND_REVIEW with zero approved; R102/R118/R163 confidence floors 80%/86%/84% and all approved candidate/Shadow boundaries unchanged.

**Next separate GA:** Examine producer-to-rule wiring, original-source replay and detection-quality precision/recall for the missed-positive rules without inflating the test PASS metric or rewriting replay labels. Perform new builds/tests only with separate owner authorization. The hourly rule and UI automations may move the feature branch; subsequent commits have their own **SOURCE CANDIDATE — UNVERIFIED** status until an exact-SHA Windows run.


### 2026-11-02 — GA evidence-producer integration: R437 strict RESP2 capture source (UNVERIFIED)

**Last owner-verified foundation:** exact `e73650fc594179d6c7c1db5d5b933a8eff4bd082` on `feature/carthago-reliability-hardening`: zero-warning Release build and full **9,762/9,762 xUnit GREEN**. All subsequent work below is **SOURCE CANDIDATE — UNVERIFIED** until a new explicit owner test-time authorization and exact-SHA Windows execution. No .NET builds, tests, benchmarks, external capture, sensor validation, holdout or promotion were performed by the assistant.

**Target and pre-existing infrastructure audit:** R437 (Redis CONFIG SET), R485 (BACnet WriteProperty), R508 (rclone UA egress) and R516 (Cloudflared Tunnel) remain replay-expected malicious positive cases with missing trusted producers. The existing isolated `Carthago/Services/ProtocolIntelligence/Resp2CommandInspector.cs` already parses strict bounded RESP2 array/bulk-string command shapes; `PacketHandler` already has a bounded early TCP segment normalizer and SYN/sequence tracking; `TrafficRecord` already has parser-only flags for HTTP. `OtProtocolLight` and `BacnetBvlcControlInspector` do not decode WriteProperty APDUs; `WindowsProcessResolver` is best-effort process-table enrichment rather than authenticated file-transfer outcome; R516 has no authenticated connector-session source. The initial integration selection is R437 to reuse an existing inspector instead of creating parallel rules or data pipelines. Full detailed source, gap and subsequent GA matrix: `docs/GA_DETECTION_EVIDENCE_PRODUCER_INTEGRATION_20261102.md`.

**Implemented R437 producer subgate — code not executed:** `Resp2CommandInspector` now exports a fixed `IsConfigSetRequest` bool only for fully validated case-insensitive `CONFIG SET` with complete parameter/value pairs; the observation contains no Redis parameter name, value or credential. `PacketHandler` invokes that existing inspector exclusively for observed client-to-TCP/6379 first plaintext payload after an observed SYN with contiguous expected TCP sequence; observed-SYN provenance is tracked under the existing bounded TCP flow lock and prevents midstream inference. `TrafficRecord.RedisRespConfigSetRequestObserved` has a public getter/internal setter; the bounded capture parser populates it; arbitrary JSON import cannot ordinarily manufacture it. `ApplicationProtocol` becomes `redis.resp2` for validated request framing. No general TCP reassembly, server reply/authorization evidence, user/process identity or encrypted inspection is added. The original `ServiceExposureEvidenceBoundary` R437 `REDIS_RESP_CONFIG_SET_UNAVAILABLE` remains fail-closed; only its detail now separates available request-shape evidence from absent trusted response/authorization. **R437_RedisCONFIGSETIndicatorRule itself, generic confidence logic, its runtime mode and thresholds, the original malicious replay label and independent benchmark missed-positive counts remain unmodified.**

**New tests AUTHORED, NOT EXECUTED:** Existing `Resp2CommandInspectorTests` extended with positive CONFIG SET (one/multiple pairs), privacy, malformed/truncated, GET/other-command, and wrong-direction cases. New `Carthago.Tests/RedisRespCaptureIntegrationTests.cs` exercises raw synthetic IPv4/TCP SYN plus first payload, contiguous-sequence and port/direction requirements, midstream/missing-gap negatives, coalesced command behavior, no configuration-value retention, imported JSON cannot assert internal capture flag, and R437's continued NoMatch when trusted server outcome/policy is absent. No private or actual capture fixture, no synthetic holdout admission and no detection true-positive promotion. All new changes share existing branch and documentation. This preserves original frozen V1 FAILED 4/6 and V2 PENDING_EXTERNAL_CAPTURE_AND_REVIEW/0 approvals and R102 80% / R118 86% / R163 84% confidence floors.

**Next separately authorized test GA:** Record exact new HEAD and clean pull; `dotnet build -c Release`, targeted `Resp2CommandInspectorTests|RedisRespCaptureIntegrationTests|NetworkBatch431440AccuracyTests|TuningBenchmarkTests` and full `Carthago.Tests` xUnit TRX; do not mark GREEN until owner sees and records results. After code verification, independently evaluate real producer admission/false positives, TCP loss/reassembly, response correlation and approval policy before allowing R437 security-alert promotion. R485, R508 and R516 remain separate open gaps. This ledger preserves earlier owner-green `e73650f` and historical RED evidence unchanged.

**Change provenance / exact code commits:** RESP2 inspector shape `50d040f` and flow-scope comment `50dee2f`; capture-only record flag `67eca4c`; packet-handler wiring `9855f94` and SYN/sequence admission `5f751d1`; R437 missing-producer explanation `4059c88`; RESP2 inspector tests `d4265ca`, response fixture `a5d3345`, and neutral test comment `364a2c0`; raw packet integration tests `0c5cd51`, SYN/gap fixtures `6478336`, and import-nullability guard `b1832b1`; detailed design audit `5ba0f03`. All are source-only candidates on the same branch. These short SHAs identify commits, not a tested checkout.

**Authoritative protocol references:** Redis RESP specification https://redis.io/docs/latest/develop/reference/protocol-spec/ and Redis CONFIG SET https://redis.io/docs/latest/commands/config-set/.


### 2026-11-02 — GA R437 Redis reply correlation + Approved.AdminHosts policy (source candidate)

**Exact verified baseline:** Owner Windows `e73650fc594179d6c7c1db5d5b933a8eff4bd082` has **9,762/9,762 xUnit PASS, zero reported Release build warnings**. All source and test work described below occurred **AFTER** that verified SHA and remains **SOURCE CANDIDATE — UNVERIFIED**. The assistant did not run Windows/.NET builds, tests, benchmarks, source capture, holdouts, or CI and did not claim a green GA.

**Mission:** Continue existing R437 protocol evidence integration—not a separate rule, parallel sensor or threat-rules count increase. The earlier GA connected bounded `Resp2CommandInspector` to SYN-anchored first TCP/6379 client request, with parser-only `RedisRespConfigSetRequestObserved`. This GA now correlates a complete first CONFIG SET request to a single reverse-direction first server reply on the same tuple, strictly requiring an observed client SYN + server SYN-ACK, contiguous TCP sequence, ACK direction, no intervening client commands or pipelining, no retransmit/gap, no FIN/RST, a bounded **30-second** request/reply window and pre-existing capped TCP flow lifetime. A new `Resp2SimpleReplyInspector` recognizes exact RESP2 `+OK\r\n` versus a bounded printable single-line `-error\r\n`. No payload, error text, configuration keys or values are retained; `TrafficRecord` adds internal-set reply OK/error observation flags. A new client SYN clears old reverse-handshake state for reused 5-tuples.

**Rule/policy safety:** R437 reads the existing `ApprovedAssetRegistry.Current` `Approved.AdminHosts` policy; `HasApprovedAdminHosts` prevents inferring 'unapproved' from missing configuration. A pure isolated `R437_RedisCONFIGSETIndicatorRule.AssessCorrelatedClient` classifies missing endpoints, missing allowlist, approved host and unapproved host deterministically. R437 returns explicit **NoMatch** reasons for wire-error replies, missing endpoints/policy, approved admin, or unapproved client with unverified Redis server identity. A correlated network `+OK` is NOT authenticated server identity, user authorization or a completed persistent configuration change; no security alert or confidence/profile/mode promotion was introduced. Request-only R437 retains original hard guard `REDIS_RESP_CONFIG_SET_UNAVAILABLE`; that guard's wording was updated to distinguish observed reply shapes from absent trusted source. All replay malicious positive labels and missed-positive counts remain unchanged.

**Source actions on the same branch (no new branch):** `Resp2SimpleReplyInspector.cs` (new, `7fa0ffb`), `TrafficRecord.cs` (wire reply flags `544d5a9`), `PacketHandler.cs` (same-flow request/reply tracking `402c6b7`, first-payload guards / FIN/RST `fab197d`, 30s limit `316be0e`, tuple reuse reverse reset `d9828cb`), `ApprovedAssetRegistry.cs` (presence of existing admin policy `e07d746`), `R437_RedisCONFIGSETIndicatorRule.cs` (NoMatch/allowlist `07c2556`, pure policy evaluation `b6ef0dc`), `ServiceExposureEvidenceBoundary.cs` (updated reason detail `170180c`). No source or policy default was changed for R485/R508/R516.

**Authored new tests, NOT executed:** `Resp2SimpleReplyInspectorTests.cs` (`ce5fc0d`) covers complete +OK vs errors, truncated/coalesced/oversized/control text, no content retention. Existing `RedisRespCaptureIntegrationTests.cs` expanded with synthetic raw SYN/SYN-ACK/request/reply TCP frames, server acceptance/error, malformed replies, missing SYNACK, wrong sequence, repeated and additional client payload, FIN/RST, prior unexpected reply, request expiration, reused tuple stale handshake, imported JSON flag forgery, and pure per-test admin policy (commits `2fb8df0`, `416cacd`, `046dc6a`, `b9967ac`, `69078a7`). Existing R437 missing-producer negative tests remain unmodified; their expectations remain authoritative until owner execution.

**Quality/remaining gaps:** This is a bounded request/reply **wire-shape** correlator only; no general TCP reassembly, AUTH/HELLO session handling, TLS decryption, RESP3, NAT attribution, authenticated Redis server identity, independent audit log, command authorization, asset inventory validation, calibration or real external packet capture. Do not claim a detector positive merely because `+OK` was observed; source policy may be empty and no alerts are emitted for any branch. Frozen holdout V1 FAILED 4/6 immutable; V2 PENDING_EXTERNAL_CAPTURE_AND_REVIEW/0 approvals; confidence floors R102 80%, R118 86%, R163 84% intact. R485, R508 and R516 remain independently unsolved trusted-producer gaps.

**Required next owner-authorized verification:** From clean `feature/carthago-reliability-hardening` working tree, pull fast-forward, print exact `git rev-parse HEAD`, run Release build, targeted xUnit filter `Resp2CommandInspectorTests|Resp2SimpleReplyInspectorTests|RedisRespCaptureIntegrationTests|NetworkBatch431440AccuracyTests|TuningBenchmarkTests` with TRX; then full `Carthago.Tests` Release xUnit with distinct TRX. Investigate warnings and genuine failures without rewriting benchmark labels. Independently measure producer coverage and labeled missed positives/FP before future rule promotion. Later automation commits to this branch require separate exact-SHA verification.

**Detailed GA architecture and limits:** `docs/GA_R437_REDIS_REPLY_CORRELATION_20261102.md`. **External protocol authority:** https://redis.io/docs/latest/reference/protocol-spec/ and https://redis.io/docs/latest/commands/config-set/.


### 2026-11-02 — GA R437 trusted Redis audit claim intake and identity policy (UNVERIFIED)

**Owner verification boundary:** Last owner-observed exact SHA `e73650fc594179d6c7c1db5d5b933a8eff4bd082` had a zero-warning Release build and **9,762/9,762 PASS**, zero failures/skipped. The immediately preceding GA R437 RESP2 request/reply correlation is not yet owner-verified. This additional signed-audit identity GA is likewise **SOURCE CANDIDATE — UNVERIFIED**. The assistant did not execute builds, xUnit, benchmarks, production capture, trusted Redis server connections or holdout tests, and did not authorize positive detection alerts.

**Reused infrastructure:** `TrustedAuditReceiptVerifier` already requires operator-pinned RSA-PSS/SHA-256 public keys, signed claims scoped by rule and operation, strict schema, freshness and bounded replay caching; `TrustedAuditReceiptCorrelation` accepts only independently signed, same-registry receipts with matching actor/resource/trace hash, endpoints and rule. Redis R437 is now an explicitly allowed audit claim scope with the exact operation `RedisConfigSetCommandSucceeded` (source `a143848`). No trust key is bundled, hardcoded or generated for production; no unsigned audit JSON can manufacture `VerifiedAuditReceipt`.

**Redis audit source limitation (verified against Redis documentation):** `ACL LOG` records denied commands/failed auth, not accepted CONFIG SET. `CLIENT LIST` exposes current connection metadata, not a historical command outcome. Redis Software's optional command auditing reports status **9=command completed successfully**, **10=command failed**, but the published generic `command: "config"` field cannot prove the **SET subcommand** without additional independently trusted evidence. Redis Software's notification TCP transport is not a signed feed and audit records may be dropped; no collector/source credential, certificate, producer-of-record, authorization-to-transaction binding or real audit ingestion is configured in this GA.

**Implemented isolated signed audit candidate path (never live Alert):** `ApprovedEnvironmentOptions.RedisServers` (source `6dbd3ac`) adds optional explicit Redis server inventory; `ApprovedAssetRegistry` adds `HasApprovedRedisServers`/`IsApprovedRedisServer` (`a6a339d`), without changing existing R437/R485/etc runtime approved-asset decisions. `RedisTrustedAuditCandidateGate` (source `2eabece`, follow-up `6920fbc`) requires a `CorrelatedAuditReceipts` capability from the existing verifier, a capture-only Redis +OK record, matching client/server IPs in reverse direction, TCP server port 6379, signed timestamps within 30 seconds of separately supplied capture UTC, configured RedisServers inventory and configured AdminHosts. A matching admin is classified as approved; otherwise it is explicitly `UnapprovedClientRequiresTransactionBinding`. Every `RedisAuditCandidateAssessment.AlertPermitted` returns **false**. A pinned signer is not cryptographic Redis daemon identity, two distinct signing keys are not automatically two independent original evidence sources, and IP/time overlap is not proof of a unique command/capture transaction.

**Opt-in intake without listener/alert registration:** `RedisSignedAuditCandidateIntake` (source `87ae5e6`) requires an externally constructed `TrustedAuditReceiptVerifier` and `ApprovedAssetRegistry`; it calls `TryVerify` on each signed envelope, `TrustedAuditReceiptCorrelation.TryCorrelate`, then the passive R437 gate. Tampered claims, absent signatures, wrong operation, replay, same issuer, missing approved servers/admin policy, mismatched endpoints or timestamps all fail closed. No new network listener, new rule ID, production secret, signer private key, auto-configured trust anchor, `RuleRegistry` promotion, `TrafficCaptureService` coupling or R437 EvaluatePrecision behavior change is introduced.

**Tests AUTHOR-ONLY (not run):** `RedisTrustedAuditCandidateGateTests.cs` (source `1edb4e9`, additional intake/replay tests `da0ed8d`) contains **12 synthetic RSA-signed `[Fact]` tests** for scoped R437 signatures, exact operation, pinned independent issuers, replay/tamper, no config, wrong server, admin policy, mismatched wire endpoint and UTC time, approved admin, malicious unapproved candidate and mandatory `AlertPermitted=false`. These synthetic fixtures are **not** original external Redis audit telemetry or detector true positives. Detailed source/provenance and independent test/quality roadmap: `docs/GA_R437_TRUSTED_REDIS_AUDIT_IDENTITY_20261102.md` (source `404af89`).

**Gate disposition:** **NOT READY FOR R437 POSITIVE ALERTS**. Need current-HEAD Windows Release compilation + targeted/full xUnit with recorded TRX, independently authenticated Redis Software or other server command auditor that actually disambiguates `CONFIG SET`, properly pinned server identity and operator key management, reliable event-delivery/drop accounting, shared nonreplayable per-TCP-transaction ID between source and packet capture (beyond matching signed audit receipts on IP/time), and independently labeled attack/benign precision/recall evaluation before any conditional promotion. Preserve the original malicious replay positive label as a missed R437 positive until proven otherwise; do not tune or alter it to make xUnit GREEN.

**Owner constraints intact:** feature branch unchanged; frozen holdout V1 immutable FAILED 4/6; Holdout V2 PENDING_EXTERNAL_CAPTURE_AND_REVIEW/0 approvals; confidence floors R102 80%, R118 86%, R163 84% and R437 82% unchanged. R485/R508/R516 separate trusted-producer gaps remain open.

**Protocol sources:** https://redis.io/docs/latest/commands/acl-log/ ; https://redis.io/docs/latest/commands/client-list/ ; https://redis.io/docs/latest/operate/rs/security/audit-events/ ; https://redis.io/docs/latest/management/security/acl/ .


### 2026-11-02 — Owner Windows R437 GA build RED at d9cd7c8: WPF MC3088; XAML source fix unverified

**Exact owner-tested branch/SHA:** `feature/carthago-reliability-hardening` at `d9cd7c8805736438494573c772105cc62e1ae272`. Owner reported a clean working tree, `git pull --ff-only` already up to date, and a Windows `dotnet build -c Release` that **FAILED** with 1 WPF XAML compiler error: `Carthago/Views/MainWindow.xaml(95,28): MC3088 Property elements cannot be in the middle of an element's content`. Compilation stopped before the new R437 audit-candidate changes could be validated. This is a **RED build checkpoint**, and no new positive R437 detection or owner-verified GA is claimed. The last accepted GREEN Release/full regression checkpoint remains `e73650f`: 9,762 / 9,762 passing, zero warnings.

**Root cause and minimal source change:** In `DashboardKpiCardTemplate` within `MainWindow.xaml`, the visual `<Border Grid.RowSpan="3" ... />` preceded the owning `<Grid.RowDefinitions>` property element. WPF requires the property definitions before the visual children. The fix moved the **same Border** after the unchanged three row definitions without changing bindings, rendering parameters, data values, layout sizes or other UI/detection files. Commit `c23549223b22285686c75d58d1f2e6c3efc8280f`, **SOURCE CANDIDATE — UNVERIFIED**. A static structural scan of the current MainWindow.xaml found no other Grid.RowDefinitions/ColumnDefinitions after Grid content; template/style triggers after their own child content are trailing property elements, not this specific MC3088 pattern.

**Test-log integrity caveat:** The owner subsequently invoked `dotnet test ... -c Release --no-build --filter ...` **after the failed build**. `--no-build` may execute previously compiled binaries; any results from that invocation, including a potential green result, are not evidence that the new exact-SHA R437 source compiled or passed. A `throw` executed at the PowerShell interactive prompt interrupts the current statement, but separately entered following commands may still run. Require a clean Release build before any targeted/full tests and capture the exact Git SHA and TRX; for strict fail-fast, execute the entire validation script as one `& { ... }` block or a `.ps1` file.

**Next owner test GA:** Pull fast-forward on the existing branch after confirming a clean tree; record exact `git rev-parse HEAD`. Run `dotnet build -c Release`, stop on nonzero status; then targeted tests `Resp2CommandInspectorTests|Resp2SimpleReplyInspectorTests|RedisRespCaptureIntegrationTests|RedisTrustedAuditCandidateGateTests|TrustedAuditReceiptVerifierTests|TrustedAuditReceiptCorrelationTests|NetworkBatch431440AccuracyTests|TuningBenchmarkTests`, and finally the complete xUnit Release regression, each with TRX and exit-code verification. Confirm no new source-compile errors/nullable warnings. R437/redis audit signed candidates remain non-alerting and cannot be promoted by synthetic test success. Frozen V1 holdout and V2 eligibility unchanged.


### 2026-11-02 — Owner Windows 2c8d0fc zero-warning build / Redis gate GREEN; full xUnit RED 12 R561/R562

**Owner-executed exact commit:** `2c8d0fc14f3881e9d2dd530518852c8afa2e61ea` on sole `feature/carthago-reliability-hardening` branch, clean tree and fast-forward `d9cd7c8..2c8d0fc`. **`dotnet build -c Release` GREEN** for Carthago, Carthago.Benchmarks and Carthago.Tests, **zero build/analyzer warnings printed** (65.0s); previous WPF MC3088 property-order error resolved. **Targeted Redis gate GREEN** `redis-trust-gate.trx`: **250/250 tests PASS**, zero failed/skipped (52.7s). This filter covered `Resp2CommandInspectorTests`, `Resp2SimpleReplyInspectorTests`, `RedisRespCaptureIntegrationTests`, `RedisTrustedAuditCandidateGateTests`, `TrustedAuditReceiptVerifierTests`, `TrustedAuditReceiptCorrelationTests`, `NetworkBatch431440AccuracyTests`, `TuningBenchmarkTests`. Crucially **it did not include R561/R562 advanced accuracy tests**.

**Full xUnit regression at the SAME exact SHA is RED:** `build-verify/full-test.trx`: **9,853 total, 9,841 passed, 12 failed, 0 skipped** (110.4s). All 12 named failures belong to two newer **candidate Shadow** rules: 6 in `R561AdvancedAccuracyBatchTests` and 6 in `R562AdvancedAccuracyBatchTests`. One independently diagnostic exception: `R561AdvancedAccuracyBatchTests.RealPacketProducerDistinguishesCorrelatedErrorFromOk` expected `ApplicationProtocol == "redis.resp2"` but the real producer returned `"HTTP"`; the other failures were count/transition, cooldown, concurrency and structured evidence expectations receiving `NoMatch` or empty events. These are actual failing tests, not misses to relabel or quarantine. The build was genuinely GREEN but overall test GA **RED**. Preserve exact historical checkpoints.

**Root-cause source review:** `PacketHandler` first binds validated, SYN-anchored Redis `CONFIG SET` requests and correlated `+OK/-ERR` replies and marks `rec.ApplicationProtocol = "redis.resp2"` with internal capture-only flags. Later in the same packet-processing sequence, the generic `HttpLight.TryParseHttp` request-line heuristic runs without checking the already validated Redis protocol and can overwrite `ApplicationProtocol` with `HTTP` and populate contradictory HTTP fields on RESP lines. Both R561/R562 deliberately require exact Redis attribution and no HTTP metadata, so the verified producer observation is discarded before burst/transition counters. Changing rule confidence or removing evidence constraints is inappropriate.

**Single shared source correction (NOT YET OWNER-VERIFIED):** `Carthago/Services/PacketHandler.cs`, source commit `2e2d6a1ce177706a62a1505f1a2e4713a9a49613`, guards generic HTTP parsing with `!string.Equals(rec.ApplicationProtocol, "redis.resp2", StringComparison.Ordinal)` so a *validated* RESP request/reply cannot be overwritten by a less-specific HTTP interpretation. For other TCP traffic—including actual HTTP on port 6379 without validated RESP framing—the HTTP parser remains unchanged. No Redis reply flag, SYN/ACK/sequence check, authority field, policy gate, evidence floor, Shadow/Alert mode or rule threshold is relaxed.

**Regression tests authored NOT RUN:** `Carthago.Tests/RedisRespCaptureIntegrationTests.cs`, commit `e0b53d33359ddd73227620a226640b644fee2a6d`, now explicitly checks that correlated Redis `+OK` and `-NOPERM` retain `redis.resp2` with null HTTP method/URI/host/headers and adds a negative test that a valid HTTP request on TCP/6379 is still classified as `HTTP`. Existing R561/R562 positive, negative, cooldown, duplicate, count and concurrency tests remain unchanged. No tests/build/replays were executed by assistant after these corrections, so this is a **SOURCE CANDIDATE — UNVERIFIED**.

**Next owner-authorized verification:** clean fast-forward pull and exact `git rev-parse HEAD`, `dotnet build -c Release`, then a targeted combined filter including `R561AdvancedAccuracyBatchTests|R562AdvancedAccuracyBatchTests|RedisRespCaptureIntegrationTests|RedisTrustedAuditCandidateGateTests|Resp2CommandInspectorTests|Resp2SimpleReplyInspectorTests` with dedicated TRX. Only if green, full `Carthago.Tests` suite with TRX; record exact SHA, totals/warnings. New hourly automation commits may change suite count. Existing intentional `PortServiceResolver` 403, corrupt-feedback fallback and failing-sink negative-test logs do not explain these 12 failures. Frozen V1 FAILED 4/6 and V2 0 approvals remain untouched; minimum confidence floors R102 80%, R118 86%, R163 84%, R437 82%, R561 86%, R562 88% unchanged, with R561/R562 Candidate Shadow and R437 wire/signed-audit candidates non-alerting.


### 2026-11-02 — Owner Windows d1cc8de Release GREEN, Redis 108/108 GREEN, full suite TESTHOST ABORT (NOT GREEN)

**Exact owner checkout:** clean working tree on `feature/carthago-reliability-hardening`, fast-forward `2c8d0fc..d1cc8de`, SHA `d1cc8dea9b955fe745d0102b334c333521158ab0`. Changes in that pull included source-fix `PacketHandler.cs` Redis-vs-HTTP precedence, targeted capture regression tests and independent UI design files. `dotnet build -c Release` completed successfully for Carthago, Carthago.Benchmarks and Carthago.Tests in **47.6s, zero compiler/analyzer warnings printed**. **Targeted Redis/R561/R562 regression GREEN:** `build-verify/redis-r561-r562-recheck.trx`, **108/108 PASS, 0 failed, 0 skipped**, 15.1s. This confirms the prior 12 R561/R562 assertion failures resolved under their targeted test contract at this SHA; all original tests, evidence guards, thresholds and Candidate/Shadow modes remain intact.

**Full regression remains NOT VERIFIED — TESTHOST ABORT, not 12 assertion failures:** The next `dotnet test ... -c Release --no-build --logger "trx;LogFileName=full-test.trx" --results-directory build-verify` ran for roughly **199s** and reported `The active test run was aborted. Reason: Unable to communicate with test host process.`, followed by `TESTRUNABORT` and nonzero exit. The console did **not** identify a failing xUnit assertion or reliably report complete pass/fail totals for this attempt. `full-test.trx` was overwritten in the owner's results directory. Therefore neither the original 9,853-test full regression nor any updated suite count is GREEN for d1cc8de, regardless of the successful targeted run. Do **not** relabel the abort as a test PASS or equate it to the earlier 12 confirmed R561/R562 assertion failures. Last owner-green full regression: exact `e73650fc594179d6c7c1db5d5b933a8eff4bd082` (9,762/9,762). Prior full regression at `2c8d0fc` was RED 12 assertion failures, 9,841/9,853 passing. Both historical results remain immutable.

**Host-failure root cause unconfirmed.** A lost VSTest/testhost connection could result from process crash, forced termination, resource exhaustion, external interference or runner/adapter communication failure. The console includes a 403 optional port-data refresh, intentional invalid-feedback negative-test log and intentional FailingSink test log, none of which independently explains why the process disappeared. Inspect actual diagnostic artifacts before modifying source or xUnit parallelism; synthetic Redis detection labels are not evidence of process crash.

**Next owner-authorized diagnostic path on the same exact source:** First preserve or copy current TRX and rerun full Release suite using unique `--results-directory`, `--blame-crash --blame-crash-dump-type mini`, `--blame-hang --blame-hang-timeout 10m --blame-hang-dump-type mini`, `--diag <unique trace file>`, and TRX. Blame emits ordered `Sequence.xml` and may emit a mini dump on eligible testhost crashes. On failure inspect the sequence's last-started tests, latest diagnostic log, Windows Application log (dotnet/testhost crash events) and available memory/antivirus intervention; only then narrow a reproducible test subset or implement a root-cause code fix. Crash minidumps may include sensitive data or credentials; share redacted text, status and sequence names, not raw dumps indiscriminately. On a clean full rerun, record exact SHA and counts. A transient success does not independently establish reliability; an abort must remain a historical RED/INCOMPLETE checkpoint.

**Frozen V1 FAILED 4/6 untouched, V2 PENDING_EXTERNAL_CAPTURE_AND_REVIEW/0 approved, R102 80% / R118 86% / R163 84% / R437 82% floors, R561/R562 candidate Shadow floors 86%/88%, and original replay missed-positive expectations unchanged. No builds/tests or host diagnostic process were executed by assistant in this ledger edit.**

**Technical reference:** Microsoft VSTest `dotnet test` blame/crash/hang and diagnostic options https://learn.microsoft.com/en-us/dotnet/core/tools/dotnet-test-vstest ; VSTest blame data collector https://github.com/microsoft/vstest/blob/main/docs/extensions/blame-datacollector.md .


### 2026-11-02 — Owner Windows full xUnit GREEN 9,854/9,854 at 65826c3; previous testhost abort unresolved

**Verified exact checkout:** The owner confirmed a clean working tree and fast-forward on the **existing** `feature/carthago-reliability-hardening` branch, from `d1cc8de` to `65826c3ec087cbd7c5306f1f32ce8dbc86d24e31`. The pull changed **only** `docs/DEVELOPMENT_VALIDATION_LEDGER.md` (previously recorded testhost abort). No app/test source changes were pulled in that step. All below are **owner-executed on Windows** at the printed SHA.

**Build GREEN:** `dotnet build -c Release` passed for `Carthago`, `Carthago.Benchmarks` and `Carthago.Tests` in **57.8s** with **no compiler or analyzer warnings reported**. This independently confirms the previous Redis/HTTP parser precedence correction builds at the tested SHA.

**Full regression GREEN:** `dotnet test Carthago.Tests/Carthago.Tests.csproj -c Release --no-build --blame-crash --blame-crash-dump-type mini --blame-hang --blame-hang-timeout 10m --blame-hang-dump-type mini --diag ... --logger "trx;LogFileName=full-diagnostic.trx" --results-directory ...` completed with **9,854 total, 9,854 passed, 0 failed, 0 skipped**, duration **112.0s**; exit code **0**, and owner console displayed `FULL REGRESSION GREEN`. Owner-local evidence: `build-verify/testhost-20261102-185727/full-diagnostic.trx` and `vstest.log`, `vstest.host.*.log`, `vstest.datacollector.*.log` in the same folder. Data collector printed **one diagnostic-only warning** `All tests finished running, Sequence file will not be generated.` This was **not** a Release build warning or failed test. No crash dump or Sequence.xml was reported; successful runs normally do not emit those. Earlier owner-targeted R561/R562+Redis suite **108/108 passed** at `d1cc8dea9b955fe745d0102b334c333521158ab0`; that and the full 9,854/9,854 at this exact newer SHA resolve the previously observed assertion failures under the unit-test contract.

**Previous host abort disposition:** At `d1cc8de`, an earlier full run ended in `TESTRUNABORT` / `Unable to communicate with test host process` after about 199s and no complete test counts. This newer full run completed in 112s under Blame instrumentation with exit 0. Therefore the earlier event is **not reproducibly diagnosed**, and its root cause (process crash, resource exhaustion, external termination or test-platform communication) remains **UNKNOWN**. Do not claim a specific cause or silently delete the abort record; if it recurs, use the archived VSTest diagnostics and Windows event logs to identify the process failure.

**Other console diagnostics:** The optional `PortServiceResolver` remote refresh returned HTTP 403; existing code has an explicit non-retryable cooldown for 403. `IncidentFeedbackStore` malformed JSON and `SinkManager` FailingSink failures are consistent with intentional negative-test paths previously audited; they are not proof of production incidents.

**GA interpretation:** **GREEN for Release compilation and complete xUnit at SHA 65826c3**. This verifies new R437 Redis signed-audit candidate contracts and R561/R562 raw-packet/correlation candidates under authored synthetic unit tests, **not production Redis audit provenance, independent detection-quality precision/recall, production sensor behavior or R437 alert eligibility**. No changes to the frozen V1 holdout (historical FAILED 4/6), pending V2 external capture review with 0 approved, confidence floors R102 80% / R118 86% / R163 84% / R437 82% / R561 86% / R562 88%, or Candidate Shadow constraints. Subsequent hourly rule/UI commits after this exact SHA are **SOURCE CANDIDATE — UNVERIFIED** until tested separately.

**Next engineering gate:** Preserve the exact Windows TRX and diagnostics; continue separately with authenticated Redis audit collector provenance and non-replayable per-transaction producer-to-packet correlation; gather independently labeled original attack/benign samples, measure distinct TP/FP/FN/TN/precision/recall and review policy before positive detection. Alternatively evaluate independently the reported intermittent testhost lifetime if it recurs. Do **not** promote R437 from wire/signed candidate on xUnit success alone.


### 2026-11-02 — GA R437 Redis Software audit source-to-packet diagnostics (SOURCE CANDIDATE — UNVERIFIED)

**Exact prior owner-green reference:** `65826c3ec087cbd7c5306f1f32ce8dbc86d24e31`, existing `feature/carthago-reliability-hardening`: Release build passed with no reported compiler/analyzer warnings and complete xUnit **9,854 / 9,854 GREEN**; the intermittent earlier testhost abort remains historically documented as unexplained. ALL source and synthetic test changes in this entry occurred **after** that owner-tested SHA and are **SOURCE CANDIDATE — UNVERIFIED**. The assistant did not execute Windows/.NET tests, live Redis, packet capture, benchmark replays or holdout operations.

**Aim / gap audit:** Redis Software's official best-effort command and connection auditing has `ts`, `id`, `srcip/srcp`, `trgip/trgp`, `bdb_uid`, `audit_worker_id`, `audit_seq`, command name and per-command statuses **9=completed, 10=failed**. Existing Carthago already supplies SYN-anchored, bounded Redis RESP2 command/reply packet evidence and a separate pinned RSA-PSS signed-audit intake. No general TCP collector-to-packet bridging was available. Official vendor audit command field `config` **cannot authenticate the exact CONFIG SET subcommand**; raw TCP notification transport is not an authenticated source and its delivery is best effort with potential drops. It is technically wrong to promote this to signed `RedisConfigSetCommandSucceeded` or an R437 positive; do not do so.

**New code on SAME branch (no new detector or source trust):**
- `Carthago/Services/TrustedAudit/RedisSoftwareAuditNotificationParser.cs` `65b5004`: max 16KiB, fixed-shape per-event Redis Software command, connection, auth and close JSON parsing; strict numeric timestamps/connection ID/worker/sequence, canonical IP/ports and bounded database UID. Returns privacy-minimized record containing no Redis keys, parameters, usernames, error/ACL text or raw payload. `ProvesConfigSetSubcommand=false` and `AuthenticatedProducer=false` by construction. Generic CONFIG is not CONFIG SET.
- `Carthago/Services/TrustedAudit/RedisSoftwareAuditContinuityTracker.cs` `9e7d4b0`: fixed-capacity per-source/per-worker audit sequence observations, acceptance of all event kinds, sticky gap/duplicate/rollback rejection; no input-provided identity trust and no invented lossless-delivery claims.
- `Carthago/Services/TrustedAudit/RedisSoftwareAuditWireCorrelation.cs` `e503b46`, clarified `748aafc`, extended status `ac3cb53`: matches real `TrafficRecord` capture-only Redis correlated server reply with vendor source/target IP **and both ports**, command outcome, ±30 seconds, available audit-sequence continuity and configured RedisServers/AdminHosts. Missing evidence yields fixed diagnostic reason; even all matched conditions on `config` return `GenericConfigSubcommandUnproven` and `AlertPermitted=false`, `ConfigSetVerified=false`, `AuthenticatedRedisServer=false`.
- `Carthago/Services/TrustedAudit/RedisSoftwareAuditDiagnosticIntake.cs` `5345dde`: opt-in, bounded complete-event entry point reusing parser, per-worker continuity tracker and existing packet record; it is **NOT** a network listener, authenticated transport, cryptographic trusted source, signed-claim generator or R437 Alert admission.
- `environment-tuning.sample.json` `7baafb4`: optional explicit `approved.redisServers: []` with unconfigured fail-closed default. No modification of current policy values or rule confidence/mode.

**Tests AUTHORED NOT EXECUTED:** `Carthago.Tests/RedisSoftwareAuditSourceTests.cs` `2f75675` (duplicate-property test hardened in `aed27c3`) contains synthetic published-schema notification examples, success/failure, non-Config/ambiguous command names, no-secret-retention, malformed/oversized/duplicate JSON and bounds, all four event shapes, worker sequence first/contiguous/gap/replay/sticky failure and capacity cases. `Carthago.Tests/RedisRespCaptureIntegrationTests.cs` updated `bc91fbf`, `84c6cd6` to join the new vendor metadata to existing raw SYN/SYN-ACK TCP Redis `CONFIG SET`/`+OK` fixtures, assert 4-tuple and outcome/time, show approved-admin classification, reject sequence gaps and duplicate vendor messages, and confirm final output always non-alerting. Historical R561/R562 positive and negative tests, original Redis malicious replay label and source floor untouched. Full detailed GA and next-step deployment/accuracy criteria: `docs/GA_R437_REDIS_SOFTWARE_AUDIT_ADAPTER_20261102.md` (`e64915b`, clarified verification command `308a14f`). A single operator-invoked Windows fail-fast script `scripts/verify-redis-software-audit-ga.ps1` (`c6529fe`) checks clean feature branch, fast-forward SHA, Release build, targeted source tests and complete xUnit with distinct TRX; **script authored, never executed by assistant**.

**Verification needed (only when owner authorizes new test window):** clean fast-forward branch and print SHA; `dotnet build -c Release` first; targeted `RedisSoftwareAuditSourceTests|RedisRespCaptureIntegrationTests|RedisTrustedAuditCandidateGateTests|TrustedAuditReceiptVerifierTests|TrustedAuditReceiptCorrelationTests|R561AdvancedAccuracyBatchTests|R562AdvancedAccuracyBatchTests` with TRX, then full xUnit Release suite with new TRX, exact SHA and error counts. Never mark current GA GREEN from the prior 9,854 checkpoint; new source may have compile/test errors. Independently validate original-source Redis audit frames, source authentication, delivery/drop metrics, subcommand proof and unique transaction binding before performance or detection-quality evaluation.

**Disposition:** R437 still NO positive alert; R561/R562 Candidate Shadow. Frozen V1 holdout historical FAILED 4/6 immutable; V2 PENDING_EXTERNAL_CAPTURE_AND_REVIEW / 0 approved; R102 80%, R118 86%, R163 84%, R437 82%, R561 86%, R562 88% confidence floors unchanged. Maintain GA development ledger without overwriting historical outcomes. Independent TP/FP/FN/TN and precision/recall are unavailable; do NOT misrepresent synthetic tests or guessed prevalence as operational detection quality.

**Authoritative vendor schema and delivery source:** https://redis.io/docs/latest/operate/rs/security/audit-events/ .


### 2026-11-02 — Owner Windows Redis Software audit GA GREEN at 6099bfa: 125/125 targeted, 9870/9870 full

**Owner-executed exact-SHA validation:** Working tree on existing `feature/carthago-reliability-hardening` was fast-forwarded from `65826c3` to `6099bfa8c9bff2150caadc7dbf89f332752a1a42`. Owner confirmed new `scripts/verify-redis-software-audit-ga.ps1` was present and executed that script successfully from the repository root. Script's own second pull was already up to date, and it printed the same SHA both at start and completion. All following results are from the **owner's Windows console**, not executions by the assistant.

**Release build: GREEN**, `dotnet build -c Release`, total **65.1s**. `Carthago`, `Carthago.Benchmarks` and `Carthago.Tests` all compiled successfully; **no compiler or analyzer warnings reported**.

**Targeted Redis audit GA: GREEN**, `dotnet test ... -c Release --no-build --filter RedisSoftwareAuditSourceTests|RedisRespCaptureIntegrationTests|RedisTrustedAuditCandidateGateTests|TrustedAuditReceiptVerifierTests|TrustedAuditReceiptCorrelationTests|R561AdvancedAccuracyBatchTests|R562AdvancedAccuracyBatchTests`: **125 total / 125 passed / 0 failed / 0 skipped**; 11.9s. Exact owner-local TRX: `build-verify/redis-audit-ga-20261102-193912/redis-source-targeted.trx`.

**Full regression: GREEN**, `dotnet test Carthago.Tests/Carthago.Tests.csproj -c Release --no-build`: **9,870 total / 9,870 passed / 0 failed / 0 skipped**, 70.4s, exit 0. Exact owner-local TRX: `build-verify/redis-audit-ga-20261102-193912/full-regression.trx`. Script printed `Full xUnit regression GREEN at 6099bfa...` and `Verified source SHA: 6099bfa...`. This is **16 tests more than the 9,854/9,854 previously owner-verified full regression** at SHA `65826c3`. The previously seen test-host abort did not recur, but its root cause remains historically unknown and must not be silently rewritten as resolved.

**Warning/noise classification:** Test output includes optional `PortServiceResolver` remote refresh 403 Forbidden, `SinkManager FailingSink` and malformed `IncidentFeedbackStore` messages from test-exercised negative paths, and a synthetic R006 DNS detection event. None caused an xUnit failure; the console does not establish any production alert from those messages.

**What is now verified:** The new bounded Redis Software notification parser, privacy-minimized metadata extraction, fail-closed sequence continuity, four-tuple + reply/status/time correlation, opt-in diagnostic intake, synthetic negative-case and Redis/R561/R562 tests pass **Release compile and automated test contracts** at this exact SHA.

**Still NOT verified or production-ready:** No authenticated Redis Software audit collector/transport is deployed; original-source command/ACL identity and signed-server provenance are absent; generic vendor `CONFIG` records cannot establish the exact `SET` subcommand; neither audit worker sequence nor four-tuple/time prove a nonreplayable unique transaction; no original independent externally labeled attack/benign detection-quality dataset, producer coverage, TP/FP/FN/TN, precision/recall or production alert acceptance review. The `RedisSoftwareAuditDiagnosticIntake` remains opt-in and **non-alerting**. R437 must NOT be promoted to positive alerts based on these synthetic tests. R561/R562 remain Candidate/Shadow and previous accuracy expectations remain intact.

**Immutable constraints:** Frozen holdout V1 historical FAILED 4/6 unchanged; V2 PENDING_EXTERNAL_CAPTURE_AND_REVIEW / zero approved captures; confidence floors R102 80%, R118 86%, R163 84%, R437 82%, R561 86% and R562 88% unchanged. This entry is a **verified Windows test GA for 6099bfa**, not approval to deploy a source, rewrite malicious replay labels, remove fail-closed guards or modify holdouts. All later branch commits, including this documentation entry, are not part of the tested source SHA.

**Next implementation gate:** Authenticated framed Redis Software audit collector with pinned source identity and reliable drop/sequence accounting; independently corroborate exact `CONFIG SET`, verified Redis server/ACL and a unique audit-to-capture transaction before independently measuring detection quality. Supporting GA documentation: `docs/GA_R437_REDIS_SOFTWARE_AUDIT_ADAPTER_20261102.md`.


### 2026-11-02 — GA R437 pinned mTLS loopback audit relay + sink-loss metrics (SOURCE CANDIDATE — UNVERIFIED)

**Most recent exact owner-Windows GREEN checkpoint:** `6099bfa8c9bff2150caadc7dbf89f332752a1a42`, on `feature/carthago-reliability-hardening`: `dotnet build -c Release` GREEN (no reported compiler/analyzer warnings), targeted Redis software audit GA **125/125 PASS**, full xUnit **9,870/9,870 PASS**, zero failed/skipped. The latest checkpoint was verified by the owner with `scripts/verify-redis-software-audit-ga.ps1`, as recorded in the previous entry. All NEW source and tests below were committed **after** that SHA; **no .NET build, xUnit, external audit receiver or performance tests have been run by the assistant** for the new work. It remains **SOURCE CANDIDATE — UNVERIFIED** even if the operator can retrieve the files.

**Objective/gap:** Redis Software sends best-effort audit notifications on its **native plain TCP** transport. The previous GA implemented bounded JSON parsing, audit_seq tracking, endpoint/port/time comparison and opt-in `RedisSoftwareAuditDiagnosticIntake` but deliberately included no transport-side authenticator. Directly treating the vendor's unauthenticated TCP metadata, IP address or audit sequence as trusted would be an invalid evidence promotion. This GA adds a distinct **operator-controlled, pinned mutual-TLS relay receiver** on loopback and separate `audit_sink_*` loss-counter monitoring **without** enabling R437 Alerts or asserting Redis daemon authentication.

**New files and commits, same existing branch:**
- `Carthago/Services/TrustedAudit/RedisAuditMutualTlsRelayReceiver.cs` — source `29abeeb`, security hardening `05f23ee`. A narrowly opt-in receiver for an **already-started loopback-bound TcpListener**, one TLS session per invocation; no service auto-start, no registry mutation, no new public bind, no outbound credential use, no Redis native sink listening. Requires an operator-provided TLS server certificate with private key and explicit **serverAuth EKU** (hardening commit `bf6e9ec`), plus a configured, exact **lowercase 64-hex SHA-256 full client certificate hash** and provisioned relay identifier. `SslStream` accepts only TLS 1.2/1.3 with mandatory peer certificate, valid time and explicit client-auth EKU; pin hash compared constant-time, and after handshake explicit `tls.IsMutuallyAuthenticated` plus remote certificate presence are required (requesting a certificate is not acceptance proof). Only 4-byte network-order length-prefixed JSON frames `1..16384` bytes, at most 512 per session; 15-second handshake/frame deadlines, caller cancellation, in-order callback, bounded memory, frame zeroing after callback and sanitized outcomes on invalid/truncated/failed packets. Pin proves the *relay* certificate only; it is **NOT** Redis daemon identity, ACL or command success.
- `Carthago/Services/TrustedAudit/RedisAuditMutualTlsDiagnosticBridge.cs` — source `a61a685`. Reuses existing `RedisSoftwareAuditNotificationParser`, `RedisSoftwareAuditDiagnosticIntake` and packet capture-only reply lookup, passing the authenticated relay ID (never JSON-provided) and emitting only fixed sanitized diagnostic statuses. Malformed JSON or audit-sequence discontinuity closes the session fail-closed, not silently ignored. No R437 rule/precision mode/authorization change.
- `Carthago/Services/TrustedAudit/RedisAuditSinkMetricsHealth.cs` — source `974357a`. Bounded per-operator-source metrics monitor for Redis Software `audit_sink_sent_messages`, `audit_sink_dropped_messages`, `audit_sink_disconnect_loss_events`, `audit_sink_reconnect_attempts_exhausted` and `audit_sink_pending_bytes`. Tracks at most 64 sources, requires nonnegative values, fresh ordered UTC samples, and treats dropped/disconnect loss, reconnect exhaustion, counter resets and sample reorders as sticky loss needing operator review; pending bytes produce a backlog state. Metric source transport is **not authenticated by this model**; sending counters does not prove receipt, no drop delta is not complete coverage, and all states have `AlertPermitted=false`.
- `Carthago.Tests/RedisAuditMutualTlsRelayReceiverTests.cs` — source `709567d`, test hardening `25f9d04`, added missing-client-cert negative `20884fc`. Authored **9** synthetic loopback TLS tests with ephemeral RSA cert fixtures (server certificate negative added `b2c1abc`): pinned peer, wrong cert, missing cert, expired/wrong EKU pin, exact framing (including 0/oversized), malformed event, existing-intake bridge, loopback-only enforcement; all must fail-closed and never authorize R437. `Carthago.Tests/RedisAuditSinkMetricsHealthTests.cs` — source `abc6c85`, authored **5 Facts and 1 Theory (3 parameter cases)** for loss/backlog/counter reset/source freshness and capacity. No original Redis capture, no commercial infrastructure, no real keys stored.
- Existing `scripts/verify-redis-software-audit-ga.ps1` updated `2ff914b` to include the new mTLS relay tests and sink-metrics tests in the targeted gate while preserving full test exit-code enforcement, exact SHA and separate TRXs. **Authored only; not executed in this GA.**
- New detailed operator contract `docs/GA_R437_REDIS_MTLS_RELAY_20261102.md` `76f54b2`, hardened `d855e30` and `1d7083d`: local-only TLS relay architecture, required external source-forwarder and cryptographic identity provisioning, privacy, metric-source trust, current limitations, exact owner test-time command and future independently labeled detection-quality gates.

**Important integration/deployment constraints:** Redis Software's native TCP sink does **not** speak the relay's mTLS/length-prefix protocol; the externally managed forwarder is **not shipped or deployed** in this GA. Source-identity proof before the forwarding relay, framing native Redis events, protection of original command status, producer loss metrics and user/ACL provenance remain open. A pinned client TLS certificate proves control of a relay key, **NOT** the Redis daemon, exact `CONFIG SET` subcommand or a shared unique command transaction. No automatic feed is connected to R437, no audit JSON is converted to a signed `RedisConfigSetCommandSucceeded` claim and no synthetic fixture is represented as a true positive. Original-source and source metrics authenticated transport remain independent open gates.

**Next owner-authorized Windows validation:** From a clean existing feature branch, run `& .\scripts\verify-redis-software-audit-ga.ps1`. It performs fast-forward and exact Git SHA, Release build before `--no-build`, a targeted filter including `RedisAuditMutualTlsRelayReceiverTests`, `RedisAuditSinkMetricsHealthTests`, existing Redis vendor/capture/signed-audit and R561/R562 tests, then the complete Release xUnit suite with new separate TRX files. On any nonzero exit, record honest RED/ABORTED, do not waive failing TLS or detection assertions. Store owner-provided actual compiler warnings and count. Newly authored tests are not part of the 9,870/9,870 previously verified SHA; **do not predict a new count**.

**GA disposition:** SOURCE CANDIDATE — UNVERIFIED. Frozen holdout V1 historical FAILED 4/6 immutable, V2 PENDING_EXTERNAL_CAPTURE_AND_REVIEW with 0 approved. R437 still non-alerting; R561/R562 Candidate Shadow. R102 80%, R118 86%, R163 84%, R437 82%, R561 86%, R562 88% confidence floors unchanged. No new rules, branches, replay-label alterations or CI execution. Next practical engineering gate is an operator-managed, authenticated **original Redis audit source** and relay deployment with trusted delivery metrics, then unique transaction binding and independent TP/FP/FN/TN measurement.

**Protocol/transport sources:** Redis Software auditing and audit_sink_* metrics https://redis.io/docs/latest/operate/rs/security/audit-events/ ; Microsoft SslStream mutual-TLS authentication https://learn.microsoft.com/en-us/dotnet/api/system.net.security.sslstream.authenticateasserverasync ; Microsoft cancellable TcpListener https://learn.microsoft.com/en-us/dotnet/api/system.net.sockets.tcplistener.accepttcpclientasync .


### 2026-11-03 — Existing R286 LDAP / R485 BACnet trusted packet request enhancement (SOURCE CANDIDATE — UNVERIFIED)

**Intent and base:** On the existing `feature/carthago-reliability-hardening` branch, source preparation began at `3481d48e60a7b9c441092987e61f5f221b64584c` without test/build execution. This is an evidence-first enhancement to **existing R286 and R485**, not new rule registration. There is no authorization to run tests yet; do not infer compile success, RED/GREEN, detection precision/recall or production alert eligibility. The prior independently owner-Windows verified full regression remains **9,870/9,870 at 6099bfa**, not a validation of this candidate.

**R286:** The existing bounded `LdapMessageInspector` is extended with `TryInspectSimpleBind` for exactly one complete LDAPv3 BER [APPLICATION 0] request, nonempty DN and nonempty simple-authentication OCTET STRING. Anonymous, SASL, unknown/extra controls, invalid lengths/version, coalesced and truncated messages fail closed. It returns only message ID, byte count and presence flag; no credentials, DNs or payloads are retained. `PacketHandler` sets the new internal-setter `TrafficRecord.LdapCleartextSimpleBindObserved` only for SYN-anchored in-order first client TCP/389 plaintext payload. R286 rejects Info/port-only claims, contradictory application/HTTP/TLS fields, non-cross-boundary traffic and explicitly approved admin sources; a new match describes only a **simple bind request observed**, never login success.

**R485:** The new `BacnetWritePropertyInspector` accepts only a complete single unsegmented BACnet/IPv4 unicast BVLC 0x0a / NPDU local request / ConfirmedRequest service 15, with structurally present object/property target and one bounded scalar value, optional priority, valid length/flags; it deliberately rejects routed/broadcast/segmented/compound requests, unrelated BACnet services, malformed bounds and incomplete messages. No property identifiers, object values or raw contents are retained. `PacketHandler` sets internal-setter `BacnetWritePropertyRequestObserved` only on source-to-destination UDP/47808 request direction, and R485 requires the flag plus cross-boundary record coherence. An observed **request does not mean a device accepted or executed a write**.

**Fail-safe policy:** Existing R286 minimum confidence **78%** and R485 **86%**, threshold 1, windows 20/10 minutes, cooldowns 20/45 minutes, existing `DefaultMode=Alert` profile metadata (historically asserted by xUnit) and IDs remain. Their newly produced candidate events are forcibly marked `DetectionSuppressionStatus.Shadowed` before the engine, including when a user has a permissive tuning profile; existing engine Core prioritizes `Shadowed` over Alert delivery. The two profiles' source maturity is recorded as Candidate. An independent static review found that the engine resets a plain `Suppressed` event to None during preparation; duplicate/cooldown results now return `RuleEvaluationResult.SuppressedMatch` with no event so they cannot page. Precision `RequiredFields` now have capture-flag-backed `HasField` recognition. No new unconditional trust in imported JSON/Info/protocol labels; original malicious replay expectations and explicit missed-positive diagnoses remain for the old JSON-only samples.

**Tests AUTHORED, NEVER EXECUTED IN THIS GA:** `LdapMessageInspectorTests`, new `LdapSimpleBindCaptureIntegrationTests`, new `BacnetWritePropertyInspectorTests`, extended `BacnetWritePrecisionTests`, new `R286R485ShadowEnginePreparationTests`. Synthetic BER and BACnet frames cover positives; anonymous/SASL/LDAPS, wrong port/direction, missing TCP SYN/sequence, fragmented/truncated IP and 4 KiB clipped TCP, malformed/coalesced, BACnet ReadProperty/WritePropertyMultiple/segmentation, BACnet same-port requests, invalid REAL/NULL/Boolean/reserved tags, internal-only boundary, JSON flag forgery, non-secret telemetry, precision-field admission, engine preparation preserving Shadow and cooldown returning a suppressed result without events. Existing `R286AdvancedAccuracyBatchTests`, `R275R343R485PairedReplayTests` and `TuningBenchmarkTests` remain unchanged; only stale commentary in `NetworkBatch481490AccuracyTests` changed. Historical negative/evidence boundaries preserved.

**Next explicit owner test-time window only:** From an exact clean feature SHA, run `dotnet build -c Release`; targeted `dotnet test Carthago.Tests/Carthago.Tests.csproj -c Release --no-build --filter "FullyQualifiedName~LdapMessageInspectorTests|FullyQualifiedName~LdapSimpleBindCaptureIntegrationTests|FullyQualifiedName~BacnetWritePropertyInspectorTests|FullyQualifiedName~BacnetWritePrecisionTests|FullyQualifiedName~R286R485ShadowEnginePreparationTests|FullyQualifiedName~R286AdvancedAccuracyBatchTests|FullyQualifiedName~NetworkBatch481490AccuracyTests|FullyQualifiedName~R275R343R485PairedReplayTests|FullyQualifiedName~TuningBenchmarkTests" --logger "trx;LogFileName=r286-r485-targeted.trx"`, then full xUnit regression with separate TRX and exact commit. Record any genuine compile/test regressions as RED until corrected. Do not run live capture, holdouts, or claim independent TP/FP/FN/TN from these synthetic contracts. Frozen V1 historical FAILED 4/6, V2 pending external source approval/0, R102 80% / R118 86% / R163 84% floors and other rule policy unchanged.

### 2026-11-03 — GA existing R486 BACnet DeviceCommunicationControl disable-request enhancement (SOURCE CANDIDATE — UNVERIFIED)

**Scope:** Existing feature branch at published base `a61b1b2`; enhance **R486**, which previously accepted no operation without a trusted producer. No new ID, separate detector engine or protocol research catalogue. Reuse the recently published BACnet/IP live-packet route and existing OT rules. A new strictly bounded `BacnetDeviceCommunicationControlInspector` recognizes only a **complete unsegmented Original-Unicast BVLC/NPDU ConfirmedRequest service 17**, with context `[1]` ENUMERATED disable (1) or disable-initiation (2), and optionally a 1–2-octet context `[0]` duration. Original-Unicast is a BVLC function designation, not independently verified transport unicast; directed-broadcast classification requires interface subnet data. The first iteration deliberately **does not claim coverage for password-bearing requests**; it rejects them pending complete BACnet character-string validation. No password or raw message field is retained. An observed request does not establish device authorization, acceptance, failed/successful service outcome or actual traffic disruption.

**Capture and rule binding:** `PacketHandler` requires a complete captured IPv4/UDP datagram, no fragmented IP, destination 47808 and validated DCC APDU. BACnet/IPv6 Annex U uses a different BVLC layout; the producer rejects all IPv6 datagrams carrying Annex J 0x81 framing (and the same origin-binding correction applies to R485). Standard same-port UDP/47808 requests are supported. The internal-setter `TrafficRecord.BacnetDeviceCommunicationDisableObserved` is not a JSON-importable attestation. `RulePrecisionCatalog` recognizes a coherent capture-only required field. R486 checks the exact flag, verified application protocol, UDP destination and cross-boundary, failing closed on text/port-only metadata. Existing R486 **86%** confidence floor, threshold 1, 10-minute window, 45-minute cooldown and historical default Alert metadata remain; actual candidates are always marked **Shadowed**. Cooldown returns `SuppressedMatch` with no event before engine preparation.

**Source tests AUTHORED ONLY:** New `BacnetDeviceCommunicationControlInspectorTests` and `BacnetDeviceCommunicationControlCaptureTests`: synthetic unicast DCC disable and disable-initiation, finite/indefinite duration, same-port request, enable-only negative, non-DCC service and R485 non-overlap, segmentation/broadcast/reserved flags, malformed lengths/tags and password variant, truncated IP capture, missing boundary/direction, forged JSON Info, privacy, cooldown, precision-catalog and engine-Shadow preparation. **No build or tests executed** at this GA. Static code review cannot establish correctness, performance, precision or recall. Existing descriptor-only replay positives must remain marked missing trusted evidence rather than being relabeled.

**Next owner test-time only:** From exact feature SHA, Release build, targeted xUnit filter `FullyQualifiedName~BacnetDeviceCommunicationControlInspectorTests|FullyQualifiedName~BacnetDeviceCommunicationControlCaptureTests|FullyQualifiedName~NetworkBatch481490AccuracyTests|FullyQualifiedName~BacnetWritePrecisionTests|FullyQualifiedName~R286R485ShadowEnginePreparationTests`, then full Release regression in separate TRX. Report actual counts and any RED honestly. Do not run either holdout, live capture or CI; V1 frozen historical 4/6, V2 pending independent external source approval 0, R102/R118/R163 floors 80%/86%/84% unchanged.

**Technical primary source:** ASHRAE/BACnet DeviceCommunicationControl-Request fields and service semantics: https://bacnet.org/wp-content/uploads/sites/4/2022/08/Add-2001-135a.pdf .

### 2026-11-03 — Owner-reported Windows Release full-suite verification at `ceb13f9` (GREEN — TEST SUITE ONLY)

**Provenance:** The owner supplied the PowerShell transcript from `C:\Users\afiay\Documents\Projects\Carthago-Network-Security-Monitor` after `git pull --ff-only origin feature/carthago-reliability-hardening` advanced `35e08d5..ceb13f9`. No independent test run was performed by the documentation editor. The exact full 40-character SHA was not printed in the transcript; `ceb13f9` is the short branch commit shown by the pull context, so the outcome is attributed to that reported checkout, not to any subsequent automation commit.

**Executed command (owner local):** `dotnet test DOTNET.sln -c Release --logger "trx;LogFileName=carthago-full.trx"`. Restore completed; the Carthago application and Carthago.Tests projects both compiled. xUnit discovery and execution completed successfully: **total 10,443; passed 10,443; failed 0; skipped 0**; test duration 96.6 s, end-to-end build/test command reported 126.7 s. The transcript names `Carthago.Tests\TestResults\carthago-full.trx` as the results file and warns that this existing file was overwritten; this local TRX was not committed or independently inspected. Console informational messages included a failed-to-load incident-feedback JSON fallback and an intentionally failing sink diagnostic, neither of which caused a test failure.

**Scope boundary:** GREEN applies to the reported Release solution test run at the stated checkout. It does **not** certify every individual R-series rule's producer reachability, missed-positive coverage, false-positive rate, live packet-capture performance, frozen holdout, or later source revisions. Preserve per-rule **SOURCE CANDIDATE — UNVERIFIED** claims until their specific evidence requirements are met. Frozen holdout V1 and V2 artifacts remain unchanged; all earlier RED/GREEN and zero-execution entries remain historical evidence rather than being retroactively rewritten.

### 2026-11-03 — Owner-reported Windows Release full-suite verification at `ca53c9f` (GREEN — TEST SUITE ONLY)

**Provenance:** The owner supplied a PowerShell transcript from `C:\Users\afiay\Documents\Projects\Carthago-Network-Security-Monitor`. A successful `git pull --ff-only origin feature/carthago-reliability-hardening` advanced the checkout `c6c7317..ca53c9f` and changed `Carthago/Engine/Rules/Expansion/Research676Evidence.cs`. The transcript did not independently print `git rev-parse HEAD`; this result is associated with the reported short checkout SHA, not with subsequent commits. No test was run by the documentation editor.

**Executed command (owner local):** `dotnet test DOTNET.sln -c Release --logger "trx;LogFileName=carthago-full.trx"`. Restore completed, and both Carthago and Carthago.Tests compiled successfully. xUnit reported **10,539 total; 10,539 passed; 0 failed; 0 skipped**, 87.2 s test duration, 87.3 s test-project execution and 120.1 s overall build/test duration. The TRX was saved to `Carthago.Tests\TestResults\carthago-full.trx` in the owner's Windows checkout, overwriting the previous local results file. This TRX was not independently inspected or committed. Console diagnostics noted a failing test sink and incident-feedback JSON fallback, but they did not fail the suite.

**Interpretation:** This is a new, distinct reported GREEN Release regression result at `ca53c9f`; the earlier **10,443/10,443** result at `ceb13f9` remains unchanged and is not superseded as historical evidence. Neither run alone proves per-rule live producer reachability, detection accuracy, independent holdout outcomes, performance under capture load, or correctness of later branch revisions. Preserve all rule-specific **SOURCE CANDIDATE — UNVERIFIED** and frozen holdout boundaries until separately verified.


### 2026-11-03 — Owner Windows verification session at pinned source `b546081`, followed by Holdout V2 contract hardening

**Execution provenance:** The owner executed the commands locally on Windows from `C:\Users\afiay\Documents\Projects\Carthago-Network-Security-Monitor` on the existing `feature/carthago-reliability-hardening` branch. The principal pinned source checkpoint for the broad regression/accuracy work was `b54608185bdda4a8f34194450ecbff8b3055ec75`. Later source-only fixes were committed to the same branch as described below. No result is attributed to a later commit unless the owner explicitly reran that gate after pulling it.

**Broad regression and accuracy gates at `b546081`:**
- Release solution/xUnit regression: **10,569 / 10,569 PASS**, 0 failed, 0 skipped.
- Targeted deployment-state/accuracy filter: **7,881 / 7,881 PASS**.
- Deployment-policy isolation: **666 / 666 PASS**.
- Noisy-rule isolation for R012/R032/R034/R095/R102/R113/R118/R163: **387 / 387 PASS**.
- Evidence/replay-policy isolation: **38 / 38 PASS**.
- Producer-gap isolation for R275/R295/R343/R437/R508/R516: **55 / 55 PASS**.
- Replay benchmark: 146 samples; 42 supported malicious, 6 explicitly unsupported malicious; supported-detector TP recognition **100%** and benign false positives **0**. Alert-level recall remained policy/shadow/environment gated and is not an accuracy failure. Existing floors R102 80%, R118 86%, R163 84% were preserved.

**Redis audit GA at `b546081`:** targeted Redis audit GA completed **142 / 142 PASS** and the script-internal full regression completed **10,569 / 10,569 PASS**. One earlier run had a single transient timeout in `RedisAuditMutualTlsRelayReceiverTests.Pinned_Mtls_Receives_Two_Length_Framed_Events_Without_Retaining_Json`; the exact test then passed **5 / 5** consecutive repetitions, and the subsequent complete Redis GA rerun was fully GREEN. No production-code change was made solely for the transient timeout.

**Rule-source inventory:** `verify-rule-source-inventory-contract.ps1 -AuthorizedTestTime` passed. Manual execution of the inventory core at `b546081` reported **695 registered rules**, **5,877 test declarations**, **52 MemberData bindings**, **29 diagnostics**, with 22 `UNSUPPORTED_SOURCE_SYNTAX` and 7 `REGISTERED_CLASS_UNRESOLVED`. The seven unresolved IDs were R104/R180/R205/R211/R212/R214/R215. Git object inspection proved all seven registered classes exist at the pinned SHA; each was excluded only because the conservative parser intentionally refuses complex interpolated-string syntax. Targeted rule execution for those seven was **86 / 86 PASS**, hardening audit reported **0 contract issues**, and no replay fixtures existed for those seven IDs. The seven test files hidden by unsupported parser syntax were then executed directly: **133 / 133 PASS**.

**Confirmed inventory wrapper defect and fix:** `inspect-rule-source-inventory.ps1` incorrectly used `-match '\.cs'` in its rejection fallback, causing `Carthago.Tests.csproj` to be misclassified as a C# source path. This was confirmed against the live branch and fixed on the same branch so only terminal `.cs` paths reach that fallback. The repaired live branch was re-read after publication; do not treat the earlier wrapper exception as a source-tree defect.

**Holdout V2 synthetic/read-only contract results:** V1 remained untouched and historically FAILED 4/6. V2 readiness correctly remained `PENDING_EXTERNAL_CAPTURE_AND_REVIEW`, **0/4 external R102 source/provenance pairs present**.
- `SyntheticHoldoutV2ContractTests`: **9 / 9 PASS**.
- `inspect-holdout-v2-readiness.ps1`: read-only status **0/4**, pending as designed.
- `verify-v2-two-writer-race-contract.ps1 -AuthorizedTestTime -IncludeReaderVisibility`: **6/6 rounds**; each round produced exactly one `WIN` and one `TARGET_EXISTS`; reader observed absent/complete only, no partial view.
- `verify-v2-provenance-schema-contract.ps1 -AuthorizedTestTime`: **2 structurally valid pending-review controls + 24 negative cases PASS**.
- `verify-v2-atomic-publication-contract.ps1 -AuthorizedTestTime`: PASS — 1 pending-only control, 8 precommit rollbacks, 1 uncertain commit, 1 existing target, 4 unsafe-name cases and 3 invalid batches.
- `verify-v2-recovery-planner-contract.ps1 -AuthorizedTestTime`: **15 / 15 advisory recovery scenarios PASS**.

**V2 auditor enforcement — observed RED/fix sequence:** The first authorized auditor-enforcement run stopped before scenario evaluation because the live auditor generated invalid TShark set syntax `frame.number in { 1 2 3 }`. The live branch was checked before editing and fixed to comma-separated membership `{ 1, 2, 3 }`. After owner pull, the rerun reached scenario logic: `BASELINE` and `A13` passed, then **A01 failed the contract because the legacy auditor accepted mirrored malicious evidence instead of rejecting with `SOURCE_INDEPENDENCE_MIRROR`**. The verification contract and V2 protocol explicitly require source/session/origin independence beyond distinct IP addresses, so the live auditor was updated at `9c10a8b2cccef116bb67a65229bae8a13b23ae8f` to add privacy-safe enforcement for mirrored malicious evidence, malicious session/origin collisions, missing origin/session, invalid vantage, invalid review-field type and unexpected provenance fields.

**Current status after source fix:** the new auditor enforcement at `9c10a8b2cccef116bb67a65229bae8a13b23ae8f` is **SOURCE CANDIDATE — UNVERIFIED until the owner reruns `verify-v2-auditor-enforcement.ps1 -AuthorizedTestTime` after pulling that commit**. Do not retroactively mark the auditor gate GREEN. Do not run `evaluate-holdout-v2.ps1`, packet audit against real external captures, or freeze V2 while readiness remains 0/4. Frozen V1, rule confidence floors and prior historical outcomes remain unchanged.


#### 2026-11-03 — V2 auditor rerun after independence enforcement: expected A01 code reached, verifier harness blocked

After owner pull to the branch containing the new auditor independence checks, `verify-v2-auditor-enforcement.ps1 -AuthorizedTestTime` again completed `BASELINE` and `A13` successfully. The child auditor then emitted the expected privacy-safe rejection `SOURCE_INDEPENDENCE_MIRROR` for A01. However, the parent verifier did **not** complete the scenario matrix: Windows PowerShell surfaced child stderr as `NativeCommandError`, and the verifier's global `$ErrorActionPreference='Stop'` terminated the parent at the native invocation boundary before it could inspect `$LASTEXITCODE` and match the expected reason.

**Classification:** auditor behavior for A01 reached the expected rejection code, but the overall auditor-enforcement gate remains **BLOCKED / NOT GREEN** because the harness aborted before completing A01 bookkeeping or any later negative cases. This is a verifier harness defect, not evidence that the source-independence check failed.

The live branch was checked before editing. Commit `ecc261d72649fd0b323c5a50712ce941476aca91` narrows the fix to the child-process invocation: it temporarily sets `$ErrorActionPreference='Continue'` only while invoking the expected-to-fail child auditor, captures `$LASTEXITCODE`, restores the prior preference in `finally`, and preserves the existing private-log inspection and exact-reason checks. No auditor policy, V1/V2 fixture, rule confidence floor or holdout approval state changed.

**Required next observation:** owner must pull `ecc261d7` or later and rerun only `verify-v2-auditor-enforcement.ps1 -AuthorizedTestTime`. Do not mark Stage 6 auditor enforcement GREEN until the full synthetic matrix completes with the expected exit category and reason for every case.


#### 2026-11-03 — V2 auditor rerun advanced through A04; A06 hit wrong rejection path

After pulling the verifier harness fix, the owner reran `verify-v2-auditor-enforcement.ps1 -AuthorizedTestTime`. The focused harness advanced substantially:
- `BASELINE`: expected category/reason PASS.
- `A13`: expected category/reason PASS.
- `A01`: expected `SOURCE_INDEPENDENCE_MIRROR` PASS.
- `A01-case`: expected `SOURCE_INDEPENDENCE_MIRROR` PASS.
- `A02`: expected `SOURCE_SESSION_COLLISION` PASS.
- `A03`: expected `SOURCE_ORIGIN_COLLISION` PASS.
- `A04`: expected same-original-frame reuse rejection PASS.
- `A06`: **rejected, but for an unexpected reason; harness correctly refused to count it as RED or GREEN**.

Live-branch inspection showed the A06 fixture changes one serialized QNAME to `tampered.example`. The auditor was performing the malicious three-distinct-long-TXT eligibility check **before** comparing serialized records to selected original PCAP frames. That caused the tampered record to lose the required long-label shape and hit the semantic eligibility rejection before the contract's intended `serialized record differs from decoded PCAP` provenance-binding path. The same ordering could also intercept A08-qtype.

The Stage 6 contract explicitly defines A06 and A08-qtype as original-PCAP binding controls. Commit `d637df90e904d8386d995253bced9ca991e0510d` therefore reorders only the malicious long-TXT eligibility check so it runs **after every selected serialized record has been verified against its original PCAP frame**. Existing schema, hash, frame-reuse, transport, source-independence, expected-match and privacy checks remain fail-closed. This is a trust-ordering correction: untrusted serialized packet semantics are no longer used for the long-TXT eligibility decision before packet binding.

**Current gate:** PARTIAL GREEN through A04; A06 prior run is INVALID FOR RED/GREEN due wrong rejection reason. Full auditor-enforcement matrix must be rerun after pulling `d637df90` or later. V2 remains PENDING_EXTERNAL_CAPTURE_AND_REVIEW with 0/4 real external pairs; V1 remains immutable.


#### 2026-11-03 — V2 auditor rerun GREEN through A10-session; A11 wrong-reason mismatch

After pulling the A06/A08 ordering correction, the owner reran `verify-v2-auditor-enforcement.ps1 -AuthorizedTestTime`. The focused harness matched the expected exit category and reason for:
`BASELINE`, `A13`, `A01`, `A01-case`, `A02`, `A03`, `A04`, `A06`, `A08-qtype`, `A08-port`, `A09`, `A09-missing`, `A10`, `A10-origin`, and `A10-session`.

The next case, `A11`, rejected but for an **unexpected reason**. The harness correctly stopped and did not count A11 as RED or GREEN. The owner-visible transcript did not expose the actual stable rejection category because the verifier intentionally retained the private child log.

Live-branch inspection showed the A11 fixture only changes `analystReviewedLabel` from true to false, while the contract expects the generic `incomplete external attribution or label review` rejection. Because the actual reason was not observable from the sanitized parent output, no auditor behavior was changed by inference.

Commit `27f3fa8357ba81ec58bfb9466c13505951eea23e` updates only the verifier harness:
- adds a bounded `-OnlyScenario` selector for the existing fixed synthetic scenarios;
- adds a hardcoded safe-reason classifier containing only contract reason strings;
- on mismatch, reports `expected=<safe reason> actual=<safe reason or UNRECOGNIZED_SANITIZED_REASON>` without publishing the private child log.

**Current gate:** GREEN through A10-session. A11 remains INVALID FOR RED/GREEN pending one focused `-OnlyScenario A11` diagnostic run. No V1/V2 fixtures, auditor policy, source approval or confidence floor changed.


#### 2026-11-03 — A11 focused diagnostic: auditor path correct, verifier reason matcher formatting-blocked

The owner pulled the focused-diagnostic verifier and ran only `A11` with `-OnlyScenario A11`. The harness reported:
`expected=incomplete external attribution or label review actual=UNRECOGNIZED_SANITIZED_REASON`.
This result is **not RED or GREEN**.

Live-branch inspection established the exact A11 control flow without inference: the fixture changes only `analystReviewedLabel` from boolean true to boolean false. The auditor's type guard accepts boolean false, then the subsequent external-attribution/review condition necessarily rejects `-not $p.analystReviewedLabel` with the intended `incomplete external attribution or label review` message before packet-dependent checks. Therefore no auditor policy change was justified.

The verifier captured the child through Windows PowerShell's formatted native-error stream and matched known reason strings as contiguous text. Line wrapping/whitespace inserted by PowerShell formatting can split a known reason across lines, producing `UNRECOGNIZED_SANITIZED_REASON` even when the underlying auditor throw is the expected one. Commit `551f3fd8d7d72ba232840f3d6bcc760ef0166d3e` changes only verifier reason matching: it normalizes whitespace on a copy of the private log before comparing against the fixed allowlist. The original private log remains unchanged for privacy scanning; no raw packet/provenance content is surfaced.

**Current gate:** GREEN through A10-session. A11 remains **pending focused rerun** after pulling `551f3fd8`. No V1/V2 fixture, source approval, detector policy, or confidence floor changed.


#### 2026-11-03 — A11 focused rerun GREEN after verifier reason normalization

The owner fast-forwarded the existing feature branch to `6e87e37babde4996b05d7798e8be96c679f6f370` and reran only:
`verify-v2-auditor-enforcement.ps1 -AuthorizedTestTime -OnlyScenario A11`.

Observed result:
- `AUDITOR CONTRACT: A11 observed expected exit category and reason; private output checked.`
- `Focused auditor scenario completed: A11. No source approved or holdout frozen.`

**Classification:** A11 is now **GREEN** for the synthetic auditor-enforcement contract. The prior `UNRECOGNIZED_SANITIZED_REASON` was confirmed as a verifier formatting issue, not an auditor-policy defect. No V1/V2 fixture, source approval, freeze state, detector confidence floor or production alert policy changed.

**Cumulative Stage 6 progress:** GREEN now includes `BASELINE`, `A13`, `A01`, `A01-case`, `A02`, `A03`, `A04`, `A06`, `A08-qtype`, `A08-port`, `A09`, `A09-missing`, `A10`, `A10-origin`, `A10-session`, and `A11`. Remaining synthetic cases have not yet been re-observed in this owner session and must not be inferred GREEN.


#### 2026-11-03 — Five remaining auditor cases GREEN; A16-distinct diagnostic still blocked by child-output formatting

After pulling the latest focused verifier, the owner executed the remaining scenarios individually with fail-fast control.

Observed GREEN:
- `A11-review-type`
- `A11-license`
- `A12`
- `A12-provenance`
- `A14`

Each printed `observed expected exit category and reason; private output checked` followed by the focused-completion statement.

`A16-distinct` rejected, but the verifier reported:
`expected=R102 malicious encoded-TXT requires three distinct captured TXT actual=UNRECOGNIZED_SANITIZED_REASON`
and correctly stopped without counting the case RED or GREEN.

Live source review confirmed the A16 fixture keeps the PCAP and serialized JSON aligned while deliberately repeating the third long TXT name in malicious slot 2. It therefore remains a semantic distinct-name control rather than a serialized/PCAP mismatch. The auditor also performs selected-frame binding before the long-TXT cardinality check. Because the actual child reason was still not recoverable from the PowerShell-formatted combined stream, no auditor policy was changed by inference.

Commit `f8cfbb09d9ff106cce5c4e7360243337a9ea312a` changes only the verifier process-capture boundary: child output is captured as objects in memory, `ErrorRecord.Exception.Message` is extracted before PowerShell formatting can wrap/annotate it, then the normalized private log is written to the existing ephemeral file and passed through the same privacy assertions. The fixed reason allowlist and auditor behavior are unchanged.

**Current cumulative Stage 6 status:** every synthetic scenario except `A16-distinct` is GREEN in this owner session. A16 remains pending one focused rerun after pulling the capture fix. V2 remains 0/4 external reviewed pairs and unfrozen; V1 remains immutable.


#### 2026-11-03 — Stage 6 V2 synthetic auditor-enforcement matrix cumulatively GREEN

The owner pulled live branch revision `303f31db32814887679958cf18a69135b693dee3` and ran the final remaining focused scenario:
`verify-v2-auditor-enforcement.ps1 -AuthorizedTestTime -OnlyScenario A16-distinct`.

Observed result:
- `AUDITOR CONTRACT: A16-distinct observed expected exit category and reason; private output checked.`
- `Focused auditor scenario completed: A16-distinct. No source approved or holdout frozen.`

**A16-distinct is GREEN.** This closes the last unresolved Stage 6 synthetic auditor-enforcement case.

Across this authorized owner session, the complete scenario set now has observed GREEN results: `BASELINE`, `A13`, `A01`, `A01-case`, `A02`, `A03`, `A04`, `A06`, `A08-qtype`, `A08-port`, `A09`, `A09-missing`, `A10`, `A10-origin`, `A10-session`, `A11`, `A11-review-type`, `A11-license`, `A12`, `A12-provenance`, `A14`, and `A16-distinct`.

**Evidence boundary:** this is a cumulative GREEN record across successive exact branch revisions during one authorized test session, not a claim that all scenarios were rerun in one monolithic invocation at `303f31d`. Subsequent verifier-only fixes were used to resolve harness/error-formatting defects; the historical intermediate failures remain recorded above. No external source was approved, no V2 candidate was frozen, no real PCAP source/license/privacy review was completed, and no detector precision/recall claim follows from this synthetic contract closure.

V2 remains `PENDING_EXTERNAL_CAPTURE_AND_REVIEW` with **0/4 reviewed external R102 source/provenance pairs**. Frozen V1 remains historically FAILED 4/6 and immutable. Confidence floors remain unchanged.


#### 2026-11-03 — DNS wire-source + V2 provenance + Stage 8 replay bridge GREEN at `2642ea3`

The owner fast-forwarded the existing `feature/carthago-reliability-hardening` branch to `2642ea3b6fa214e3227e8998ea8809f18891cdc8` and executed:

`verify-dns-wire-source-contract.ps1 -TsharkPath 'C:\Program Files\Wireshark\tshark.exe' -IncludeV2Provenance -IncludeReplayCompatibility -AuthorizedTestTime`

Observed output was fully GREEN across all enabled synthetic contract layers:

- DNS TCP framing: unmodified UDP and exact TCP payload preserved; **5 invalid length prefixes rejected**.
- TShark `jsonraw` descriptor compatibility: valid 5/6-member formats preserved; **10 ambiguous/invalid descriptors rejected**.
- Core DNS wire-source binding: **4 source-bound questions corroborated; 5 invalid/ambiguous selections rejected**.
- V2 record schema: **1 exact layout accepted; 4 malformed layouts rejected**.
- V2 frame/question binding: **2 source-bound records verified; 19 tampering/missing-original cases rejected**.
- V2 logical-source contract: **7 mirror/overlap/session/origin/frame-reuse/non-ASCII review scenarios completed; no source auto-approved**.
- Stage 8 replay bridge unit compatibility: **2 exact printable names accepted; 10 non-lossless names rejected**.
- Stage 8 replay bridge original-source binding: **3 original frame/question records bound; 11 source/schema/binary/review-state negatives rejected**; no projected samples or approvals.

**Classification:** GREEN for the synthetic DNS wire-source, V2 provenance/source-independence and replay-compatibility contracts at the owner-reported checkout. This verifies bounded source/frame/question binding, wire-name losslessness checks, strict pending-only replay compatibility and negative-control sensitivity. It does **not** approve a real external source, establish source rights or label truth, evaluate R102 precision/recall, freeze V2, or modify frozen V1.

V2 remains `PENDING_EXTERNAL_CAPTURE_AND_REVIEW` with **0/4 reviewed external pairs**. Frozen V1 remains immutable. R102/R118/R163 confidence floors remain 80%/86%/84%.


#### 2026-11-03 — R343 Windows audit readiness: non-elevated access remains unverified

The owner pulled live branch revision `2a472f16ae317716127de03a78199eeddd3c145f` and ran the read-only command:
`inspect-winrm-audit-readiness.ps1 -InspectAuditPolicy -InspectRecentEvents -LookbackMinutes 30`.

Observed sanitized result:
- Elevated administrator token: **False**.
- Windows Event Log service: **Running**.
- 4688 include-command-line local policy value: **NOT SET**.
- Process Creation success-audit policy: **UNKNOWN (OTHER_ERROR (RemoteException; 0x80131501))**.
- Security channel metadata: **ACCESS_DENIED**.
- Security 4624/4688 queries: **NO MATCHES REPORTED (log access unverified)**.
- Final status: **ACCESS UNVERIFIED**.

**Interpretation:** this run does not establish that Security auditing is disabled, that 4624/4688 are absent, or that R343 source code is defective. The current PowerShell token lacks enough access to verify the Security channel/audit-policy state. No Windows setting, ACL, event, registry value, detector policy or confidence floor was changed.

Historical Stage 1 remains valid and separate: an earlier authorized elevated CARTHAGE lab proved 4688 PID/image-path correlation and then restored Process Creation auditing to `No Auditing`. Do not re-enable auditing merely to repeat that already-closed lab gate. The next current-state check is an already-authorized elevated **read-only** rerun of the same readiness script.


#### 2026-11-03 — R343 elevated current-state readiness confirmed: OS telemetry BLOCKED, Security access verified

From an already-authorized elevated Windows PowerShell session, the owner ran:
`inspect-winrm-audit-readiness.ps1 -InspectAuditPolicy -InspectRecentEvents -LookbackMinutes 30`.

Observed sanitized result:
- Elevated administrator token: **True**.
- Windows Event Log service: **Running**.
- 4688 include-command-line local policy value: **NOT SET**.
- Process Creation success-audit policy: **NO AUDITING**.
- Security channel metadata: **READABLE**.
- Security 4624 in the last 30 minutes: **OBSERVED (event ID only)**.
- Security 4688 in the last 30 minutes: **NO MATCHING EVENTS**.
- Final status: **BLOCKED — Process Creation success auditing is disabled; fresh Security 4688 evidence is not expected**.

**Classification:** environment/producer prerequisite BLOCKED, not a Carthago regression. This elevated run resolves the prior non-elevated `ACCESS UNVERIFIED` state: Security-log access is available under the authorized administrator token, but the effective Windows Process Creation success-audit subcategory is currently disabled. The absent recent 4688 event is therefore consistent with the effective policy.

Historical Stage 1 remains closed and valid: CARTHAGE previously enabled Process Creation auditing in a controlled lab, correlated a harmless local process to a 4688 event by PID/image path, and restored the setting to `No Auditing`. No reason exists to repeat that already-closed lab gate unless a new explicitly authorized producer experiment requires it.

No Windows policy, command-line logging, ACL, registry setting, detector behavior, confidence floor, holdout fixture or alert mode was changed by this read-only check.

#### 2026-11-03 — R275 trusted IdP audit candidate boundary authored

A new R275 producer-side candidate boundary was authored directly on `feature/carthago-reliability-hardening` after the current producer-gap review.

Source commits in this increment:
- `7f6b2084737394ee08d928bc12fe6307f6f1e18c` — non-alerting R275 IdP audit candidate gate.
- `760023b8c8040405674a8b9801c6fdaa18c6899f` — signed R275 IdP audit intake.
- `33da7bbc926f94bd8bcc15fbc6512220490e2566` — focused synthetic R275 trust-boundary tests.
- `53ac27caf6d53d09b614bdfe573f8f939059cbec` — require identity-web packet context in addition to endpoint/time binding.
- `2f78eaeea3cf50df1ec957c1a9a0e484945c02db` — cover arbitrary TCP/443 rejection.
- `80fb9384568ab673926c65dd846da6b3357327eb` — handle observed SNI/TLS-SNI/HTTP-host fields without null-coalescing ambiguity.
- `d9ea26e03f45a46c4fd575d02d2db5fbafa4dc15` — trusted IdP candidate boundary documentation.

The implementation reuses the existing `TrustedAuditReceiptVerifier` and `TrustedAuditReceiptCorrelation` contracts. Two independently pinned RSA-PSS issuers must attest the exact R275 operation `OAuthDeviceFlowAbuseConfirmed`, with matching privacy-minimized actor/resource/trace hashes and endpoints. The candidate gate additionally requires a captured TCP/443 HTTP/HTTPS/TLS flow with an observed host/SNI, exact endpoint agreement and a two-minute UTC clock bound.

**Fail-closed boundary:** every assessment remains non-alerting (`AlertPermitted=false`). A fully correlated candidate returns `R275_SIGNED_IDP_AUDIT_CANDIDATE_NOT_INTEGRATED`. No trusted field was added to `TrafficRecord`, `RuleEvaluationContext` remains packet-only, and R275 itself still fails closed with `TRUSTED_DEVICE_CODE_ABUSE_EVENT_UNAVAILABLE`.

**Verification status:** SOURCE CANDIDATE — UNVERIFIED. Focused tests are authored but have not yet been executed in this increment. No confidence floor, runtime mode, holdout fixture, replay classification, V1/V2 state or alert policy was changed.

#### 2026-11-03 — Microsoft Entra device-code SigninLogs intake authored for R275

A provider-facing, still-untrusted parser was added after checking Microsoft's current Azure Monitor `SigninLogs` schema.

Source commits:
- `856ae9c952df340ad19c25236c4d00483e30d50b` — strict projected `SigninLogs` parser.
- `c30c1bbf296805b0a7795a15025948d40805a6c4` — focused Entra parser tests.
- `40c3389e15be29bf0cdf415ffaae56c8b02ddb8b` — require explicit UTC timestamps.
- `e87781a6764e5489c4e82b3737c431d1224bc5ab` — cover non-UTC timestamp rejection.
- `99683f39b548228bcd5485c631924026e0273971` — portable UTC-shape check.

The parser accepts only a narrow projection of Microsoft Entra `SigninLogs`. It recognizes only successful `AuthenticationProtocol=deviceCode` events whose risk state is `confirmedCompromised` and whose risk detail is `adminConfirmedSigninCompromised`. It validates typed identifiers and source IP, hashes user/app/resource/tenant identifiers before emitting an observation, and rejects unexpected PII/token fields.

**Trust boundary:** the output remains `FromTrustedProviderTransport=false`. No Microsoft credential, Graph/Log Analytics client, trusted transport, private signing key, rule-engine wiring or alert promotion was introduced. This layer validates provider semantics only; it does not prove the JSON came from Microsoft Entra.

**Verification status:** SOURCE CANDIDATE — UNVERIFIED. The new Entra parser tests and the earlier R275 signed-candidate tests must be run together before marking this increment GREEN.

#### 2026-11-03 — R275 trusted IdP candidate verification GREEN (56/56)

The owner fast-forwarded `feature/carthago-reliability-hardening` to `5f95521611e1549cd89c20d6149ea71fc7e75b36` and executed the focused R275 verification:

`dotnet test .\Carthago.Tests\Carthago.Tests.csproj -c Release --filter "FullyQualifiedName~MicrosoftEntraDeviceCodeAuditIntakeTests|FullyQualifiedName~OAuthDeviceFlowAuditCandidateGateTests|FullyQualifiedName~R275AdvancedAccuracyBatchTests|FullyQualifiedName~R275R343R485PairedReplayTests"`

Observed result:
- Carthago build succeeded.
- Carthago.Tests build succeeded.
- **56 total; 56 succeeded; 0 failed; 0 skipped**.
- Focused test duration: 16.9 seconds; overall command completed with build success.

**Classification:** GREEN for the authored synthetic R275 provider-semantics and signed-candidate boundary.

This verifies the strict Microsoft Entra projected `SigninLogs` parser, RSA-PSS trust-anchor enforcement, replay rejection, independent-issuer correlation, endpoint/time corroboration, packet-only false-positive protections and explicit non-promotion of the candidate path into R275.

**Scope boundary:** this does not prove a live Microsoft Entra collector, tenant authentication, provider transport provenance, signing-key custody, real phishing-label truth, production alert quality or rule-engine integration. R275 remains fail-closed in normal rule evaluation until a separately reviewed trusted producer is wired through an authenticated capability path.

No confidence floor, runtime mode, holdout fixture, V1/V2 state or alert policy changed.

#### 2026-11-03 — Authenticated Azure Monitor Logs source authored for R275

After the 56/56 GREEN synthetic R275 boundary verification, the next producer increment was authored without changing R275 alert behavior.

Source commits:
- `0f40e44e9e6b5853dd012ca6317db8800c1340eb` — authenticated Azure Monitor Logs source adapter.
- `058e3219686441a2ca6ca97ba1c0dc45eba7f05b` — source-adapter contract tests.
- `1676e9726f4830dce57df2c08e1c499978cfcd44` — deterministic newest-first Entra query ordering.

The source uses the current Azure Monitor Logs data-plane endpoint `https://api.loganalytics.azure.com/v1/workspaces/{workspaceId}/query`, obtains a Microsoft Entra bearer token through an injected `Azure.Core.TokenCredential`, and requests the documented Log Analytics `.default` scope. It accepts only an operator-supplied workspace GUID and injected `HttpClient`; no credential, tenant identifier, workspace identifier or secret is committed.

The KQL is fixed and privacy-minimized, result count is capped at 100, lookback is restricted to 1–60 minutes, response size is capped at 1 MiB, the Azure Monitor table schema must exactly equal the reviewed R275 projection, and each row must still pass `MicrosoftEntraDeviceCodeAuditIntake` before it can be marked `FromTrustedProviderTransport=true`.

**Security boundary:** authenticated provider transport is not a signed R275 receipt and does not authorize a rule match. The existing non-alerting signed-candidate boundary and normal R275 fail-closed behavior remain unchanged.

**Verification status:** SOURCE CANDIDATE — UNVERIFIED. The new `MicrosoftEntraLogAnalyticsDeviceCodeSourceTests` must be executed together with the already-GREEN R275 focused suites before this increment is marked GREEN.

#### 2026-11-03 — Authenticated R275 Entra source verification GREEN (66/66)

The owner fast-forwarded `feature/carthago-reliability-hardening` to `9c0d11ad7971a9f6b272611cc870abcea74217f6` and executed:

`dotnet test .\Carthago.Tests\Carthago.Tests.csproj -c Release --filter "FullyQualifiedName~MicrosoftEntraLogAnalyticsDeviceCodeSourceTests|FullyQualifiedName~MicrosoftEntraDeviceCodeAuditIntakeTests|FullyQualifiedName~OAuthDeviceFlowAuditCandidateGateTests|FullyQualifiedName~R275AdvancedAccuracyBatchTests|FullyQualifiedName~R275R343R485PairedReplayTests"`

Observed result:
- `Carthago` build succeeded.
- `Carthago.Tests` build succeeded.
- **66 total; 66 succeeded; 0 failed; 0 skipped**.
- Focused test duration: **15.2 seconds**.
- Overall command completed with **Build succeeded** in **49.3 seconds**.

**Classification:** GREEN for the authenticated Azure Monitor Logs source adapter plus the previously verified R275 Entra parser, signed-candidate boundary, advanced accuracy controls and paired replay.

This verifies the injected `TokenCredential` contract, fixed Azure Monitor Logs endpoint and scope, bounded lookback, fixed privacy-minimized KQL, exact result-schema enforcement, sanitized HTTP failure mapping, strict Entra row parsing, RSA-PSS receipt verification, replay rejection, independent-issuer correlation, packet endpoint/time corroboration and explicit non-promotion into the live R275 rule.

**Scope boundary:** no live Microsoft Entra tenant, Log Analytics workspace, production credential, signer private key or real phishing event was used in this run. The adapter's authenticated transport path is contract-tested with injected doubles. R275 remains fail-closed in ordinary rule evaluation until a separately reviewed producer-to-signed-receipt capability is integrated.

No confidence floor, runtime mode, replay fixture classification, holdout V1/V2 state or alert policy changed.

#### 2026-11-03 — R275 authenticated Entra-to-packet claim material authored

After the authenticated Azure Monitor Logs source reached 66/66 GREEN, a separate non-signing handoff was authored to solve the provider/capture endpoint gap without fabricating data.

Source commits:
- `4a137bda4919a4120c771b4f1b741e74e51e727a` — authenticated Entra + packet claim-material builder.
- `99393288c2a1d42bbd225f5912a2987bdb5851ce` — focused claim-material tests.
- `ae75bf3401299daf201e7bdc841e03e92e6fac5f` — require HTTP/HTTPS/TLS application context in addition to TCP/443.
- `a9763e632b3e0f64dab6798e9a02c3b8ca9d4a09` — cover arbitrary 443 application-context rejection.

The builder accepts only `MicrosoftEntraDeviceCodeAuditObservation` values already marked `FromTrustedProviderTransport=true`. It binds them to independently captured identity-web traffic by exact source/client IP, explicit UTC time within two minutes, TCP/443, HTTP/HTTPS/TLS context, and an operator-supplied approved identity-host policy. The IdP destination IP is taken exclusively from the capture record because the Entra source row does not provide a trustworthy destination-IP field for this contract.

The output is privacy-minimized `MicrosoftEntraDeviceFlowClaimMaterial` only. It contains no signing key and cannot create `SignedAuditEnvelope`, `VerifiedAuditReceipt` or an R275 alert.

**Verification status:** SOURCE CANDIDATE — UNVERIFIED. The previously observed 66/66 authenticated-source GREEN remains valid; this new claim-material increment requires a focused rerun before it can be classified GREEN.

#### 2026-11-03 — R275 Entra-to-packet claim-material verification GREEN (83/83)

The owner fast-forwarded `feature/carthago-reliability-hardening` to `1d7111398bdff3a72926b7b3b181e97d2adef0e2` and executed:

`dotnet test .\Carthago.Tests\Carthago.Tests.csproj -c Release --filter "FullyQualifiedName~MicrosoftEntraDeviceFlowClaimMaterialBuilderTests|FullyQualifiedName~MicrosoftEntraLogAnalyticsDeviceCodeSourceTests|FullyQualifiedName~MicrosoftEntraDeviceCodeAuditIntakeTests|FullyQualifiedName~OAuthDeviceFlowAuditCandidateGateTests|FullyQualifiedName~R275AdvancedAccuracyBatchTests|FullyQualifiedName~R275R343R485PairedReplayTests"`

Observed result:
- `Carthago` build succeeded.
- `Carthago.Tests` build succeeded.
- **83 total; 83 succeeded; 0 failed; 0 skipped**.
- Focused test duration: **13.7 seconds**.
- Overall command completed with **Build succeeded** in **43.2 seconds**.

**Classification:** GREEN for the authenticated Entra-to-packet claim-material boundary plus the previously GREEN authenticated source/parser/candidate layers.

This verifies that only an authenticated Entra observation can enter the claim-material path; the provider source IP must match the captured client; the destination IP is derived only from captured traffic; the flow must be TCP/443 with HTTP/HTTPS/TLS context; the identity host must satisfy explicit operator policy without lookalike suffix bypass; and UTC time correlation is bounded to two minutes.

**Scope boundary:** the output is still unsigned claim material only. No private signer key, signed envelope, verified receipt, live tenant event, rule-engine trust capability or R275 alert promotion is represented by this run.

No confidence floor, runtime mode, replay classification, holdout fixture, V1/V2 state or alert policy changed.

#### 2026-11-03 — R275 keyless external-signer handoff authored

After the Entra-to-packet claim-material boundary reached 83/83 GREEN, a separate keyless signer handoff was authored.

Source commits:
- `9492588c386969a3087d8cb3db0cc048eba02fab` — immutable R275 external-signing request and unsigned claim creation.
- `32af0092219e93cbe50044f55afbdda393f4fb32` — focused external-signer handoff tests.

The request is created only from validated R275 claim material and fixes rule ID, operation, UTC time, source/destination IPs and privacy-minimized subject/trace hashes. The external signer supplies only its configured issuer ID and a unique evidence ID. No private key, signing operation, trust-store mutation or alert capability exists in this class.

The focused synthetic end-to-end test uses two different RSA keys and two independently configured issuers, verifies both claims through the existing trusted-audit verifier, correlates them through the existing independent-issuer contract, and proves the result still terminates at `R275_SIGNED_IDP_AUDIT_CANDIDATE_NOT_INTEGRATED` with `AlertPermitted=false`.

**Verification status:** SOURCE CANDIDATE — UNVERIFIED. The previously observed 83/83 claim-material GREEN remains valid; only this new external-signer handoff requires focused execution.

#### 2026-11-03 — R275 keyless external-signer verification GREEN (92/92)

The owner fast-forwarded `feature/carthago-reliability-hardening` to `2686157e96a0cbc1835eb6adaef31393c7cf0a3d` and executed the expanded focused R275 suite including `OAuthDeviceFlowExternalSigningRequestTests`.

Observed result:
- `Carthago` build succeeded.
- `Carthago.Tests` build succeeded.
- **92 total; 92 succeeded; 0 failed; 0 skipped**.
- Focused test duration: **14.1 seconds**.
- Overall command completed with **Build succeeded** in **45.1 seconds**.

**Classification:** GREEN for the keyless external-signer handoff plus all previously verified R275 Entra source/parser/correlation layers.

This verifies that CARTHAGO can create a fixed unsigned R275 claim request without holding a private key; two independently keyed external signers can produce separately verified receipts; independent-receipt correlation succeeds; and the correlated pair still terminates at `R275_SIGNED_IDP_AUDIT_CANDIDATE_NOT_INTEGRATED` with `AlertPermitted=false`.

**Scope boundary:** this remains synthetic signing evidence. No production key custody, live signer service, live Entra event, ambient rule-engine trust, or R275 alert promotion is claimed.

No confidence floor, runtime mode, replay classification, holdout fixture, V1/V2 state or alert policy changed.

#### 2026-11-03 — R275 internal non-ambient rule capability authored

After the keyless external-signer handoff reached 92/92 GREEN, an internal-only rule-evaluation capability boundary was authored.

Source commits:
- `798d5bcb997db37be28def5bf1a75162c3bdeab8` — opaque R275 rule capability bound to one packet snapshot and UTC timestamp.
- `f6df06450d3a50147cf8afcbadcf0f66c2420a1f` — internal-only `RuleEvaluationContext` overload; public constructor remains packet-only.
- `e5b5f77ae71fb14d1682893ea4d8b4018a07d57f` — R275 recognizes the trusted capability but still returns NoMatch.
- `6c82e65c8b540563fd07fc6694803a05422c061b` — focused capability-delivery tests.

The capability can be minted only from a correlated independently verified R275 receipt pair that already passes the existing packet gate. It is bound by object identity plus a snapshot of endpoints, ports, protocol/identity-host fields and the exact UTC timestamp. A different packet object, modified packet or different timestamp cannot reuse it.

`TrafficRecord` was not modified. The existing public `RuleEvaluationContext` constructor remains available unchanged and cannot attach trusted evidence. The capability property and overload are internal to the Carthago assembly.

R275 remains non-alerting. Public packet-only evaluation continues to return `TRUSTED_DEVICE_CODE_ABUSE_EVENT_UNAVAILABLE`; the trusted internal path returns `TRUSTED_DEVICE_CODE_CAPABILITY_PRESENT_NOT_PROMOTED` with `RuntimePrecisionGate`, `Matched=false` and no events.

**Verification status:** SOURCE CANDIDATE — UNVERIFIED. The previously observed 92/92 keyless-signer GREEN remains valid; this new internal-capability increment requires focused execution.

#### 2026-11-03 — R275 internal capability delivery verification GREEN (99/99)

The owner fast-forwarded `feature/carthago-reliability-hardening` to `1851539ffbd71c27579dc135000a8678711adb36` and executed the expanded focused R275 suite including `R275TrustedCapabilityContextTests`.

Observed result:
- `Carthago` build succeeded.
- `Carthago.Tests` build succeeded.
- **99 total; 99 succeeded; 0 failed; 0 skipped**.
- Focused test duration: **14.6 seconds**.
- Overall command completed with **Build succeeded** in **40.9 seconds**.

**Classification:** GREEN for the internal non-ambient capability-delivery boundary plus all previously verified R275 source/parser/signer layers.

This verifies that the public `RuleEvaluationContext` remains packet-only; only an internal capability path can carry trusted R275 evidence; the capability is bound to the exact packet instance, relevant packet snapshot and exact UTC timestamp; reuse on a different packet, mutated packet or different timestamp is rejected; and a valid capability reaches R275 only as `TRUSTED_DEVICE_CODE_CAPABILITY_PRESENT_NOT_PROMOTED` with `Matched=false` and no events.

**Scope boundary:** no promotion policy is yet authorized by this evidence. A valid capability reaching rule evaluation is intentionally insufficient to emit an R275 detection event.

No confidence floor, runtime mode, replay classification, holdout fixture, V1/V2 state or alert policy changed.

#### 2026-11-03 — R275 explicit default-deny promotion policy authored

After internal capability delivery reached 99/99 GREEN, the first actual R275 promotion-policy source increment was authored without wiring it into normal production context construction.

Source commits:
- `c37dd0383e7da9d13245d312af22954fbd687991` — expose normalized identity host internally on the bound R275 capability for independent policy enforcement.
- `72842ee24101cd7e374977a85dd8bd2f3b80a996` — explicit default-deny promotion options and opaque promotion authorization.
- `2dbe8a3015fb8aac75e46a7fe0b663545bfc5909` — bind promotion authorization to the internal `RuleEvaluationContext` path.
- `d4212586b553cb4576f195aa3f1c8e826f9e4902` — authorized R275 event path with privacy-minimized evidence, high confidence and profile cooldown.
- `7ba10752ee9e532aae085ae2ebe1f8fe22bb47f3` — adversarial promotion-policy tests.
- `1373ffeb1146d9d2a4fcaf32ade649d686318040` — bound promotion cooldown state to 8,192 keys and fail closed on saturated recent state.

Promotion now requires an explicit enabled policy, both independently verified issuer IDs in the approved issuer set, an approved identity host, exact capability/packet/timestamp binding and a separate internal promotion authorization. The public `RuleEvaluationContext` remains unchanged and cannot attach either trusted object.

When all promotion prerequisites are present, R275 uses the shared event builder and emits only structural trusted-evidence markers. It does not emit OAuth codes, token material, actor/resource hashes, trace hashes or signer IDs. Confidence is derived from admin-confirmed compromise + independent signed corroboration + exact packet binding. Duplicate trace evidence is subject to the existing 20-minute R275 cooldown through a bounded fail-closed state cache.

**Production-default boundary:** no normal runtime code constructs `OAuthDeviceFlowPromotionAuthorization`; therefore ordinary packet evaluation remains fail-closed and the promotion path is not production-enabled by this increment.

**Verification status:** SOURCE CANDIDATE — UNVERIFIED. The previously observed 99/99 capability-delivery GREEN remains valid; the new promotion-policy suite must now be executed.

#### 2026-11-03 — R275 explicit promotion-policy verification GREEN (107/107)

The owner fast-forwarded `feature/carthago-reliability-hardening` to `5d142366a75b6797e7906cce50e0ba49952ea6e7` and executed the expanded focused R275 suite including `R275PromotionPolicyTests`.

Observed result:
- `Carthago` build succeeded.
- `Carthago.Tests` build succeeded.
- **107 total; 107 succeeded; 0 failed; 0 skipped**.
- Focused test duration: **19.8 seconds**.
- Overall command completed with **Build succeeded** in **55.2 seconds**.

**Classification:** GREEN for the explicit default-deny R275 promotion-policy layer plus all previously verified R275 source, signer and capability-delivery layers.

This verifies default-deny promotion, independent approved-issuer enforcement, approved identity-host enforcement including lookalike rejection, exact promotion-authorization binding, privacy-minimized High-severity event creation, confidence above the existing R275 floor, capability-without-authorization NoMatch behavior, duplicate-trace cooldown suppression and the non-public promotion surface.

**Scope boundary:** production runtime is still unwired. No normal application path currently constructs `OAuthDeviceFlowPromotionAuthorization`, so ordinary packet processing remains fail-closed despite the promotion policy itself now being test-verified.

No confidence floor, default runtime mode, replay classification, holdout fixture, V1/V2 state or production alert configuration changed.

#### 2026-11-03 — R275 selector-safe trusted RuleEngine runtime hook authored

After the explicit R275 promotion policy reached 107/107 GREEN, the first RuleEngine runtime-integration hook was authored without broadening R275's normal HTTP telemetry profile and without connecting a production receipt inbox.

Source commits:
- `9550d5e1e81eba95441ffd165af199e30b404546` — default-null internal R275 trusted runtime context resolver hook.
- `b1390e7065d948e6da01171b52fbdc57d2c0776f` — narrow R275 selector/telemetry bypass when a trusted context is already resolved.
- `02819ad4d6ceeaf8d9db3a0bf5a244e27005326d` — explicit selector-reason initialization.
- `e1b95d0ddfeeb7b00769de69780c2a0cf85bfe0a` — engine-level resolver tests.
- `72a2e2e251a10055ba9d7b365f0ad39bc6655a59` — test namespace correction.
- `58994682a2d3746acfadbbae6f7c808dc88ac97e` — internal scoped detection-journal isolation hook.
- `023c814561c7cb6d53cce5497d0da3e89592e8ba` — route RuleEngine journaling through the default-preserving isolation hook.
- `d85775b1fa1d05f00735f9a924df2caefbd919e9` — temporary-journal and non-parallel resolver-test isolation.
- `17d50e3cd57433d9f8f3e75818194d0dd2e53609` — internal-only trusted R275 precision telemetry evaluation path.
- `6db55173e09869bce24a916672284f086b9abfd9` — thread resolver-backed R275 state through result handling.
- `5d0622e1bba9db0717ff4769ef5629786998c8ea` — use trusted precision evaluation only for resolver-backed R275.
- `7242e7e7a140d05bea2a12aade611cc823c4329a` — profile-safe resolver assertions and public-vs-trusted precision coverage.

The ordinary R275 precision profile still requires HTTP telemetry; it was not changed to TLS or Flow. RuleEngine consults the trusted resolver only for R275. A resolver result is accepted only if the context is bound to the exact same record/timestamp and already contains both the opaque R275 capability and opaque promotion authorization.

Without a resolver, with an invalid/public context, or after a resolver exception, the original selector and telemetry path remains authoritative. With a valid trusted context, only R275 may bypass its raw HTTP selector/telemetry check. Public `RulePrecisionRuntimeEvaluator.Evaluate` is unchanged; the new trusted telemetry override is internal and restricted to R275.

Downstream confidence, evidence-family, tuning-profile, suppression and runtime-mode gates remain active. In particular, the default tuning profile may still Shadow a matched R275 candidate; the trusted resolver does not automatically force paging.

Focused tests redirect RuleEngine journal writes to temporary test directories so synthetic runtime detections do not enter the machine's normal journal.

**Production-default boundary:** the resolver is default-null and no live signed-receipt inbox or operator bootstrap is connected. Ordinary application behavior therefore remains unchanged.

**Verification status:** SOURCE CANDIDATE — UNVERIFIED. The prior 107/107 promotion-policy GREEN remains valid; this new runtime hook requires focused owner execution.

#### 2026-11-03 — R275 trusted runtime hook focused owner verification GREEN (114/114)

Owner-provided local PowerShell output for branch commit `8f4a771c1bf2fb859e44638bb18e72dcf3b403fe`, before the subsequent nullable-guard correction, confirms execution of the focused R275 resolver, promotion-policy, internal capability, OAuth device-flow, Entra source and paired-replay test filter.

Observed result:
- `Carthago` and `Carthago.Tests` Release builds succeeded.
- **114 total; 114 succeeded; 0 failed; 0 skipped.**
- Focused test duration: **18.3 seconds**.
- Overall build/test command completed in **87.9 seconds** with **2 reported warning occurrences** for `CS8604`, both originating at `Carthago/Engine/Rules/Abstractions/RulePrecisionRuntimeEvaluator.cs:65` (same nullability diagnostic reported for different build targets).

**Classification:** GREEN for the focused R275 integration tests **on commit `8f4a771` only**. The trusted runtime hook's authored source-candidate designation above is superseded **for that exact tested revision**, not for later untested revisions. This does not establish complete-system regression success, live trusted signed-receipt intake, or production promotion.

Follow-up source correction: commit `a7589023a470ad2aa26e2309a5c88a3f27838c19` adds an explicit `descriptor is null` guard before the R275-only descriptor check to address `CS8604`. This is a source-level correction, **not yet reverified by owner test output**.

**Remaining validation gates:** (1) rerun the identical focused 114-test filter on the corrected commit; (2) run the entire `Carthago.Tests` Release suite and record its exact counts. **Both are PENDING; do not label the corrected commit or full suite GREEN without execution evidence.** Do not alter R275 confidence floor, telemetry selector semantics, promotion policy, tuning or holdout fixtures.

#### 2026-11-03 — R275 nullable-guard correction focused re-verification GREEN (114/114)

The owner ran the same 10-class focused R275 filter in Release after fast-forwarding the existing `feature/carthago-reliability-hardening` branch (reported `Already up to date`; last confirmed remote head before this record was `3859d3157aca71687442bc76dd3cf5a7890903ad`, containing the nullable-guard correction `a7589023a470ad2aa26e2309a5c88a3f27838c19`).

Observed console output:
- `dotnet test .\\Carthago.Tests\\Carthago.Tests.csproj -c Release --filter $filter --logger "trx;LogFileName=R275-postfix.trx"` built `Carthago` and `Carthago.Tests` successfully.
- **114 total; 114 succeeded; 0 failed; 0 skipped**; focused test duration **20.2 seconds**; overall build/test **89.1 seconds**.
- No compiler warnings were reported in this post-fix output, unlike the previous focused run where `CS8604` appeared.
- Local evidence path (owner's Windows machine): `build-verify/test-results/R275-postfix.trx`.

**Classification:** focused R275 trusted runtime hook and nullable correction **GREEN (114/114)** on the owner's checked-out branch revision, per owner console evidence. This is **not** a production integration/promotion approval; the trusted resolver's default-null boundary remains intact.

The owner also initiated an unfiltered Release `Carthago.Tests` run with `--no-restore` and `Carthago-full.trx` logging. The supplied output contains a progress line `Carthago.Tests Testing (1484,1s)` but **no completion summary, exit code or TRX counters**. The visible synthetic `R006`, `FailingSink` and malformed-feedback messages are not sufficient to attribute a regression. **Full-suite status: INCOMPLETE / NOT VERIFIED**. Do not invent a pass count or infer failure/hang from the partial output; investigate the test process and result files.

**Remaining gate:** obtain complete Release suite run evidence including total/pass/fail/skipped counts and exit code, and only then record whole-suite classification. R275 confidence floor (80%), public HTTP telemetry profile, promotion authorization, holdouts and production gates remain unchanged.

#### 2026-11-03 — Complete Carthago Release regression GREEN (10,669/10,669)

The owner supplied the completed console transcript of the **unfiltered** `Carthago.Tests` Release diagnostic run after the R275 null-guard correction. The prior log excerpt ending at `Testing (1484,1s)` described an earlier incomplete attempt; it is **superseded for this validation gate** by the independently completed diagnostic run below.

Executed scope: `dotnet test .\\Carthago.Tests\\Carthago.Tests.csproj -c Release --no-build --no-restore --logger "console;verbosity=normal" --logger "trx;LogFilePrefix=Carthago-full-diagnostic" --results-directory .\\build-verify\\test-results --blame-hang --blame-hang-timeout 15m --blame-hang-dump-type none`.

Observed console evidence:
- `Test Run Successful.` — **10,669 total; 10,669 passed; 0 failed; 0 skipped.**
- Test duration **84.6 seconds**; full command/build duration **85.4 seconds**.
- `FULL SUITE EXIT CODE: 0`.
- One diagnostic infrastructure warning: `Data collector 'Blame' message: All tests finished running, Sequence file will not be generated.` This is not a compiler warning, failed test or hang.
- Local TRX result path (on owner's Windows machine): `build-verify/test-results/Carthago-full-diagnostic_net8.0_20261103214103.trx`.
- The earlier post-fix R275 focused verification was separately **114/114 GREEN** with no compiler warnings.

**Classification:** BOTH REQUIRED R275 VALIDATION GATES COMPLETE — focused **114/114 GREEN** and unfiltered `Carthago.Tests` Release regression **10,669/10,669 GREEN**, per owner local console evidence. The transcript does not independently print `git rev-parse HEAD` at test time, so the result is attributed to the owner's checked-out existing branch, **without claiming exact-SHA attestation**.

**Scope boundary:** test success does not enable production trusted receipt intake or authorize an R275 promotion. R275 80% confidence floor, raw HTTP telemetry profile, explicit promotion authorization, policy gates and frozen holdouts are unchanged. No frozen-holdout, benchmark, live capture or product-wide production acceptance is claimed by this unit-test gate.

#### 2026-11-03 — Detection-quality replay gate RED; report verifier repair authored

Owner-authorized Windows `./verify-local.ps1 -Details` finished restore, benchmark/test builds, xUnit stage, and benchmark process successfully. The **validation result remains RED**, not GREEN.

Observed owner console:
- `146` replay samples: `42` supported malicious, `98` benign, and `6` unsupported malicious according to the separate read-only accuracy inspector.
- Supported malicious raw recognition: `42/42` across all six profiles; alert-level recognition: `1/42` in five profiles and `0/42` in IoTHeavy, with policy Shadow decisions. These are distinct metrics: raw matches are NOT alerts.
- Benign alert false-positive count: `0` on the labeled replay corpus only. The sample size does not certify field false-positive rates.
- `ssrf-imds`: `Maximum confidence 0.62 was below the expected floor 0.65`. R163's actual source assigns 0.34 (metadata-service target) + 0.28 (credential-path) and explicitly refuses to award confidence for ordinary IMDSv2 token headers. Its **84% runtime confidence floor remains unchanged**. This fixture expectation is **unresolved**; it was not silently lowered and confidence was not boosted.
- `verify-local.ps1` aborted the remaining report audit on `Unrecognized replay classification on sample ad-psremoting-encoded-command`; benchmark code uses an explicit `UnsupportedMalicious` class. The validator also contained a hardcoded `544` default-rule count although the checked-out RuleRegistry source contains `695` default rule constructor registrations. `inspect-rule-evidence.ps1` reported a broader `705`-ID evidence inventory, 8 IDs with positive controls, 61 with explicit negative controls, 7 with paired controls. Default registry and evidence inventory are **different denominators**.

SOURCE CANDIDATE fix authored directly on the existing feature branch in `e3c5357f06bb2c2b4acc6b92a2498ac2794e71ab`:
1. The PowerShell alert-quality report explicitly accepts `UnsupportedMalicious` without counting it as supported attack or benign; it fails if a supposedly unavailable producer rule emits an alert. The benchmark's independent reason-code checks remain required.
2. The audit inventory now cross-checks exact default rule IDs and duplicates against the checked-out `RuleRegistry.cs` instead of rejecting every catalog larger than 544. R001-R695 preservation provides a minimum floor, not an upper cap. Additional evidence-only IDs are not silently equated with default registrations.

**Verification status:** SOURCE CANDIDATE — UNVERIFIED for the PowerShell repair; no .NET/PowerShell tests executed in the assistant environment. **Detection-quality gate remains RED** because of the unresolved `ssrf-imds` confidence expectation until independently investigated and rerun. No production rule, rule confidence, suppression policy, replay classification or frozen holdout changed.

#### 2026-11-03 — R163 SSRF replay confidence contract aligned to observable evidence

Follow-up to the owner's detection-quality run that built/tests/benchmark executed successfully but whose end-to-end validation remained RED: the `ssrf-imds` fixture required raw confidence >=0.65 while the R163 rule intentionally produces only 0.62 from metadata-service target (0.34) + credential-path evidence (0.28). Ordinary IMDSv2 headers and time-adjacent inbound HTTP are not independently proven SSRF causality and must not add confidence.

Source-only changes published on the existing `feature/carthago-reliability-hardening` branch:
- `e764baf5fd207543f38ac6492f65e10676c0bc6f` — correct **only the fixture's raw-candidate `expectedMinimumConfidence`** from 0.65 to the existing 0.62. The fixture retains its malicious scenario label, `expectedMatches: ["R163"]`, and original traffic records.
- `5cc62cb99a2d3d13c87b4f95d53466c9c71b5496` — add a fixture-specific replay xUnit contract requiring R163 raw recognition, 0.62 exact replay confidence, empty fixture expectation errors, the immutable 84% R163 precision floor, and **no R163 simulated alert in any of six profiles**.

These assertions prevent silently inflating the detector score to make the fixture pass; they also prevent misinterpreting a legitimate metadata-credential probe as independently proven SSRF. No production rule confidence weighting, policy, alert mode, classification, expected negative labels, frozen holdouts, or producer trust path changed.

The earlier `verify-local.ps1` PowerShell repair `e3c5357` also remains SOURCE CANDIDATE — UNVERIFIED. **Validation state: PENDING owner Windows rerun**. First run focused `FullyQualifiedName~R118R163PairedReplayQualityTests`, then `./verify-local.ps1 -Details`, and record the exact pass/fail numbers, benchmark errors, and rule-inventory equality checks. No tests were run from the assistant's environment. Previous RED and 42/42 raw recognition evidence remain historical; do not mark a new overall detection-quality GREEN until observed.

#### 2026-11-03 — Owner Windows R163 and development detection-quality replay GREEN at `bf7e889`

The owner fast-forwarded the existing branch from `3859d31` to `bf7e889b107a6cf334e3bbefa990b7718818d53b` (confirmed `git pull --ff-only`) and executed the validation steps below. This report **closes the preceding source-candidate tests and development replay RED** for this checked-out revision; it does not erase their historical entries.

**Focused regression:** `dotnet test .\\Carthago.Tests\\Carthago.Tests.csproj -c Release --filter "FullyQualifiedName~R118R163PairedReplayQualityTests"`
- `5 total, 5 succeeded, 0 failed, 0 skipped`; focused test duration **21.4 seconds**, overall build succeeded in **65.7 seconds**.

**Full local development verification:** `.\\verify-local.ps1 -Details`
- Restore tests **PASS** (1.6s), restore benchmarks **PASS** (1.3s), build tests **PASS** (2.5s), build benchmarks **PASS** (2.8s), full xUnit stage **PASS** (91.9s), replay benchmark stage **PASS** (8.9s), command exited without triggering the owner's nonzero-exit guard.
- No exact test count was printed by this `verify-local.ps1` transcript; do not misattribute the older `10,669/10,669` result to the current full xUnit stage.
- **146 replay samples**: 42 supported malicious, 98 benign, 6 unsupported malicious (producer-limited; excluded from supported malicious recall).
- **Supported raw detector recognition: 42/42 (100%)** across Enterprise, HomeLab, IoTHeavy, OTSegment, Research and SmallBusiness; **benign critical alerts: 0**, alert-level false positives: **0** on the development corpus.
- **Simulated alert-level recall:** Enterprise/HomeLab/OTSegment/Research/SmallBusiness: `1/42 = 2.4%`, with precision `1/1` (not a field precision estimate); IoTHeavy: `0/42 = 0%`, precision undefined. Most recognized events remain Shadow/Disabled, not emitted alerts.
- R118: `0/15` alerted; R163: `0/20` alerted; R102: `0/2` alerted in all six profiles, consistent with separately preserved evidence and policy gates.
- **Rule catalog audit:** `695` default rules; `7` paired synthetic controls; `640` without explicit replay controls; `0` contract issues. **PASS: registered default rule inventory agrees with benchmark (695 entries)**. The broader `705`-ID evidence report previously seen is a different denominator.
- The previous `ssrf-imds` confidence mismatch and `UnsupportedMalicious` verifier error did **not** recur. The R163 fixture's raw observed 0.62 score and 84% production floor are distinct; no confidence or policy tuning was performed.

**Classification:** **DEVELOPMENT DETECTION-QUALITY REPLAY GREEN** at the owner-reported checked-out branch `bf7e889`; focused R163 regression **5/5 GREEN**. This establishes that the replay scorer and safety guardrails succeeded on the current development corpus, **not** per-rule field accuracy or production alert recall, complete producer integration, independent holdout success, or live detection delivery.

**Open quality gaps:** explicit paired evidence for most registered rules; low policy-constrained alert recall; missing external independent R102 V2 source/provenance pairs (0/4); trusted runtime producer reachability and live performance are separate gates. Frozen V1 remains historical 4/6, unchanged. R102/R118/R163 floors (80%/86%/84%), R275's 80% floor, default modes, and all holdout states remain unchanged. The owner did not provide a contemporaneous `git rev-parse HEAD` output; this classification uses the fast-forward + command transcript without claiming independent exact-SHA runner attestation.

#### 2026-11-03 — GA-03 paired replay evidence for four existing high-priority stateful rules authored

The immediately preceding owner Windows verification was **5/5 R163 focused GREEN** and **`verify-local.ps1 -Details` development replay GREEN** on `bf7e889b107a6cf334e3bbefa990b7718818d53b`. That older checkpoint included 146 replay samples, 42/42 supported raw recognition, 0 benign alert false positives, 695 default registry entries with 0 contract issues, 7 paired-rule controls and 640 default rules without explicit replay controls. Those are historical observed counts, **not predicted counts for this candidate**.

To close explicit development-replay evidence gaps without adding or re-registering any detection rules, GA-03 published **source-only commit `d5d53f50fd7b5206809d930c4d14cd108d77e469`** directly to the existing `feature/carthago-reliability-hardening` branch. Seven JSON fixtures and one xUnit benchmark-level contract were added:

| Existing rule | Positive malicious development replay | Paired benign explicit nonmatch |
| --- | --- | --- |
| R001 TCP port scan | `ga03-r001-eight-distinct-tcp-syn-ports` — eight distinct destination ports, one source/target, initial SYN only (checked-in threshold 8) | `ga03-r001-retransmissions-and-synack` — repeated same-port SYNs plus distinct SYN/ACK responses cannot form a port scan |
| R004 SSH authentication failures | `ga03-r004-twelve-attributed-ssh-failures` — 12 source/target/service-bound observed failure outcomes (checked-in auth-port threshold 25/2 = 12) | `ga03-r004-successful-ssh-and-banners` — accepted key exchanges and SSH banners must not count as failed credentials |
| R017 internal host sweep | `ga03-r017-ten-private-host-syn-sweep` — 10 distinct private destinations on TCP/8080 (checked-in threshold 10) | `ga03-r017-retransmissions-and-ack-only` — repeat probes to one host and response-only ACKs do not establish distinct-host reconnaissance |
| R030 internal administrative lateral sweep | `ga03-r030-eight-private-admin-syn-targets` — 8 distinct private targets on TCP/22 (rule threshold 8) | Reuses existing `r030-synack-not-lateral-sweep`; no duplicate negative fixture |

Every new scenario exercises the existing RuleEngine stateful predicates through `TuningBenchmarkRunner` with **explicit per-rule labels**; labels in other samples are not automatically treated as negatives. The new `Carthago.Tests/Ga03ExistingRulePairedReplayTests.cs` loads the full development replay catalog, checks all four positive raw matches and benign explicit nonmatches, requires no sample assertion errors, confirms non-alerting negative decisions across available profiles and checks positive/negative evidence coverage bookkeeping.

**Validation status: SOURCE CANDIDATE — UNVERIFIED.** Neither the new xUnit class nor `verify-local.ps1` was executed by the assistant. Do **not** claim new paired-rule counts or a new GREEN checkpoint until the owner has explicitly executed both verification gates and reported their results. Existing benchmark results can change when new labeled cases are added; reporting raw recognition, policy simulated alerts and field alert accuracy separately remains mandatory.

Owner test-time instructions (after pulling new source):
1. `dotnet test .\\Carthago.Tests\\Carthago.Tests.csproj -c Release --filter "FullyQualifiedName~Ga03ExistingRulePairedReplayTests"`
2. If focused gate GREEN, `.\\verify-local.ps1 -Details` then `.\\scripts\\inspect-rule-evidence.ps1 -MissingPaired -Top 25` and record test counts, replay counts, rule audit counts, any failed assertion, total paired rules, benign alert outcomes and policy decisions.

No existing predicate, thresholds, confidence floors, tuning profiles, event semantics, registry, Holdout V1 (frozen historical 4/6), Holdout V2 (0/4 reviewed external R102 pairs), production alert mode or unrelated automation were modified. This is offline developer synthetic evidence, not an independent field-quality claim.

#### 2026-11-03 — GA-03 four-rule paired replay owner verification GREEN (153 samples)

The owner supplied Windows PowerShell execution evidence after a **fast-forward pull** from `bf7e889` to `19bf1aabac187cf53964d44c46d55887212e70f9` on the existing `feature/carthago-reliability-hardening` branch. This closes the preceding GA-03 SOURCE CANDIDATE — UNVERIFIED **for that checked-out revision**, without retroactively reclassifying other, unexecuted candidate rule batches.

**Focused test gate**:
- `dotnet test .\\Carthago.Tests\\Carthago.Tests.csproj -c Release --filter "FullyQualifiedName~Ga03ExistingRulePairedReplayTests"`
- Release builds of `Carthago` and `Carthago.Tests` **succeeded**.
- **1 total, 1 passed, 0 failed, 0 skipped**, test duration **13.4 seconds**, overall build/test **60.6 seconds**.
- This one test runs the development replay harness and verifies four different positive/negative rule pairs; it is **one xUnit test case**, not four separately reported xUnit passes.

**End-to-end development validation**:
- `.\\verify-local.ps1 -Details` — restore-tests **PASS** (1.7s), restore-benchmarks **PASS** (1.4s), build-tests **PASS** (2.5s), build-benchmarks **PASS** (3.3s), full test stage **PASS** (131.5s), replay benchmark **PASS** (9.1s), final **`PASS: local build, tests and replay validation.`**
- The complete xUnit test count was **not printed** in this transcript, so only successful stage completion is claimed for this invocation.
- **153 offline labeled replay samples**: **46** supported malicious, **101** benign, **6** producer-limited `UnsupportedMalicious`; these are separate categories.
- **46/46 supported expected raw detector matches recognized** in each of the six profiles (100% on this synthetic development corpus, not field recall).
- Benign critical alerts **0**; simulated alert-level false positives **0** on the reported labeled replay corpus.
- **Alert-level recall** in Enterprise, HomeLab, OTSegment, Research and SmallBusiness = **1/46 (2.2%)**; IoTHeavy = **0/46 (0.0%)**. An empirical precision of 100% on a single emitted true-positive alert in five profiles is statistically weak and must not be represented as production precision.
- All R118 (`0/15`), R163 (`0/20`), and R102 (`0/2`) observed expected matches remain non-alerting across all six tested profiles.
- **695 default rule registrations**, **0 rule contract issues** and **PASS: registered default rule inventory agrees with benchmark (695 entries)**.
- **11** default rules with paired positive/explicit-negative synthetic controls (up from **7**), **638** without any explicit replay controls (down from **640**).
- `.\\scripts\\inspect-rule-evidence.ps1 -MissingPaired -Top 25` confirmed a separate **705-ID evidence inventory**, with **12** having at least one positive control, **63** at least one explicitly labeled negative control, and **11** paired. The 705 IDs **must not be mistaken for 705 default registered rules**.

**Classification: GA-03 FOCUSED GREEN (1/1); 153-SAMPLE DEVELOPMENT DETECTION-QUALITY REPLAY GREEN.** The covered rules R001, R004, R017, R030 now have observed passing positive and benign nonmatch evidence, with the R030 negative scenario reused rather than duplicated. The development gate is closed for the owner-reported tested branch revision; original synthetic-data and corpus-label limitations remain.

**Open work:** the majority of registered rules still lack paired controls, policy-constrained simulated alert recall remains low, trusted-producer end-to-end validation and the independent R102 Holdout V2 external capture/provenance review remain pending. Frozen V1 (historical 4/6) remains immutable. Confidence floors, detection predicates, profile policy, promotion authorization and production alert mode were not changed by this GA-03 increment. The owner did not provide a separate `git rev-parse HEAD` at test invocation; no independent exact-SHA runner attestation is claimed.

#### 2026-11-03 — GA-04 R014/R026/R027/R031 paired credential/service/DNS replay authored

Following owner-confirmed GA-03 GREEN (153 replay samples; 46/46 supported malicious raw recognitions; 11 paired controls; 0 benign alert false positives; default registry 695 entries with zero contract issues), a new **source-only GA-04 candidate** was published directly to the existing `feature/carthago-reliability-hardening` branch as **`281ed02719394c9718279b5b8ee118849d009c0c`**. No new detection rule IDs, alternate engines, thresholds, runtime modes or production detector changes were authored.

Added **8** offline developer-labeled JSON fixtures and **1** benchmark-level xUnit class `Carthago.Tests/Ga04ExistingRulePairedReplayTests.cs`:

| Existing rule | New synthetic positive candidate | New explicit benign counterexample |
| --- | --- | --- |
| **R014** cleartext credentials | `ga04-r014-cleartext-ftp-pass-observed`: attributed TCP/21 FTP `PASS` command with synthetic placeholder value | `ga04-r014-encrypted-pass-and-auth-negotiation`: TLS-protected FTP command, SMTP `AUTH LOGIN` negotiation without value, and FTP `USER` alone |
| **R026** external SMB/NetBIOS | `ga04-r026-private-to-public-smb-syn`: private-source/public-destination TCP/445 initial SYN, not evidence of completed compromise | `ga04-r026-internal-smb-and-public-synack`: internally scoped SMB and an unclassified public SYN/ACK response |
| **R027** public admin-service egress | `ga04-r027-private-to-public-rdp-syn`: private-source/public-destination TCP/3389 initial SYN candidate, not proof of unauthorized administration | `ga04-r027-internal-ssh-and-mismatched-service`: internal SSH, public TCP/22 with contradictory RDP service classification, and unrelated IMAP port |
| **R031** DNS TXT spike | `ga04-r031-fifteen-valid-txt-queries`: 15 synthetic client-to-resolver TXT queries at the existing 15-in-60-seconds threshold | `ga04-r031-txt-responses-and-nontxt-queries`: 18 TXT responses plus 18 A queries cannot be miscounted as TXT query requests |

The new test class loads the entire development replay through the existing `TuningBenchmarkRunner` and checks all four expected positive and negative rule IDs, explicit labels, empty assertion errors, per-rule positive/negative coverage accounting, non-alert behavior for explicitly benign rule controls under all six profiles, and no serialised synthetic credential placeholder in matched benchmark sample observations.

The previous benign fixtures for these rules (`r014-smtp-envelope-not-credentials`, `r026-udp445-not-smb-egress`, `r027-mail-auth-not-admin-egress`, `r031-dns-response-not-query`) remain intact; the new negatives add distinct boundaries instead of replacing them.

**Expected, NOT verified:** replay sample count could rise from **153 to 161**, supported malicious sample count from **46 to 50**, paired default-rule controls from **11 to 15**, if all new assertions pass. This does not imply a measured improvement in field precision or alert recall, and pre-existing rules with only negative controls may remain unpaired if the replay is not executable.

**Owner validation required:** After fast-forward pull, run `dotnet test .\\Carthago.Tests\\Carthago.Tests.csproj -c Release --filter "FullyQualifiedName~Ga04ExistingRulePairedReplayTests"`; only if GREEN, run `.\\verify-local.ps1 -Details` followed by `.\\scripts\\inspect-rule-evidence.ps1 -RuleId R014,R026,R027,R031`. Record exact focused and aggregate test counts, benchmark classification/match errors, alert-level FP, raw recognition, rule-pair totals and actual branch revision. **GA-04 classification: SOURCE CANDIDATE — UNVERIFIED**. No tests executed by the assistant.

Safeguards: R102 80%, R118 86%, R163 84%, R275 80% confidence floors untouched; all rule predicates, suppressions, tuning policies and runtime telemetry semantics untouched; frozen V1 holdout historical 4/6 and V2 external-source review gates untouched. Existing hourly rule/UI automations remain independent.

## 2026-11-13 — Owner full regression checkpoint and intermittent test-host abort

- Owner-tested source: `a740c3d` (docs synchronization; includes SMB2 WRITE response and TLS identity enrichment). Direct Windows Release xUnit run: **12,272/12,272 passed, 0 failed, 0 skipped**; 229.0 s tests, 256.7 s total. Result: `build-verify/test-results/carthago-full-regression.trx`.
- Separate `verify-local.ps1 -Details -LiveOutput` attempt: restores and both builds passed with 0 warnings/errors. Test host aborted after 12,079 completed tests, exit 1; **comprehensive gate FAILED: tests**. No failing assertion reported. Feedback deserialization and intentional failing-sink messages also appeared in the successful direct run; neither establishes crash causality. No dump/sequence evidence supplied yet.
- Benchmark stage passed: 161 development samples (50 supported malicious, 6 unsupported malicious, 105 benign); 50/50 supported detector recognition, zero cold benign alerts; cold SmallBusiness 2 TP/0 FP/48 FN/105 TN (4% alert recall, 7.7% F1). Calibrated profiles emitted 2–5 of 50 supported expected alerts, one false-positive sample per profile. Audit: 965 entries, 15 paired synthetic controls, 908 without explicit replay controls, zero contract issues. These are offline observations, not field accuracy.
- Six unsupported producer scenarios remain separate: R275, R295, R343, R437, R508, R516. No promotion, relabeling, confidence-floor reduction or holdout change made.
- Diagnostic change: `verify-local.ps1 -Details -LiveOutput -DiagnoseTestCrash` adds VSTest blame-crash mini dump and diagnostic log under a unique local results directory. Preserve original failure status; no automatic retry or assertion suppression. Windows execution pending at this new source revision. Root cause remains unknown; inspect crash artifacts if recurrence occurs.

## 2026-11-13 — Owner comprehensive verification GREEN (12,293 tests)

- Owner-tested SHA: `b90d73b329557c84048695bb5edc10f275a4199c`. Windows command: `.\verify-local.ps1 -Details -LiveOutput -DiagnoseTestCrash`. Both restore and build stages passed; builds reported zero warnings and zero errors. **12,293 passed, 0 failed, 0 skipped**; xUnit duration 2m54s, test stage 182.7s. Benchmark stage passed in 9.4s; final output **PASS: local build, tests and replay validation**.
- Diagnostic mode created a unique local results directory (`build-verify/test-results/crash-20261113-002326-888-30d7cfeb`), attached crash monitoring, and wrote the TRX and VSTest diagnostic log. No host abort occurred. Prior intermittent abort remains unexplained; retain the historical failed attempt, do not claim a root-cause fix or stability certification.
- Replay: 161 samples, 50/50 supported malicious recognized, six unsupported malicious producer contracts, 105 benign samples. Cold SmallBusiness: 2 TP, 0 FP, 48 FN, 105 TN (4% recall, 7.7% F1); 47 shadow, 1 disabled. Calibrated profiles 4–10% alert recall with one false-positive sample each. All reported funnel accounting passed. Registry audit: 965 default IDs, 15 paired synthetic controls, 908 without explicit replay controls, zero contract issues. No field accuracy or production readiness claim.
- Next investigation: R163 (20 positive replay cases, zero cold expected alerts). Current detector evidence weights 0.34 metadata target + 0.28 credential path = 0.62; precision floor 0.84. Source intentionally excludes ordinary provider headers/token mechanics from confidence. Obtain independently qualified inbound-to-outbound causal provenance before considering any promotion; direct metadata access is not SSRF proof. Preserve R163 floor 84%, R118 floor 86%, R102 floor 80%, benign controls and frozen holdouts. Inspect existing evidence coverage with `.\scripts\inspect-rule-evidence.ps1 -RuleId R163,R118,R102`; no new tests or detector changes executed by assistant.
- This checkpoint applies only to the tested SHA, not future branch changes; recording it is a documentation-only update.

## 2026-11-13 — GA-05 R356 paired replay and evidence inventory scope

Owner inspection at `373d526`: R102 2/2 positive, 2/2 explicit negative; R118 15/15, 58/58; R163 20/20, 57/57. Evidence inventory 975, 16 with positives, 63 with negatives, 15 paired; default audit 965. Analyzer unions rule coverage with fixture labels, unsupported IDs and benign observed IDs; extra IDs are not automatically content-pack entries or registered rules. Inspector now prints exact extra IDs relative to report default audit.

R356 positive-only (1/1, 0 negatives): added parser-backed benign near-miss `ga05-r356-jenkins-crumb-lookalike` (same Jenkins host, GET, port and CI/CD context as positive; jsonx rather than exact json). Existing malicious-labeled synthetic positive unchanged. GA-05 test asserts labels, raw results, no expectation errors and no R356 alert on negative in any profile. No predicates, thresholds or policies changed; no malicious intent or field accuracy established.

Expected, NOT verified: 162 fixtures, 106 benign, 50 supported and 6 unsupported malicious, 16 paired default rules, 965 default registrations. Windows validation: `dotnet test .\\Carthago.Tests\\Carthago.Tests.csproj -c Release --filter "FullyQualifiedName~Ga05JenkinsCrumbPairedReplayTests|FullyQualifiedName~R356AdvancedAccuracyBatchTests"`; then `.\\verify-local.ps1 -Details -LiveOutput -DiagnoseTestCrash` and `.\\scripts\\inspect-rule-evidence.ps1 -RuleId R356,R163,R118,R102`. Preserve prior owner 12,293 checkpoint at b90d73b. No assistant test execution.

## 2026-11-13 — GA-05 GREEN and GA-06 canonical replay labels

Owner-tested `75c66c4`: R356 focused **16/16**; complete Windows verification **12,347/12,347**, zero failed/skipped/warnings/errors, final PASS. Replay 162 samples (50 supported malicious, 6 unsupported, 106 benign), 50/50 raw recognition, cold 2/50 alerts SmallBusiness, no cold benign alerts, 16 paired default rules, 908 without explicit controls, zero contract issues. Crash monitor completed without abort; historical root cause remains unknown.

Inspector identified ten evidence-only IDs R41–R50. Checked each matching r041–r050 negative fixture: the expectedNonMatches label omitted the leading zero, while the intended registered detector is R041–R050. These were vacuous nonmatches against absent IDs, not verified negatives for the actual rules. Corrected only the ten labels; records, classifications, positive labels and detector source unchanged. Added GA-06 regression checking all explicit negative labels against default audit, exact ten corrected fixtures and equal evidence/default inventory. Expected evidence inventory 965; negative coverage transfers to the intended registered IDs; actual results pending Windows execution. Run `dotnet test .\\Carthago.Tests\\Carthago.Tests.csproj -c Release --filter "FullyQualifiedName~Ga06CanonicalReplayLabelTests"` and comprehensive verification. No assistant test execution.

## 2026-11-13 — GA-07 parser-backed DevOps token replay candidates

R353/R354/R359 previously had five explicit negatives each but no positive replay. Live PacketHandler derives token-shape flags from HttpLight before redaction, while the offline benchmark only copied the Basic-auth flag. Extended the offline raw-request path to copy the three existing parser-owned flags on coherent TCP/HTTP requests with valid ports. Added three synthetic token-shaped cleartext fixtures (GitHub, GitLab, Azure DevOps), cross-provider explicit nonmatches, and a paired replay test requiring recognition, existing negatives and no synthetic token leakage in serialized sample results. No real credentials, credential validity, authorization or malicious outcome inferred; synthetic malicious labels represent development exposure scenarios only. No production detector/threshold/alert-policy changes. R009/R010 deferred: VPN/proxy and destination country classification alone are not malicious ground truth; require separately defined policy-qualified positive scenario instead of inflating attack recall.

Expected, NOT verified: 165 development fixtures, 53 supported malicious, 6 unsupported malicious, 106 benign, 19 paired default IDs; 965 default/evidence IDs after GA-06. Owner validation: `dotnet test .\\Carthago.Tests\\Carthago.Tests.csproj -c Release --filter "FullyQualifiedName~Ga06CanonicalReplayLabelTests|FullyQualifiedName~Ga07DevOpsTokenPairedReplayTests|FullyQualifiedName~DevOpsHttpParserProvenanceTests|FullyQualifiedName~R353AdvancedAccuracyBatchTests|FullyQualifiedName~R354AdvancedAccuracyBatchTests|FullyQualifiedName~R359AdvancedAccuracyBatchTests"` then comprehensive verify-local. Assistant executed no Windows tests.

## 2026-11-13 — GA-06/07 GREEN; GA-08 environment qualification candidate

Owner-tested `c164be6`: targeted 49/49 and comprehensive Windows 12,371/12,371; zero failures/skips/warnings/errors, final PASS. Test stage 182.2s, no host abort. 165 development samples (53 supported malicious, 6 unsupported, 106 benign), 53/53 raw recognition. Cold SmallBusiness 2 TP/0 FP/51 FN/106 TN (3.8% recall, 7.3% F1); 50 shadow, 1 disabled. The three added non-alerting samples change the denominator, not prior alert counts. Calibrated 2–5 alerts with one benign FP per profile. Default and evidence inventories both 965, zero extra IDs; 19 positive-controlled, 64 negative-controlled, 19 paired, 898 no explicit controls, zero contract issues. R041–R050 each 1/1 negative; R353/R354/R359 each 1/1 positive and 7/7 negative. No field accuracy or credential compromise claim.

GA-08: RulePrecisionRuntimeEvaluator requires DevOpsAudit environment scope; exact Approved.CiCdServers destination/HTTP Host can satisfy it, independent of confidence and profile policy. The GA-07 fixtures lack such configuration. Added separate temporary-fixture end-to-end test with exact versus unrelated CI/CD host for each of three token patterns. Expected Enterprise cold Shadow for both, configured exact Alert versus unrelated Shadow; HomeLab Disabled remains non-alerting. Scored corpus, production rules, confidence floors, runtime policy and existing holdouts unchanged. This is synthetic eligibility testing, not live authorization or malicious intent. Windows validation pending: `dotnet test .\\Carthago.Tests\\Carthago.Tests.csproj -c Release --filter "FullyQualifiedName~Ga08DevOpsEnvironmentScopeTests"`. No assistant execution. Historical test-host root cause remains unknown.


## 2026-11-13 — GA-08b exact-scope bypass correction; GA-09a causal boundary

Reviewed live parent `4e6d7f192e5fcb5ae58b3823302fe1c139155b00`. No newer owner Windows results supplied; c164be6 remains verified. GA-08 fixture paths, names and host configuration match GA-07 source. Found a concrete policy gap: generic EnvironmentEvidencePresent accepts any nonempty ProcessName or MAC (and descriptive evidence kinds), allowing the three token rules to bypass explicit CI/CD scope on attributed traffic. Restrict R353/R354/R359 only to exact Approved.CiCdServers destination or HTTP host; preserve generic environment policy for other rules, existing confidence floors, detector predicates and profile modes. Expand GA-08 temporary fixtures from six to twelve with exact/unrelated scopes plus process/MAC attribution; expect cold Shadow, configured exact Alert, unrelated Shadow and HomeLab Disabled. Host scope is a configured observation, not proof of server identity or authorization. No scored corpus edits.

GA-09a: extend existing ssrf-imds replay test to calibrated profiles; adjacent inbound request, metadata credential path and IMDSv2 header remain 0.62, below 0.84, even after baseline readiness. No causal producer or confidence boost introduced. Next: inventory trustworthy application trace/egress correlation capability, then R118 authentication outcome and R102 independent capture baseline. Preserve frozen holdouts and six unsupported producer gaps. Windows pending: `dotnet test .\\Carthago.Tests\\Carthago.Tests.csproj -c Release --filter "FullyQualifiedName~Ga08DevOpsEnvironmentScopeTests|FullyQualifiedName~R118R163PairedReplayQualityTests|FullyQualifiedName~Ga07DevOpsTokenPairedReplayTests"`; full verify-local after focused GREEN. No assistant test execution. Source candidate, not promotion.

## 2026-11-13 — GA-09b R118 calibrated attempt boundary and producer inventory

Reviewed parent `356601e837eff0bc0d0ddee7dff72ff3b210cf6a`; no new detection-quality owner verification in ledger. R163 currently consumes metadata target/path, process name and provider headers; TrafficRecord exposes process attribution but no application trace ID or authenticated request-to-egress causal binding. PacketHandler HttpLight derives request flags, not a trusted application trace. RuleEvaluationTrace is rule evaluation instrumentation, not application causality. Do not use PID/timing or inbound adjacency as proof. R118 consumes a default-credential request and likely device target, not an authentication outcome. PacketHandler derives HttpBasicDefaultCredentialObserved on client-to-server HTTP; TrafficRecord has no HTTP authentication-outcome field. ApprovedAssetRegistry camera/NVR suppression is R119-specific, not R118 login verification. A configured device, HTTP 2xx or a TCP ACK alone cannot prove authentication; a future producer needs bounded request/response association and device-specific independently verified authentication semantics. No new trust flags or confidence boosts.

Extended existing parser-redacted ONVIF positive/negative regression: all profiles must retain the same R118 confidence after calibration, remain below 86%, and emit no R118 alert for either attempt or unknown-credential control; assert the independent precision-floor reason. No corpus or holdout edits, no rule IDs or policy changes. GA-08b and GA-09a/b Windows pending. Next: inspect R102 capture-backed baseline and independent holdout runner; R163 application instrumentation and R118 authenticated outcome remain producer dependencies. Run `dotnet test .\\Carthago.Tests\\Carthago.Tests.csproj -c Release --filter "FullyQualifiedName~R118R163PairedReplayQualityTests|FullyQualifiedName~Ga08DevOpsEnvironmentScopeTests"` then comprehensive verify-local. No assistant execution.

## 2026-11-13 — GA-09c R102 packet-to-rule boundary

Reviewed live parent `db9b582f88931504f69ffa9b992f0fbe0948c5fb`, qualification gate Q2/Q9 and R102 frozen telemetry audit. R916/R962 capture-attested DNS transaction inspector is intentionally single IN/A; it cannot establish TXT provenance or independent baseline readiness. R102 consumes structured question shape and bounded source/root windows; the existing frozen V1 failure (4/6 recognition) remains historical, V2 external capture/review remains pending absent new evidence. Added separate synthetic raw IPv4 UDP A-query integration control using existing PacketHandler test frame builder: ordinary short query must not match, 62-character high-entropy query must match, capture-attested A question must not bypass unready baseline in SmallBusiness. No production predicates, floors, scored corpus or frozen fixtures changed. This is parser integration, not independent capture or malicious ground truth. Windows pending: `dotnet test .\\Carthago.Tests\\Carthago.Tests.csproj -c Release --filter "FullyQualifiedName~Ga09DnsCaptureBoundaryTests|FullyQualifiedName~R102DistinctTxtCorrelationTests|FullyQualifiedName~DnsCaptureQualificationTests"`. Last detection-quality owner verification c164be6 12,371/12,371; GA-08/09 pending. Next: audit live baseline readiness source and TXT capture boundary; independent V2 PCAPs and reviewed labels still required. No assistant execution.


## 2026-11-13 — GA-09d scoped baseline readiness primitive (R102/R103)

Reviewed parent `5b33055cced30308ec5bc9244a230b53bfe837aa`. RuleEngine.Tuning currently passes global BaselineStore.Readiness into tuning and baseline promotion; global history pools all kinds and subjects, so unrelated history can satisfy readiness. Added exact kind/subject scoped persisted-readiness API, sharing existing count/diversity/span/staleness/corruption/learning checks. Regression demonstrates global readiness cannot supply another subject or kind, scoped history survives reopen and clear removes readiness. No live promotion wiring yet: capture provenance, subject/interface identity and actual observation producer must be established first; persisted history is not trusted benign ground truth. No change to R102/R103 predicates, 80% R102 floor, corpus or frozen holdouts. Windows pending: `dotnet test .\\Carthago.Tests\\Carthago.Tests.csproj -c Release --filter "FullyQualifiedName~BaselineStoreTests|FullyQualifiedName~Ga09DnsCaptureBoundaryTests"`. Next inspect observation call sites and integrate fail-closed scoped readiness only with justified provenance; GA-08/09 owner execution pending, last verified detection-quality c164be6. No assistant execution.

## 2026-11-13 — GA-09e live DNS baseline fail-closed gate

Reviewed live parent `6d32c4a497f378f44c3abbc7d340dfec052ad658`, qualification gate and DNS precision base. RuleEngine.Tuning consumes global readiness; DNS precision base persists observations through ObserveAsync without an independent benign/source-interface attestation. GA-09d exact kind/subject counts alone cannot establish provenance; suspicious observations can contribute to persisted history. R102/R103 live tuning now explicitly receives unavailable readiness until a qualified source/interface DNS baseline producer exists; other rules retain prior readiness. This intentionally prevents automatic live alert promotion even with mature global history, including explicit Alert mode through existing baseline policy. Raw recognition, confidence floors, benchmark calibrated simulations and frozen holdouts unchanged. Added three regression cases for live readiness selection (R102/R103 and unaffected R104); Windows execution pending. No new owner detection-quality result in ledger; c164be6 remains historical verified baseline. Next: qualified benign DNS intake with source/interface identity and replay isolation; independent V2 captures still required. Run `dotnet test .\\Carthago.Tests\\Carthago.Tests.csproj -c Release --filter "FullyQualifiedName~Ga09LiveBaselineGateTests|FullyQualifiedName~BaselineStoreTests|FullyQualifiedName~RuleTuningCatalogTests"`. No assistant execution.

## 2026-11-13 — Enrichment historical coverage migration controls

Reviewed parent `c80f3e788453a6d4a205ab3d55c7cf78e5c0acbc`, V3 reader and comparison. Missing coverage entries for retained communication sessions now withhold absence-based novelty, rather than implicitly assuming zero rejections. Synthetic comparison fixtures explicitly supply zero-rejection coverage. Added missing-coverage regression and four serialized V2/V3 reader cases (legacy unknown, missing/negative V3 counters, nonzero persisted counter). Windows execution pending; no new owner verification. Next: actual saturated registry round-trip and V1 fixture, then runtime/export qualification. No detector changes.

## 2026-11-13 — GA-09f durable baseline failure boundary

Reviewed live parent `cc57320650ad0e73accc9235721e83d15119e529`, qualification gate Q9, BaselineStore and live DNS gate. Concrete defect: failed observe append sets cached readiness unavailable but GetReadinessAsync/GetScopedReadinessAsync recompute from old entries and can restore readiness; failed clear append did not invalidate readiness at all. Latch persistence uncertainty for the lifetime of the store, include in shared readiness calculation, and invalidate on failed clear. Later successful writes do not erase ambiguity; reopening reloads journal and existing corruption checks apply. Two Windows file-lock regression cases cover observe/clear, global/scoped refresh, unchanged counts and subsequent successful write. No rule IDs changed; R102/R103 live fail-closed remains, floors and holdouts unchanged. This is a prerequisite for qualified DNS intake, not a benign producer or promotion. Next: explicit capture-source/interface identity and reviewed benign intake; R118/R163 producers and V2 external evidence remain outstanding. Last owner detection-quality checkpoint c164be6; no new execution. Windows pending: `dotnet test .\\Carthago.Tests\\Carthago.Tests.csproj -c Release --filter "FullyQualifiedName~BaselineStoreTests|FullyQualifiedName~Ga09LiveBaselineGateTests"`.

## 2026-11-13 — Enrichment checkpoint end-to-end regression fixtures

Reviewed live parent `eebfcc257fc7eee3dd27b3bdede4bf966bca7000`, checkpoint writer/reader and external comparison. Added original-schema V1 asset-only filesystem fixture (no communication or capacity fields) and actual saturated 2,048-destination registry save/reopen/compare regression with two rejected observations. Asserts positive retained evidence survives while absent destination novelty is withheld. Test-only increment; no production or detector changes. Windows execution pending; no new pass claims. Next: retained-session completeness presentation and runtime/export qualification. Run `dotnet test .\\Carthago.Tests\\Carthago.Tests.csproj -c Release --filter "FullyQualifiedName~AssetHistoryStoreTests|FullyQualifiedName~ExternalCommunicationTests"`.

## 2026-11-13 — GA-09g baseline reload integrity

Reviewed live parent `aea58d55bc7771d516df6a58394b296d2f2f7ba1`, GA-09f and qualification gate. Before adding a qualified DNS intake, fix two shared persistence hazards: interrupted initial load could leave partially accumulated journal entries and double-count on retry; syntactically valid JSON records with arbitrary noncanonical keys could count toward global readiness and evade exact scope. Reset partial load state before retry; validate persisted keys as canonical three nonblank string components for snapshots and journals, reject null snapshot entries, retain corruption blocker. Two regression cases inject invalid keys into snapshot/journal alongside valid DNS history; global and scoped readiness must remain unavailable and count only valid history. No rule IDs, thresholds, corpus or holdout changes. R102/R103 live fail-closed remains; qualified benign intake and independent captures, R118/R163 producers still pending. Windows execution pending: `dotnet test .\\Carthago.Tests\\Carthago.Tests.csproj -c Release --filter "FullyQualifiedName~BaselineStoreTests|FullyQualifiedName~Ga09LiveBaselineGateTests"`. Last owner detection-quality baseline c164be6; no assistant execution. Next: explicit source/interface and reviewed benign intake contract, without enabling live promotion.


## 2026-11-13 — Enrichment retained-session coverage presentation

Reviewed live parent `fd793982094b35eb8c19bc668171dc9b709392be`, checkpoint reader, comparison and investigation refresh. Add a pure summary of retained checkpoint coverage to the existing history status: legacy asset-only sessions, communication-capable sessions, sessions with destination rows, unknown/zero/positive capacity rejection counts independently for assets and destinations. Counts describe retained files, not eligible comparison sessions or network completeness. No additional disk reads or detector changes. Two focused tests cover mixed V1/V2/V3 and empty/read-error snapshots. Windows execution pending. Next: runtime/export provenance qualification. Run `dotnet test .\\Carthago.Tests\\Carthago.Tests.csproj -c Release --filter "FullyQualifiedName~AssetHistoryCoveragePresentationTests|FullyQualifiedName~AssetHistoryStoreTests|FullyQualifiedName~ExternalCommunicationTests"`.

## 2026-11-13 — GA-09h persisted observation semantic integrity (R102/R103 prerequisite)

Reviewed live parent `4b357b3fe2523c6378de608db77bcee0bbebde58`, qualification gate and GA-09g. Invalid snapshot counts/timestamp ordering or future timestamps previously entered the store and could be masked by later valid observations (e.g. zero count becomes one); invalid journal timestamps likewise entered history. Reject these records at load, retain corruption blocker, preserve valid counts. Two synthetic filesystem regression cases (zero-count snapshot and future journal observation followed by valid observation); expected global/scoped unavailable, one valid count. No execution, no rule predicate/floor changes, no live promotion, no corpus/holdout changes. Qualified benign intake remains pending: separate namespace, authenticated capture/interface/network identity, reviewed benign evidence and replay isolation required; no generic trust flag introduced. R118/R163 producers and V2 independent evidence remain open. Windows pending: `dotnet test .\\Carthago.Tests\\Carthago.Tests.csproj -c Release --filter "FullyQualifiedName~BaselineStoreTests|FullyQualifiedName~Ga09LiveBaselineGateTests"`. Historical detection-quality verified c164be6; no newer owner result inferred.

## 2026-11-13 — Enrichment export provenance and denominator

Reviewed live parent `c4f61c698b7bb1ded603da81da53f54d45bf6636`, TrafficRecord, session snapshot, Excel DataQuality and existing session-file tests. Enrichment sheet previously filtered out entirely missing rows and omitted endpoint scope, lookup target/status, ASN, attribution and capture/DNS/TLS provenance. Extract passive projection for every retained traffic row; preserve nulls and original fields, no inference or detector changes. Two focused tests cover inbound lookup target versus destination, independent WHOIS/GeoIP country, attribution and missing-row denominator. Windows execution pending. Next: actual XLSX round-trip and runtime capture/export consistency. Run `dotnet test .\\Carthago.Tests\\Carthago.Tests.csproj -c Release --filter "FullyQualifiedName~CarthagoEnrichmentExportTests|FullyQualifiedName~CarthagoSessionFileTests"`.
