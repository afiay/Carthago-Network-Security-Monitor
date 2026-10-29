# Lossless DNS Wire Names and Frame Provenance Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Preserve every DNS QNAME label octet, verify imported names against immutable captured frames, and let R102 evaluate valid binary-label DNS questions without weakening existing detection controls.

**Architecture:** Introduce a small immutable byte-label codec in the existing C# project, while keeping `TrafficRecord.DnsQname` and legacy ASCII paths stable. Store reversible per-label Base64 only in explicit private evidence paths; bind it to the source PCAP SHA-256, frame number and DNS question index. Validate V2 sources independently through bounded TShark raw-frame export plus PowerShell checks, never by detector outcome.

**Tech Stack:** .NET 8 / C# / xUnit, Windows PowerShell, TShark, existing GitHub branch `feature/carthago-reliability-hardening`; no new NuGet or PowerShell dependencies.

**Spec:** `docs/superpowers/specs/2026-10-29-dns-wire-name-provenance-design.md`

## Global Constraints

- Work only on `feature/carthago-reliability-hardening`; do not create branches, merge or delete branches in this task.
- Preserve frozen V1 and its recorded failure, all pinned hashes, V2 `PENDING_EXTERNAL_CAPTURE_AND_REVIEW`, R102 runtime thresholds/confidence weights, the V2 acceptance floor `0.75`, and all existing benign exclusions.
- Production tests must be red-first, then green, before claiming any code change correct. **Do not start full repository verification or frozen holdout evaluation until the owner explicitly says it is test time.**
- No external PCAP is approved merely for being well-formed. Independent malicious/benign labels, source licensing, privacy and logical-client independence remain separate human review gates.
- Protect binary QNAME contents: standard Base64 is reversible, never an acceptable redaction. Ordinary event/log/report serialization must omit raw labels, source addresses and binary QNAME displays.
- Commit each changed file separately, with a descriptive file-specific message. Do not modify unrelated detector rules or the established application architecture.
- Original capture SHA-256: `b9c5ec5b6a50facb8719ffe47656d2cda0f0704ed08d91130c8b48a3e0ddf102`; source Git blob: `c061d953b9e21068031d604b9c1001ddcd1cfa53`.

## File map

| File | Responsibility |
| --- | --- |
| `Carthago/Services/DnsWireNameCodec.cs` (new) | Immutable label bytes, Base64, DNS wire parser, ASCII-case identity and safe text projection |
| `Carthago/Models/TrafficRecord.cs` | Optional non-default-serializable wire-label property |
| `Carthago/Services/PacketHandler.cs` | Replace lossy DNS label conversion; retain existing ASCII behavior |
| `Carthago/Engine/Rules/Abstractions/NetworkBatch096100Evidence.cs` | Opt-in structural DNS wire-name validation for R102 only |
| `Carthago/Engine/Rules/Dns/R102_DNSTunnelingViaLongLabelsRule.cs` | Byte-aware metrics and non-disclosing event evidence |
| `Carthago/Services/Benchmarking/DnsReplayTelemetryDiagnostics.cs` | Explain missing vs valid-wire telemetry with metadata-only diagnostic codes |
| `Carthago/Services/Benchmarking/DnsWireReplayHydrator.cs` (new) | Private, schema-gated wire-name hydration in replay loading |
| `Carthago/Services/Benchmarking/{RuleReplayRunner,TuningBenchmarkRunner}.cs` | Use the explicit private hydration path when reading reviewed V2 records |
| `scripts/DnsWirePcap.psm1` (new) | Bounded TShark raw-message extraction and independently checked label parsing |
| `scripts/{inspect,import,audit}-holdout-v2-*.ps1` | Report syntax exclusions separately and require exact original-frame evidence |
| `scripts/{evaluate,freeze,inspect}-holdout-v2-*.ps1` | Versioned V2-only schema/freeze integrity checks; no implicit approval |
| `Carthago.Tests/DnsWireNameCodecTests.cs` (new) | Raw byte round-trip, limits, compression and identity |
| `Carthago.Tests/DnsWirePacketTests.cs` (new) | Legacy compatibility and captured UDP/TCP parsing |
| `Carthago.Tests/R102BinaryDnsPrecisionTests.cs` (new) | Exact-byte detection metrics, negative controls and redaction |
| `Carthago.Tests/DnsWireReplayHydratorTests.cs` (new) | Private serialization consistency and tamper failures |
| `Carthago.Tests/SyntheticHoldoutV2ContractTests.cs` | Strict V2 schema and source-audit invariants |
| `scripts/verify-dns-wire-source-contract.ps1` (new) | Read-only synthetic-PCAP/TShark source and provenance assertions |

## Review Focus

Five failure modes especially likely to escape a straightforward happy-path test; each is pinned to the task that owns it:

1. A 63-byte label followed by other labels crosses the **255-byte decompressed name** boundary — Task 1, `Rejects_Overlong_Decompressed_Name`.
2. A compressed name pointer loops or points forward — Task 1, `Rejects_Compression_Cycle_And_Forward_Pointer`.
3. A legacy name and Base64 labels contradict one another — Task 4, `Rejects_Conflicting_Legacy_And_Wire_Names`.
4. Two source IPs merely mirror the same QNAME set — Task 6, `Rejects_Mirrored_Clients_As_Independent_Evidence`.
5. An event or general JSON export exposes reversible binary names — Tasks 2 and 3, `Default_Serialization_Omits_Wire_Labels` and `R102_Binary_Evidence_Contains_No_Raw_Qname`.

---

### Task 1: Lossless DNS label codec and identity

**Files:** Create `Carthago/Services/DnsWireNameCodec.cs`; create `Carthago.Tests/DnsWireNameCodecTests.cs`.

**Interfaces:** `internal sealed class DnsWireName` holding defensive copies of ordered label octets; `internal static class DnsWireNameCodec` exposing `TryFromBase64Labels(IReadOnlyList<string>?, out DnsWireName?, out DnsWireNameError)`, `TryReadQuestion(ReadOnlySpan<byte>, int, out DnsWireName?, out int, out DnsWireNameError)`, `ToBase64Labels(DnsWireName)`, `CanonicalIdentityKey(DnsWireName)` and `TryGetSafeAsciiQName(DnsWireName, out string?)`. `DnsWireNameError` is a fixed enum of non-disclosing causes.

- [ ] **Step 1 — RED test:** Write `RoundTrips_Binary_Label_Byte_For_Byte` for label `[0x00,0x2e,0x5c,0x7f,0x80,0xff]`; assert exact decoded bytes and canonical Base64, not printable text. Include `Rejects_Overlong_Decompressed_Name`, `Rejects_Compression_Cycle_And_Forward_Pointer`, `Identity_Folds_Only_ASCII_Case`, `Rejects_Noncanonical_Base64` and boundary cases for 63/64-octet labels and 255/256-octet names.
- [ ] **Step 2 — Observe RED:** On CARTHAGE run `dotnet test .\Carthago.Tests\Carthago.Tests.csproj -c Release --filter "FullyQualifiedName~DnsWireNameCodecTests"`; expected missing contract or failing assertions attributable to the unimplemented codec, not a restore/environment error. Do not continue if tests cannot execute.
- [ ] **Step 3 — GREEN implementation:** Implement the two immutable types and methods above, validating exact Base64 re-encoding, wire-label length octets, decompressed length, compression bounds and case-folded length-prefixed identity. No raw bytes in exception messages.
- [ ] **Step 4 — Verify GREEN:** Run the same focused filter; require zero failures and no new warnings. Inspect exact-byte equality and cycle rejection.
- [ ] **Step 5 — Commit:** Commit the test file, then codec file, separately; preserve the red/green evidence in the change log.

### Task 2: Live DNS telemetry adapter without lossy ASCII fallback

**Files:** Modify `Carthago/Models/TrafficRecord.cs`, `Carthago/Services/PacketHandler.cs`; create `Carthago.Tests/DnsWirePacketTests.cs`.

**Interfaces:** Add `TrafficRecord.DnsWireLabelsBase64` as an optional property excluded from *default* `System.Text.Json` serialization; private replay hydration is Task 4. `DnsLight.TryParse` uses the Task 1 codec and exposes both safe ASCII `QName` and exact wire labels. Existing ASCII `DnsQname`, `DnsQtype`, transport and response fields are unchanged.

- [ ] **Step 1 — RED test:** Write `PacketHandler_Preserves_Binary_Label_Without_Question_Marks`, `PacketHandler_Preserves_Legacy_Ascii_DnsQname`, `Default_Serialization_Omits_Wire_Labels`, `Does_Not_Split_Embedded_Dot_Octet`, and UDP/TCP/framing negative cases using deterministic in-memory DNS packets.
- [ ] **Step 2 — Observe RED:** Run focused `dotnet test .\Carthago.Tests\Carthago.Tests.csproj -c Release --filter "FullyQualifiedName~DnsWirePacketTests"` on CARTHAGE; verify failures reflect the old lossy behavior.
- [ ] **Step 3 — GREEN implementation:** Replace `DnsLight.TryReadQName`'s `Encoding.ASCII.GetString` path with the codec; set `DnsQname` only when safe and keep exact labels in the new property. Do not alter transport attribution or other packet decoders.
- [ ] **Step 4 — Verify GREEN:** Rerun focused tests plus `FullyQualifiedName~PacketHandlerLinkLayerTests`; require no regressions.
- [ ] **Step 5 — Commit:** Commit each of the three files separately with `test(dns-wire)` / `feat(dns-wire)` messages.

### Task 3: R102 consumes exact bytes with unchanged thresholds

**Files:** Modify `Carthago/Engine/Rules/Abstractions/NetworkBatch096100Evidence.cs`, `Carthago/Engine/Rules/Dns/R102_DNSTunnelingViaLongLabelsRule.cs`, `Carthago/Services/Benchmarking/DnsReplayTelemetryDiagnostics.cs`; create `Carthago.Tests/R102BinaryDnsPrecisionTests.cs`.

**Interfaces:** Add `NetworkBatch096100Evidence.Dns(..., bool allowWireName = false)`; only R102 passes `true`. R102 obtains `DnsWireName` from Task 1 for label-octet length/entropy/unique-byte count, DNS identity and distinct TXT correlation, while the legacy text branch retains existing logic and confidence. Wire-name event evidence is metric-only and redacted.

- [ ] **Step 1 — RED test:** Write `R102_Detects_Three_Distinct_Binary_Txt_Names_Without_Lowering_Floor`, `R102_Binary_Evidence_Contains_No_Raw_Qname`, `R102_Mirrored_Retries_Do_Not_Add_Distinct_Confidence`, `Legacy_Dns_Rules_Reject_Unattributed_Wire_Only_Records`, and `Diagnostics_Report_Wire_Name_Without_Qname_Missing`.
- [ ] **Step 2 — Observe RED:** Run focused `FullyQualifiedName~R102BinaryDnsPrecisionTests` on CARTHAGE; require expected pre-change failures.
- [ ] **Step 3 — GREEN implementation:** Introduce a narrow wire-name validation path under the existing endpoint/transport gates; measure raw octets; preserve R102 settings, windowing, cooldown, 0.80 runtime precision minimum and 0.75 V2 floor; never place binary names in summaries or structured evidence.
- [ ] **Step 4 — Verify GREEN:** Run filters `FullyQualifiedName~R102BinaryDnsPrecisionTests|FullyQualifiedName~R102DistinctTxtCorrelationTests|FullyQualifiedName~R102AdvancedAccuracyBatchTests|FullyQualifiedName~DnsReplayTelemetryDiagnosticsTests` and compare current known expectations.
- [ ] **Step 5 — Commit:** Commit each changed file independently, with test first; no unrelated rule edits.

### Task 4: Explicit private replay hydration, not default JSON leakage

**Files:** Create `Carthago/Services/Benchmarking/DnsWireReplayHydrator.cs` and `Carthago.Tests/DnsWireReplayHydratorTests.cs`; modify `Carthago/Services/Benchmarking/RuleReplayRunner.cs` and `Carthago/Services/Benchmarking/TuningBenchmarkRunner.cs`.

**Interfaces:** `DnsWireReplayHydrator.ApplyReviewedWireLabels(JsonElement root, RuleReplaySample sample)` accepts only an explicitly versioned private V2 sample (`dnsWireNameEncoding = "labels-base64-v1"`) and one wire-label list per selected record; it validates Task 1 codec and rejects conflicting `dnsQname`. Default `TrafficRecord` serialization stays redacted/ignored.

- [ ] **Step 1 — RED test:** Write `Hydrates_Explicit_V2_Wire_Labels`, `Rejects_Conflicting_Legacy_And_Wire_Names`, `Rejects_Unversioned_Wire_Fields`, and `Default_Replay_Json_Does_Not_Leak_Wire_Labels` using small local JSON strings.
- [ ] **Step 2 — Observe RED:** Run focused `FullyQualifiedName~DnsWireReplayHydratorTests` on CARTHAGE and confirm expected failures.
- [ ] **Step 3 — GREEN implementation:** Rehydrate only under a positive version contract after normal sample parsing in both existing loaders; reject extra/ambiguous fields and never change the default sample corpus reader when no wire fields exist.
- [ ] **Step 4 — Verify GREEN:** Rerun the filter and existing `FullyQualifiedName~SyntheticHoldoutV2ContractTests`, ensuring 12-slot V2 and eight pinned V1 reuses remain identical.
- [ ] **Step 5 — Commit:** Separate test, helper and two loader commits; do not change frozen fixture data.

### Task 5: Bounded independent TShark raw-source decoder

**Files:** Create `scripts/DnsWirePcap.psm1` and `scripts/verify-dns-wire-source-contract.ps1`; modify `scripts/inspect-holdout-v2-pcap.ps1`.

**Interfaces:** `Read-DnsWireQuestion -CapturePath <path> -FrameNumber <int> -QuestionIndex <int> -TsharkPath <path>` emits only a private structured object with exact Base64 labels, captured IP/port/transport/QTYPE, the chosen frame/question index and source SHA. Read bounded `tshark -T jsonraw` `dns_raw` bytes; do not derive raw labels from `dns.qry.name` text. Validate per-frame DNS lengths and question ordering independently in PowerShell.

- [ ] **Step 1 — RED source check:** Build a deterministic synthetic PCAP containing an embedded dot, binary `0xff`, compressed QNAME, two questions and malformed-pointer controls. Assert exact labels, targeted frame/question selection, byte-match with original packet, no raw-name output and exclusive skip reasons.
- [ ] **Step 2 — Observe RED:** On CARTHAGE run `powershell.exe -NoProfile -File .\scripts\verify-dns-wire-source-contract.ps1 -TsharkPath 'C:\Program Files\Wireshark\tshark.exe'`; expect missing helper/incorrect binary-name behavior. Source-only check, not a detector run.
- [ ] **Step 3 — GREEN implementation:** Implement bounded raw-message extraction, packet and pointer validation, and separate counters for wire-invalid names versus text-policy-excluded names; retain current inspector threshold and privacy defaults.
- [ ] **Step 4 — Verify GREEN:** Rerun the synthetic source check; separately inspect a small selected-frame set from the pinned Korving PCAP and compare with TShark 4.6.9 frame/QTYPE/transport plus the already independently corroborated 7,991/5,335/2,656 query counts. Do not export raw QNAMEs.
- [ ] **Step 5 — Commit:** Each script independently with a source-specific message.

### Task 6: V2 importer/auditor and logical-source integrity

**Files:** Modify `scripts/import-holdout-v2-r102.ps1`, `scripts/audit-holdout-v2-candidates.ps1` and `Carthago.Tests/SyntheticHoldoutV2ContractTests.cs`; extend `scripts/verify-dns-wire-source-contract.ps1` with provenance cases.

**Interfaces:** Candidate records use `dnsWireLabelsBase64` plus optional consistent `dnsQname`; provenance has `dnsWireNameEncoding`, aligned `frameNumbers` and zero-based `questionIndices`, with original `captureSha256`. For malicious samples require a privacy-safe `originatingClientLabel`, `collectionSessionId`, `collectionVantage` (`client`, `resolver`, `authoritative` or `other`), and HTTPS `independentClientEvidenceUri` to support **human** source-independence review; these strings alone never establish authenticity. The Task 5 helper supplies original bytes; importer and auditor independently check frame identity, typed ports/transport, DNS QTYPE, canonical roots, full label bytes, strict allowed fields and reviewed labels/rights.

- [ ] **Step 1 — RED test:** Add `Rejects_Tampered_Frame_Question_And_Labels`, `Rejects_Mirrored_Clients_As_Independent_Evidence`, `Rejects_Duplicate_Collection_Session`, `Rejects_Unreviewed_License_And_Label`, `Rejects_Unexpected_Fixture_Fields`, `Rejects_Same_Frame_Reused`, and strict manifest invariants.
- [ ] **Step 2 — Observe RED:** Run `powershell.exe -NoProfile -File .\scripts\verify-dns-wire-source-contract.ps1 -TsharkPath 'C:\Program Files\Wireshark\tshark.exe'` and focused `FullyQualifiedName~SyntheticHoldoutV2ContractTests`; verify failures are due to missing new invariants.
- [ ] **Step 3 — GREEN implementation:** Accept verified wire labels only in private candidate preparation; re-decode original PCAP during audit. Flag completely overlapping QNAME sets from apparently different clients and fail independence approval without independently reviewed logical-client provenance. Retain the existing two-benign/two-malicious and three-distinct-long-TXT rules.
- [ ] **Step 4 — Verify GREEN:** Repeat focused source/contract checks. Run `scripts/inspect-holdout-v2-readiness.ps1` read-only and confirm V2 stays `PENDING_EXTERNAL_CAPTURE_AND_REVIEW`, 0/4 approved in absence of reviewed sources.
- [ ] **Step 5 — Commit:** One file per commit, test evidence first; do not import or freeze the Korving source.

### Task 7: V2 evaluator and freeze gate compatibility

**Files:** Modify `scripts/evaluate-holdout-v2.ps1`, `scripts/freeze-holdout-v2.ps1`, `scripts/inspect-holdout-v2-readiness.ps1`; extend `Carthago.Tests/SyntheticHoldoutV2ContractTests.cs`; update `docs/HOLDOUT_V2_PROTOCOL.md` and `docs/HOLDOUT_V2_SOURCE_REVIEW.md` only to describe verified contracts.

**Interfaces:** Existing V1 evaluation remains the default. Only a separately reviewed `labels-base64-v1` V2 source record can reach the pending readiness gate; evaluator never grants approval or changes confidence floors; freeze refuses unreviewed or non-attributable originals.

- [ ] **Step 1 — RED test:** Add `V1_Hashes_And_Default_Evaluation_Are_Unchanged`, `V2_Rejects_Missing_Original_Pcap_Or_Question_Ordinal`, `V2_Rejects_Unsupported_Wire_Name_Encoding`, and `V2_Pending_Never_Auto_Freezes`.
- [ ] **Step 2 — Observe RED:** Run focused `FullyQualifiedName~SyntheticHoldoutV2ContractTests` on CARTHAGE. Do not call the production freeze or holdout evaluation scripts.
- [ ] **Step 3 — GREEN implementation:** Extend V2-only strict schema and provenance checks, preserve rollback behavior and `PENDING` state, document the versioned representation and independent source gates.
- [ ] **Step 4 — Verify GREEN:** Run focused tests and read-only readiness only. Recheck Git blob hashes of every frozen V1 file and unchanged V2 12-case manifest; do not make a source-certification claim.
- [ ] **Step 5 — Commit:** Commit every modified file separately with its own message.

## Whole-feature verification and controlled handoff

- [ ] Verify all seven tasks' focused checks on CARTHAGE, with exact test counts, warnings, scripts' exit codes and SHA recorded; no assertion of success from code review alone.
- [ ] Perform targeted *source-only* TShark corroboration on selected pinned frames with privacy-safe aggregate output. Keep the original capture and source receipt under ignored `build-verify`.
- [ ] **Only after the owner's explicit test-time authorization:** run the standard full Windows repository verifier and any isolated V1/V2 evaluations separately. Preserve and report the known frozen V1 miss; V2 must fail closed while 0/4 source pairs remain unapproved.
- [ ] Complete an independent whole-branch code review, reconcile documentation, then ask before merging into `main`; do not create additional branches.

**Execution method:** Native, sequential implementation on the existing branch (no subagent dispatch). Pause before implementation until the project owner approves this plan and authorizes the intended focused red/green test stage.
