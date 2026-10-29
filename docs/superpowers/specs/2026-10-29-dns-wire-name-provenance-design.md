# Lossless DNS Wire Names and Frame Provenance — Design

**Status:** Design proposed for approval, 2026-10-29. No implementation, regression execution, source approval, or holdout freeze is authorized by this document.

## Intent

Carthago's DNS parsing, R102 evidence, and independently sourced Holdout V2 must distinguish *wire-valid binary DNS labels* from printable hostnames without losing octets or inventing source independence. A source PCAP remains the original evidence; a replay record is a checked representation of selected frames, not a replacement for the capture.

## Decision and alternatives

**Selected by the project owner: Approach A, Base64 per DNS label.** Each label is encoded independently from its original octets, so periods, backslashes, NUL, non-ASCII data and label boundaries are unambiguous. Standard RFC 4648 Base64 is used; decoders reject noncanonical variants by decoding and re-encoding to an exact match.

Considered but not selected:

- RFC 4343 `\DDD`/escaped presentation as the authoritative value: readable but error-prone if downstream code splits on periods or measures escaped-text length rather than wire octets. It remains an optional diagnostic *view*, never the audit source.
- Base64 of the compressed QNAME slice or whole DNS message as the only representation: retains encoding context but cannot independently recover a compressed name without the rest of the frame. The original PCAP plus frame reference already preserves byte-for-byte compression and framing.

## Scope and boundaries

1. Add a small, dependency-free DNS wire-name codec and strict source provenance validation. Do not replace Carthago's existing architecture or rewrite unrelated DNS rules.
2. Preserve `TrafficRecord.DnsQname` and all existing printable-ASCII behavior. Add an **optional**, explicitly versioned structured value for wire-name labels. Historical JSON without it remains valid.
3. Compute R102 label lengths, entropy, uniqueness and DNS identity from decoded label octets when a validated wire value is available; preserve current thresholds, confidence weights, benign protections and legacy string fallback.
4. Keep frozen Holdout V1, its failure history, V2 state `PENDING_EXTERNAL_CAPTURE_AND_REVIEW`, the 0.75 V2 R102 acceptance floor and the existing twelve-case V2 manifest unchanged until a separately approved, audited freeze.
5. Keep source archives, raw names and source IPs in private ignored evidence locations until license, privacy and labels are reviewed. Do not publish reversible Base64 data by default.

## Data contract

An optional `DnsWireLabelsBase64` collection on `TrafficRecord` is a sequence of Base64 strings in DNS label order (left to right). The serialized property is `dnsWireLabelsBase64`; no label separators appear in the byte values. Each decoded label has 1–63 octets. The decompressed DNS name is at most 255 octets **including one length octet per label and the terminal zero-length root label**. An empty label collection represents the DNS root only when the caller explicitly supports it; R102 still requires a meaningful query name.

Each Base64 string is standard, padded, canonical RFC 4648 Base64 of the *original* label bytes. Preserve case and all byte values in storage. Reject null entries, invalid padding/alphabet, zero-length labels, out-of-range lengths, and decompressed names over 255 octets. Reject malformed compression pointers, pointer loops and truncated DNS questions at the packet parser boundary before creating this property.

For DNS name *identity only*, fold ASCII bytes `0x41`–`0x5A` to `0x61`–`0x7A`, leaving every other octet unchanged (RFC 4343). Compare canonical sequences of length-prefixed labels; never compare reconstructed printable text or Unicode-normalized bytes. Distinct R102 TXT names are counted using this canonical wire identity, scoped by original client and independently established DNS root. Entropy, uniqueness and thresholds use original label bytes, not Base64 or escaped-display character counts.

`DnsQname` remains the established dot-joined string for names that existing parsing can represent unambiguously with printable ASCII labels. Binary labels must **not** be decoded with `Encoding.ASCII.GetString`, silently replaced with `?`, or inserted unescaped into legacy string-based rules. For such names, `DnsQname` can be absent while the new wire-name value carries the question. An RFC 4343 escaped presentation may be generated on demand for authorized inspection, never used for equality, R102 length/entropy, or default logs.

When both representations are present, a strict validator must verify that the decoded wire name and the legacy text denote the same printable DNS name under ASCII-only case folding; contradictions fail closed. Default telemetry/event/report serializers must omit or redact the reversible wire-label collection. Only an explicit, privacy-reviewed private-candidate serialization path may output it, with exact schema and maximum-size validation.

### Original-frame binding

For every imported Holdout V2 packet, keep the existing `captureSha256`, `frameNumbers`, source/destination addresses and ports, IP version, DNS QTYPE and explicit UDP/TCP attribution. Add a zero-based `questionIndices` array aligned one-for-one with the selected records (multiple DNS questions per frame must not be silently conflated). Persist the wire-label collection in the private candidate record and declare the representation version in its provenance metadata, for example `dnsWireNameEncoding: "labels-base64-v1"`.

The audit must re-read the **original capture**, validate its SHA-256, select the named frame and DNS question, independently decode the wire label bytes, and byte-compare them to decoded `dnsWireLabelsBase64`. It must also recheck transport, ports, addresses, QTYPE and record/frame cardinality. The provenance input itself is not proof: mismatches, missing originals, unsupported label types, ambiguous question indices or invalid wire encodings **fail closed**. Original wire/compression bytes remain preserved by the PCAP; a decoded label sequence is lossless for DNS-name value, not a substitute for the original compression layout.

No extra mutable fields may bypass the existing strict packet-fixture allowlist. A future schema change must explicitly extend the allowed record/provenance fields and update importer, audit, freeze and evaluator contracts together; all existing V1 and pinned V2 hashes remain verified.

### Logical client independence

An IP-address difference alone does not establish independent capture evidence. The pinned Korving-F BIND9 Base32 PCAP exposes two observed source groups with **3,977 identical distinct QNAMEs each**; such complete overlap is consistent with forwarding/mirroring. Do not allocate two malicious V2 slots from those groups. A reviewed provenance chain must identify the actual originating client, collection point, recording session, logical flow, licensing and independent malicious label basis. The audit should report suspicious cross-source QNAME overlap without silently merging flows or declaring separate clients; final independence approval requires documented analyst review and non-overlapping logical-source evidence.

## Security, privacy and performance constraints

- Base64 is reversible encoding, **not redaction**. Private profiles may contain exact labels but reports, exceptions and production event descriptions must not emit raw Base64, raw binary, raw escaped QNAMEs, source identifiers or payload content by default.
- For binary-name R102 detections, emit bounded structural metrics and stable diagnostic category codes; do not concatenate a synthetic string into `whyMatched`, event summary or `dns.qname` evidence. Existing behavior for normal printable names is preserved subject to existing policy.
- Maximum decoded DNS-name material is 255 octets per question; bound compression hops and packet-scanning work. Avoid unbounded capture imports and preserve cancellation/size limits already present.
- No automatic benign/malicious labels, rule promotion, source-license inference, or frozen sample modification follows from syntactic validity.

## Independent source corroboration (completed as research, not an acceptance gate)

The original Korving-F archive Git blob `c061d953b9e21068031d604b9c1001ddcd1cfa53` and extracted `bind9/dns.pcap` SHA-256 `b9c5ec5b6a50facb8719ffe47656d2cda0f0704ed08d91130c8b48a3e0ddf102` were reproduced. A separate raw-wire decoder counted 15,942 frames, 7,991 UDP TXT queries, 5,335 names accepted under the old text syntax, and 2,656 binary-label names excluded by it. Independent TShark **4.2.2** corroborated 7,991/5,335/2,656; CARTHAGE TShark **4.6.9** had reported the same counts. The wire decoder found 1,311 distinct long-label names per observed source/root, but both source QNAME sets overlap completely and do not prove two independent malicious clients. See `docs/HOLDOUT_V2_SOURCE_REVIEW.md`.

TShark's **exported textual QNAME alone is not a lossless wire-name contract**. Before changing production parsing or source import, use specific source-frame comparisons to prove the new codec's byte reconstruction matches original PCAP octets and TShark's frame/QTYPE/transport dissection. Never select or relabel samples according to R102 success.

## Regression tests required *before* implementation

The implementer writes focused failing tests first, observes their expected failure, then writes minimal implementation and confirms green. Full repository verification and Windows holdout execution remain separate owner-controlled gates.

1. **Byte-perfect names:** round-trip `0x00`, `0x2e`, `0x5c`, `0x7f`, `0x80`, `0xff`, ASCII casing, nested labels, and maximum legal 63/255-octet boundaries without text replacement.
2. **Canonical identity:** ASCII-case variants compare equal for DNS identity but stored bytes remain distinct; non-ASCII bytes are never Unicode-folded. Literal period within one label must not become a separator.
3. **Invalid input:** reject empty interior labels, noncanonical Base64, malformed padding, 64-octet labels, overlong names, truncated questions, compression loops, forward/invalid pointers and unsupported label types, without producing partial records.
4. **Transport/question provenance:** genuine UDP/TCP packet data round-trips; changing PCAP SHA, frame number, question index, QTYPE, source/destination, ports, label bytes or transport fails audit.
5. **Independence:** same original frame reused fails; identical mirrored QNAME sets from two source addresses are flagged as one logical-flow risk, not automatically promoted to two malicious sources.
6. **Compatibility:** ASCII names, previous R102 high-entropy/validation/benign behavior and historical V1 manifests/hashes remain unchanged. A binary name never appears as replacement-character text in old fields.
7. **Privacy:** default diagnostics, exceptions, logs, and R102 event evidence do not disclose reversible binary labels or addresses.
8. **External source corroboration:** a bounded private test against selected immutable Korving PCAP frames compares the new codec's exact label octets with original bytes and TShark frame/QTYPE fields; no sample enters frozen V2 on that basis alone.
9. **Dual-representation conflict:** a valid ASCII `DnsQname` paired with different wire-label bytes fails the import/audit path; default record/report serialization never includes reversible Base64 labels without explicit private-candidate authorization.

## Acceptance criteria and rollout

- A versioned codec/field with documented round-trip semantics and typed failure outcomes exists without breaking existing TrafficRecord deserialization.
- Targeted red-first regression tests are independently verified on Windows with the supported .NET runtime; TShark source checks are reproducible against the pinned PCAP hash.
- The source inspector clearly distinguishes hostname-text policy exclusions from DNS wire-invalid names; V2 importer/auditor accepts only explicitly represented, independently audited, privacy-reviewed packet evidence.
- R102 metrics for valid binary labels are computed from octets, with no relaxed threshold or confidence floor, and no unreviewed runtime alert promotion.
- Frozen V1 remains unchanged; V2 remains pending until all four externally sourced candidates meet independent review, frame audit and explicit freeze authorization.

## Implementation map (after design approval)

Likely touched surfaces, subject to implementation planning: `Carthago/Services/PacketHandler.cs` (`DnsLight`), a small shared DNS wire-name codec, `Carthago/Models/TrafficRecord.cs`, R102's structured DNS metrics path, `scripts/inspect-holdout-v2-pcap.ps1`, `scripts/import-holdout-v2-r102.ps1`, `scripts/audit-holdout-v2-candidates.ps1`, `scripts/evaluate-holdout-v2.ps1`, strict V2 contract tests and focused codec/packet tests. Decompose these into small, reviewable, test-first commits. Do not change unrelated detection rules.

## Authoritative references

- RFC 1035, section 3.1: https://www.rfc-editor.org/rfc/rfc1035.html
- RFC 2181, section 11: https://datatracker.ietf.org/doc/html/rfc2181#section-11
- RFC 4343, sections 2–4: https://www.rfc-editor.org/rfc/rfc4343.html
- RFC 4648 Base64: https://www.rfc-editor.org/rfc/rfc4648.html
