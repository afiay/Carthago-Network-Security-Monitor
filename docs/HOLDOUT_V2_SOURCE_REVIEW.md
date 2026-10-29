# R102 holdout v2 — source review and acquisition ledger

**Status: source candidates only, not certified (2026-10-27).**
No new external PCAP was imported into the frozen v2 holdout, and no
independent label, privacy clearance or packet eligibility was approved.
The failed original v1 evaluation remains unchanged.

The v2 requirement is two benign and two malicious independently
documented DNS packet traces with explicit UDP/TCP transport and packet
frame attribution. Avoid claiming that mere DNS shape proves malignancy.

## Candidate source review

| Source | Available evidence | Limitation and decision |
| --- | --- | --- |
| **Elastic iodine DNS tunnel** | The Apache-2.0-licensed [elastic/examples](https://github.com/elastic/examples) repository contains a 77,524-byte demonstration [dns-tunnel-iodine.pcap](https://github.com/elastic/examples/blob/master/Security%20Analytics/dns_tunnel_detection/dns-tunnel-iodine.pcap), pinned at commit 6d86454ebb7a850bcd7e80abe86fe683370018a6, Git blob f43152b995d0eb9127d5a8fcaf13e5c26595ce69. A [third-party report](https://apackets.com/reports/iodine-dns-tunnel) for a same-named 75.71-KB capture (SHA-256 91fd221e07107507c8327a9d9487cd7f7531a1fd87cf543b1a76160ff0609b7b) documents **222 NULL-only (type 10) DNS queries; zero TXT**. | **Protocol-diversity control, NOT an eligible encoded-TXT candidate if hashes match.** Recheck source SHA-256 and QTYPE locally; privacy and archive-specific rights still need review. |
| **Thapar campus DNS** | [Mendeley DOI 10.17632/zh3wnddzxy.2](https://data.mendeley.com/datasets/zh3wnddzxy/2) describes hourly campus DNS PCAPs under CC BY 4.0. | Candidate benign traffic, but campus captures may expose browsing habits and source identities. Benign label, privacy and packets need review. No automatic publication. |
| **GraphTunnel** | [Repository](https://github.com/ggyggy666/DNS-Tunnel-Datasets) describes large benign, known-tunnel and unknown-tunnel PCAP groups. | Data rights are not established by the README's citation request alone. **Do not import** before licensing review. |
| **Korving-F DNS tunnel captures** | [Repository](https://github.com/Korving-F/dns-tunnel-dataset) publishes controlled port-53 iodine, dns2tcp and dnscat2 captures. Two directly inspected scenario metadata files declare iodine `record_type: txt` with `encoding: base32` ([86950175 scenario](https://github.com/Korving-F/dns-tunnel-dataset/blob/master/dns_tunnel_file_transfer/86950175ba9bf6b4aaea5478bbd49ad7/.metadata)) and `base64` ([c6a08caf scenario](https://github.com/Korving-F/dns-tunnel-dataset/blob/master/dns_tunnel_file_transfer/c6a08caf0d52af99dfd2487f2b48c54a/.metadata)). Their scripted clients use `-Ttxt` and run under the `example.attack` lab domain. | **Higher-priority TXT research candidates**, not approved samples. Those lab scenarios reuse client IP `192.168.0.30`, so they do not satisfy the independent-client requirement on metadata alone. Raw archive rights, actual packets and QNAME structure are not yet validated. **Do not import** before review. |
| **UFU DNS-360** | [Repository](https://github.com/CborgesUFU/DNS-360-Dataset) includes PCAPs with a dataset-specific CC BY-NC 4.0 license. | **Exclude from unrestricted commercial incorporation** without separate permission. |
| **Rocha DNS Exfiltration** | [Mendeley DOI 10.17632/v2cy9y58t7.2](https://data.mendeley.com/datasets/v2cy9y58t7/2) is CC BY 4.0 and describes labeled DNS exfiltration traffic. | Its published CSV release is not independently verified raw PCAP evidence. **Ineligible as a PCAP without originals.** |
| **DNSTunnel2026** | [Zenodo](https://zenodo.org/records/20137065) documents enterprise DNS logs and synthetic tunneling, CC BY 4.0. | Published processed train/test data are not independently verified original PCAPs. **Ineligible until actual captures are confirmed.** |

This is a factual screening record, not legal advice. Published data can
contain confidential DNS queries or third-party IPs; redistribution and
privacy rights require separate review.

The Korving-F scenario metadata demonstrates a TXT-mode *configuration*,
not confirmation that every corresponding DNS packet or all long labels
actually appear in the archives. Selecting a training/holdout sample
must be based on independent source provenance and original packet decode,
not on whether Carthago reports a match.

## Acquiring one pinned PCAP without running any Carthago tests

The read-only acquisition script fetches exactly the Elastic demonstration
PCAP by immutable Git commit, checks byte count and content blob hash,
and saves a receipt and raw capture under the ignored build-verify folder.

~~~powershell
.\scripts\acquire-holdout-v2-source-candidates.ps1 -Source ElasticIodine
~~~

The capture can then be inspected offline with bounded TShark decoding.
By default this emits aggregate counts without raw source addresses or
full DNS QNAME strings. It does NOT classify, test or freeze any record.

~~~powershell
.\scripts\inspect-holdout-v2-pcap.ps1 -CapturePath 'build-verify/holdout-v2-sources/elastic-iodine-6d86454ebb7a.pcap' -MaximumPacketsToScan 100000
~~~

The downloader now records whether the acquired SHA-256 matches the
published NULL-only report and warns if so. This iodine capture is useful
as a protocol-diversity negative/control, but **must not** be entered into
a malicious encoded-TXT slot. Its status remains an unreviewed candidate.
A different source containing fewer than three distinct long TXT queries,
only CNAME/NULL traffic, or unapproved private identifiers is **not eligible**
for either frozen malicious encoded-TXT slot.

## Mandatory acceptance chain

Source and license confirmation → independent label evidence → original
PCAP SHA-256 and frame decoding → privacy approval → packet-matched JSON
candidate → separate v2 Git hash freeze → manually authorized isolated
holdout run. V1 never changes and v2 does not establish field precision.
See HOLDOUT_V2_PROTOCOL.md for original-capture audit requirements.

## CARTHAGE actual Elastic iodine acquisition and packet inspection (2026-10-29)

**Reference source: acquired and hash-verified, but ineligible for encoded-TXT v2 slots.** The operator ran `scripts/acquire-holdout-v2-source-candidates.ps1 -Source ElasticIodine` on CARTHAGE. The reported downloaded capture is `build-verify/holdout-v2-sources/elastic-iodine-6d86454ebb7a.pcap`; the script produced its source receipt separately. Reported SHA-256: `91fd221e07107507c8327a9d9487cd7f7531a1fd87cf543b1a76160ff0609b7b`. This matches the independently published analysis of the same NULL-only iodine capture: https://apackets.com/reports/iodine-dns-tunnel. Verified integrity is *not* evidence of permissions, representativeness, source independence, independent labeling or suitability for TXT exfiltration.

Subsequent bounded, privacy-conscious offline inspection used installed TShark 4.6.9 at `C:\Program Files\Wireshark\tshark.exe` and `scripts/inspect-holdout-v2-pcap.ps1 -MaximumPacketsToScan 100000`. Operator output: **one DNS source/root group, 41 skipped/invalid frames, zero groups with at least three distinct long TXT QNAMEs**. It created a local profile under ignored `build-verify/holdout-v2-profiles/`. These are an inspector's reported counts, not a full-capture eligibility certification. No alerts, classification approvals, freeze or v2 fixture changes occurred. **Do not use this capture for either malicious encoded-TXT slot.** It may be retained only as a separately reviewed protocol-diversity/negative-control research input, without changing frozen v1.

### Next inspected-but-unapproved TXT-mode source locations

The existing Korving-F source ledger identified two controlled iodine configurations specifying `-Ttxt` and Base32 / Base64, respectively. GitHub was checked again at source commit `bdc4486751f5e87fa6100b17dd57fc001743b43c` to confirm both corresponding public archive objects exist:

- `dns_tunnel_file_transfer/86950175ba9bf6b4aaea5478bbd49ad7/86950175ba9bf6b4aaea5478bbd49ad7_full_dataset.tar.gz` (3,178,726 bytes; metadata `record_type: txt`, `encoding: base32`); Git blob `c061d953b9e21068031d604b9c1001ddcd1cfa53`).
- `dns_tunnel_file_transfer/c6a08caf0d52af99dfd2487f2b48c54a/c6a08caf0d52af99dfd2487f2b48c54a_full_dataset.tar.gz` (3,065,396 bytes; metadata `record_type: txt`, `encoding: base64`); Git blob `3f2a09fd86f1b7ac16adab963967c153b3e707fa`).

Repository: https://github.com/Korving-F/dns-tunnel-dataset. **No original archive contents were independently decoded in this review; no raw archive license or publication clearance was established.** Both metadata files reference the same lab client `192.168.0.30`, so neither should be assumed to supply the required *second independently captured malicious client*. Separate benign PCAP sources likewise remain unverified. Do not import either archive into a v2 slot without rights review, isolated inspection, SHA-256 receipt and original-packet TShark audit. No source approval is implied by this ledger entry.

**V2 status remains `PENDING_EXTERNAL_CAPTURE_AND_REVIEW`, 0/4 approved and packet-audited external R102 fixture/provenance pairs.**

## CARTHAGE Korving TXT Base32 archive verified and inventoried (2026-10-29)

The operator downloaded the immutable-commit published archive to the locally ignored `build-verify/holdout-v2-sources/korving-iodine-txt-base32.tar.gz`, then independently ran `git hash-object --no-filters` against the expected source Git object `c061d953b9e21068031d604b9c1001ddcd1cfa53`. The comparison succeeded. This verifies **archive integrity against the pinned upstream Git blob**, not the embedded PCAP's individual SHA-256 or suitability.

The operator ran `tar -tzf` (list only). It reported the exact archive member `86950175ba9bf6b4aaea5478bbd49ad7/bind9/dns.pcap` alongside BIND9 query logs, metadata and scripts. **No embedded packet was extracted, decoded or independently analyzed in this checkpoint; none of the bundled scripts should be executed.** The upstream scenario metadata indicates TXT Base32 iodine, but that is not packet-level proof of qualifying long TXT queries.

Next safe action: extract **only** the named `bind9/dns.pcap` member under the ignored local `build-verify/holdout-v2-sources/korving-base32-extract` directory, compute its independent SHA-256, and inspect using the existing read-only `scripts/inspect-holdout-v2-pcap.ps1` with the fully qualified installed TShark 4.6.9 executable. Keep extraction output private; do not upload raw DNS/IP data or evaluate detection. The exact source archive member is pinned above; avoid extracting the entire tarball or executing scripts.

**Status remains 0/4 v2 reviewed source/provenance pairs.** Archive integrity and member inventory are necessary preliminaries, not label independence, source licensing, privacy clearance, R102 transport eligibility, packet-frame attribution, frozen fixture approval or holdout certification.

## CARTHAGE TXT Base32 PCAP extraction and initial inspection (2026-10-29)

**Operator-observed result, not v2 approval:** After verifying the parent archive's Git blob, CARTHAGE extracted **only** `86950175ba9bf6b4aaea5478bbd49ad7/bind9/dns.pcap` to the ignored `build-verify/holdout-v2-sources/korving-base32-extract/` directory. `tar -xzf` exited successfully, the PCAP existed, and `Get-FileHash -Algorithm SHA256` returned a PCAP hash beginning `B9C5EC5B6A50FACB8719FFE47656D2CDA0F0704ED08D91130C8B48A3` (operator's PowerShell table truncated the remaining characters). **The full PCAP SHA-256 has not yet been captured in the transcript and must not be inferred or pinned from this prefix.**

The user ran `scripts/inspect-holdout-v2-pcap.ps1` with installed TShark 4.6.9 and `-MaximumPacketsToScan 100000`. Output: **2 DNS source/root groups**, **2656 skipped/invalid frame rows**, and **0 groups containing at least 3 distinct long TXT QNAMEs**. A privacy-conscious report was written only under ignored `build-verify/holdout-v2-profiles/dns-*.json`. The inspection does not disclose root names, source addresses or raw QNAMEs. No Carthago detection test, v2 freeze, classification approval, or holdout sample import ran.

**Disposition:** candidate is **unqualified on the currently accepted decoded subset**, NOT proven categorically unsuitable. The inspector combines malformed/unsupported fields and duplicate rows into one skipped count and does not break down skip causes; it cannot prove the 2656 skipped rows contain no valid TXT queries. Verify aggregate TShark query-type counts and cause categories (e.g., missing transport, unsupported/duplicated DNS questions, invalid DNS names) before deciding whether to exclude the original PCAP. Keep the original under `build-verify/` and do not alter packet fields, parser thresholds or corpus labels to produce a positive result. It cannot populate a v2 source slot until independent label, rights/privacy and packet-frame audit requirements have all passed.

**No change to acceptance:** v2 still has 0/4 approved external source/provenance pairs; original frozen v1 failed result is preserved.

## CARTHAGE Base32 PCAP query-type and DNS label audit (2026-10-29)

Additional operator-provided *read-only* TShark output establishes that the extracted PCAP SHA-256 is **`b9c5ec5b6a50facb8719ffe47656d2cda0f0704ed08d91130c8b48a3e0ddf102`** (full 64 hex characters). TShark 4.6.9 reported **7,991 DNS query records of QTYPE 16 (TXT)** under the bounded `dns.flags.response == 0 && (udp.dstport == 53 || tcp.dstport == 53)` filter. This is direct, concrete evidence that the source is **not NULL-only** like the separately verified Elastic iodine capture.

The original source inspector's two source/root groups reported:

| Anonymized group | Accepted TXT records | Distinct TXT names | Distinct TXT names with label >=50 | Maximum label length |
| --- | ---: | ---: | ---: | ---: |
| Client-001 | 2,671 | 2,664 | 1 | 56 |
| Client-002 | 2,664 | 2,664 | 1 | 56 |

**Accounting:** 2,671 + 2,664 accepted rows + 2,656 previously combined skipped/invalid rows = 7,991 filtered query records in this bounded inspection. This correspondence is not an independent guarantee that every source frame was fully parsed; the inspector may reject duplicates or malformed question fields. The two anonymized source/root groups are **not** evidence of two independently captured malicious clients, and the distinct TXT sets may overlap.

**Interpretation:** The PCAP has thousands of genuinely observed TXT queries, but only one distinct *long-label* TXT name per accepted source/root group under the current (>=50 character) shape check, versus three required by the v2 malicious R102 pre-freeze contract. It is **not eligible for either v2 malicious encoded-long-TXT slot under the observed accepted records**. This does not mean the iodine scenario was benign or that no DNS tunneling occurred; it may exercise shorter-label tunneling behavior not covered by that specific v2 contract. Do not lower R102 thresholds, relabel the sample, merge unrelated clients, or rewrite the v1 failure to force eligibility.

**New diagnostic-only inspector enhancement:** `scripts/inspect-holdout-v2-pcap.ps1` now records a mutually exclusive reason for each rejected filtered row (`repeatedFrameNumber`, missing/conflicting transport, unsupported type, malformed/invalid name, label length, source/destination) and anonymized per-group TXT longest-label histograms in relevant bands `0-19`, `20-39`, `40-45`, `46-49`, `50-53`, `54-57`, `58-63`. It retains privacy defaults, source field attribution and the original eligibility predicate. The new code and companion contract assertion are committed but **have not yet been executed on CARTHAGE**.

Use the same original PCAP and TShark executable to rerun read-only inspection after pulling the new branch revision. Compare the mutually exclusive reason counts to 2,656 and the group distinct-long counts to 1. The extra breakdown can identify parsing gaps but must not turn this PCAP into an approved v2 fixture without independent review of original frames, classification basis, license and privacy. V2 remains `PENDING_EXTERNAL_CAPTURE_AND_REVIEW`, **0/4** approved fixture/provenance pairs.

## Independent raw-wire triage of Korving Base32 source (2026-10-29)

**Research-only result; source NOT approved, V2 still 0/4.** To investigate
the 2,656 \`invalidQuestionName\` exclusions without repeating a Carthago
test, the exact pinned 3,178,726-byte archive was independently obtained.
\`git hash-object --no-filters\` returned the ledger's expected source
blob \`c061d953b9e21068031d604b9c1001ddcd1cfa53\`. Only the named
\`bind9/dns.pcap\` member was extracted; its independent SHA-256 was
\`b9c5ec5b6a50facb8719ffe47656d2cda0f0704ed08d91130c8b48a3e0ddf102\`,
identical to the CARTHAGE result. No bundled executable or source script
was run.

A separate temporary, **read-only wire-format decoder**, not TShark or
the Carthago importer, traversed the Linux-cooked PCAP records, IPv4,
UDP, DNS questions and length-prefixed/compressed DNS labels. It emitted
aggregate statistics only: no raw QNAMEs, source addresses or DNS roots.
Independent counts reconciled with the CARTHAGE inspector:

| Property | Independently decoded value |
| --- | ---: |
| Total PCAP frames | 15,942 |
| UDP/53 DNS query frames with QTYPE TXT (16) | 7,991 |
| Question names accepted by current inspector ASCII syntax | 5,335 |
| Excluded due to octets outside \`[a-z0-9_-]\` | 2,656 |
| Of those excluded, names with a longest label of 62 octets | 2,644 |
| Question names exceeding 255 DNS wire octets | 0 |
| Source/root groups (anonymized) | 2 |
| Distinct full wire QNAMEs per observed source | 3,977 |
| Distinct long-label (>=50 octets) QNAMEs per source/root | 1,311 |
| Distinct full wire QNAMEs shared by both sources | 3,977 |

**Interpretation and correction to prior subset-only assessment:**
the \`invalidQuestionName\` label means these TShark-exported names failed
the inspector's restrictive *textual character policy*. It does not
demonstrate malformed DNS framing, bad label lengths, or an invalid DNS
wire QNAME. RFC 1035 section 3.1 and RFC 2181 section 11 allow arbitrary
binary label octets within DNS length limits; see
https://www.rfc-editor.org/rfc/rfc1035.html and
https://datatracker.ietf.org/doc/html/rfc2181#section-11.
The current inspector counts only one distinct long TXT QNAME per group
because it excludes the binary-label questions before constructing the
histogram. The original wire capture contains many more such long names.
This finding does **not** justify modifying production R102 thresholds,
silently changing the established importer/auditor policy, or treating
the extra names as automatically approved holdout evidence.

The two observed source/root groups have **100% overlap in their 3,977
distinct QNAMEs**, and the upstream controlled-lab metadata identifies
one iodine client. This is consistent with duplicated/forwarded queries
on two network legs and is **not** two independent malicious clients.
Distinct source IPs alone must not substitute for independent trace
provenance. The original archive's scenario configuration, trace rights,
ground-truth labeling and privacy still require separate approval.

**Next gate:** independently corroborate the binary-label decode using
TShark's original-frame representation before any extractor change;
distinguish DNS wire-valid labels from permitted serialized replay
fields; identify independently captured, licensed and reviewed source(s)
for the two malicious and two benign V2 cases. If binary DNS name
support is considered for importer/telemetry, design an explicit
lossless representation and regression tests first. Do not alter
frozen V1, the 0.75 confidence floor, existing fixture hashes, or
the V2 pending state. No detector tests, rule evaluations, import,
freeze or promotion took place during this investigation.
