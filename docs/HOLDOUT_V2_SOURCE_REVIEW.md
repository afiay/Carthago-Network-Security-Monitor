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

- `dns_tunnel_file_transfer/86950175ba9bf6b4aaea5478bbd49ad7/86950175ba9bf6b4aaea5478bbd49ad7_full_dataset.tar.gz` (3,178,726 bytes; metadata `record_type: txt`, `encoding: base32`).
- `dns_tunnel_file_transfer/c6a08caf0d52af99dfd2487f2b48c54a/c6a08caf0d52af99dfd2487f2b48c54a_full_dataset.tar.gz` (3,065,396 bytes; metadata `record_type: txt`, `encoding: base64`).

Repository: https://github.com/Korving-F/dns-tunnel-dataset. **No original archive contents were independently decoded in this review; no raw archive license or publication clearance was established.** Both metadata files reference the same lab client `192.168.0.30`, so neither should be assumed to supply the required *second independently captured malicious client*. Separate benign PCAP sources likewise remain unverified. Do not import either archive into a v2 slot without rights review, isolated inspection, SHA-256 receipt and original-packet TShark audit. No source approval is implied by this ledger entry.

**V2 status remains `PENDING_EXTERNAL_CAPTURE_AND_REVIEW`, 0/4 approved and packet-audited external R102 fixture/provenance pairs.**
