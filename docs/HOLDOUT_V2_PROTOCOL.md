# Holdout v2 — packet-attributed, separately frozen synthetic evaluation

## Status and scope

**Status: PENDING_EXTERNAL_CAPTURE_AND_REVIEW.** No valid v2 observations
have been acquired, reviewed, frozen or executed in this change set. The
failed v1 result (4/6 expected malicious recognitions, two missing R102)
is retained permanently as a separate historical evaluation.

V2 reuses the eight pinned synthetic v1 R118/R163 cases by their original
Git blob hashes. The four R102 slots require newly acquired, independently
labeled, packet-attributed DNS captures: two malicious and two benign.
The v2 manifest is docs/holdout-evaluation-v2-manifest.json.

V2 is NOT an independently labeled production field dataset: the eight
reused cases remain synthetic and externally sourced controlled DNS attacks
are likewise labeled by their documented provenance.

No detector rule, baseline readiness requirement, confidence floor,
approval safeguard or Shadow/Disabled configuration has been modified.

## Required evidence for every R102 v2 fixture

1. A legitimately acquired PCAP or PCAPNG with source URL, license,
   capture SHA-256, traceable creation context and documented labeling.
2. Evidence for benign or malicious classification independent of Carthago
   output. For controlled attacks record the source tool and scenario.
3. Independently captured frame numbers and DNS fields, including IP source
   and destination, actual UDP or TCP transport and source/destination ports,
   question name and query type, decoded with TShark.
4. Three or more distinct packet frames, and for malicious R102 a minimum
   of three distinct question names from the same attributed client/root.
5. A privacy and license review before any QNAME, original IP or provenance
   is published. The importer writes candidate output under build-verify/
   rather than placing sensitive data directly into the repository.

Public sources to examine (not imported or independently validated here):
- https://github.com/Korving-F/dns-tunnel-dataset — controlled iodine,
  dns2tcp and dnscat2 datasets. Verify scenario and reuse rights.
- https://wiki.wireshark.org/SampleCaptures — candidate benign DNS traces;
  check source-specific terms and captured-field suitability.
- https://github.com/CborgesUFU/DNS-360-Dataset documents actual PCAPs,
  but its dataset license is CC BY-NC 4.0 (non-commercial); do not
  incorporate it into a potentially commercial Carthago dataset without
  separately established permission. The MIT statement in the
  Korving-F project describes DACA software; do not infer the same
  license automatically covers each capture archive.
- https://data.mendeley.com/datasets/v2cy9y58t7/2 — controlled DNS
  exfiltration dataset. The published download is CSV feature data, not
  a verified PCAP; it is unsuitable for this packet-attributed importer
  unless original captures are independently obtained and authenticated.

## Prepare the four samples (no tests or freeze)

Install TShark on the analysis workstation and review source PCAPs.
Supply actual source-address and domain-suffix values from each capture.
The names MUST match all four pending R102 entries in the v2 manifest.

Example, with illustrative values to be replaced by real evidence:

~~~powershell
.\scripts\import-holdout-v2-r102.ps1 -CapturePath 'C:\evidence\reviewed-malicious-1.pcapng' -SourceAddress '10.10.10.5' -DnsRoot 'example.invalid' -Classification Malicious -Name 'holdout-v2-r102-encoded-txt-first-client' -SourceUri 'https://source.example/dataset' -SourceLicense 'Reviewed authorized dataset license' -IndependentLabelBasis 'Independently documented controlled exfiltration scenario from this source capture' -AnalystReviewedLabel
~~~

The importer extracts source, destination, transport, ports and DNS fields
directly from packet decode and writes two files for each candidate:
- build-verify/holdout-v2-import/NAME.json
- build-verify/holdout-v2-import/NAME.provenance.json

It does not freeze, execute rules, score accuracy or alter v1.
Review and redact sensitive data before publication without inventing
missing packets, transport attribution or ground-truth labels.

## Packet provenance audit and explicit freeze (not a detector test)

The freeze step requires the **original captures**, not just metadata.
Store the original .pcap or .pcapng files in a local restricted directory.
The audit checks each capture SHA-256; each selected frame against decoded
IP addresses, UDP/TCP transport, ports and DNS query fields; and uniqueness
of frame identities across all four cases. The two malicious R102 cases
must originate from different captured client IPs and contain at least
three distinct, actually captured TXT query names each.

Optional offline source-integrity audit (runs no Carthago rule tests):

~~~powershell
.\scripts\audit-holdout-v2-candidates.ps1 -CaptureDirectory 'C:\evidence\pcaps'
~~~

After review of labels, source license and potentially sensitive telemetry,
freeze explicitly with the original capture files available:

~~~powershell
.\scripts\freeze-holdout-v2.ps1 -CaptureDirectory 'C:\evidence\pcaps' -ApproveFreeze -ReviewedSensitiveTelemetry
~~~

The freeze repeats the PCAP audit before changing files, then pins hashes.
It atomically replaces the manifest and rolls back newly copied v2 files
on errors. V1 never changes. Packet authenticity does not independently
establish a malicious ground-truth label or publication permission.

The freeze refuses missing evidence and copies the new four fixture/provenance
pairs into the v2-only locations. It pins Git blob hashes and transitions
the manifest to FROZEN_V2_SYNTHETIC. It never modifies the original v1
manifest or files.

Review and commit the manifest, four R102 JSON fixtures and four
corresponding provenance JSON files TOGETHER. Record the exact Git SHA.

## Opt-in consolidated acceptance (only when testing is authorized)

The normal command keeps v1 as the default:

~~~powershell
.\scripts\verify-all-rule-batches.ps1
~~~

The new v2 selection is explicit, not automatic:

~~~powershell
.\scripts\verify-all-rule-batches.ps1 -HoldoutVersion v2
~~~

V2 fails closed when pending. Once frozen, it verifies 12 fixture blobs,
four external R102 provenance blobs, eight original v1 R118/R163 hashes,
transport and frame attribution, 6/6 malicious recognitions, zero benign
alerts and profile accounting. Full xUnit and development replay remain
separate mandatory gates. No automated runner/test invocation is permitted
before the project owner explicitly authorizes testing.

Even if v2 passes, the v1 failure remains documented. Neither synthetic
dataset establishes field precision or operational alert recall, and no
rule promotion follows automatically from synthetic success.
