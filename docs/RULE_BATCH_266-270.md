# R266–R270 — process-egress provenance, DNS failure attribution and fail-closed pipeline tamper

**CANDIDATE — UNVERIFIED.** Authored 2026-10-28 on the existing feature/carthago-reliability-hardening branch. **62 advanced xUnit facts authored** (R266=12, R267=12, R268=14, R269=14, R270=10); **ZERO executed**. No builds, xUnit, replay, benchmark, V1/V2 holdout, CI, GitHub Actions or Windows runner.

## Publication and exact paths

- Source commit: 7babe8b2bec3919b5764bdfc122eecb177af50ac; static source corrections: 756be6f511041f52740e64bb0967d40122bbddc1 and c39c7a8133b7f43e54e5b7807708ca263290f650.
- Advanced tests commit: 871432c905d2201c819f98f2ff2561912ed05d96 (62 authored; 0 executed).
- Production: Carthago/Engine/Rules/Expansion/NetworkBatch266270Evidence.cs, Carthago/Engine/Rules/Expansion/EvasionInfraPrecisionDetectionRuleBase.cs, and R266_NewProcessInitiatingNetworkEgressRule.cs, R267_SuspiciousProcessNameNetworkEgressRule.cs, R268_DnsOrHttpFromScriptInterpreterRule.cs, R269_SecurityToolUpdateBlockIndicatorRule.cs, R270_DetectionPipelineTamperingIndicatorRule.cs in that same directory.
- Tests: Carthago.Tests/NetworkBatch266270Context.cs and Carthago.Tests/R266AdvancedAccuracyBatchTests.cs through R270AdvancedAccuracyBatchTests.cs.
- Ledger: docs/RULE_HARDENING_PROGRESS.md. The single deferred Windows verifier remains scripts/verify-all-rule-batches.ps1, with dynamic advanced-test discovery and PowerShell 5.1-compatible syntax; it was **not executed**.

## Observable contracts and authored scenarios

**R266 (12):** Private-source to public-destination typed TCP, nonzero process PID and normalized process basename; first observation of source/PID/basename in this detector instance. Tests: first observation positive, repeated observation rejected, independent PID, packet Info spoof, missing PID, benign browser, internal destination, UDP contradiction, malformed process, replay ID, raw path/Info redaction, unchanged profile. **First observed is not a new process launch, durable approved baseline or maliciousness.** Live process enrichment unverified.

**R267 (12):** Exact allowlisted masquerade-like process basename co-observed with typed external TCP and nonzero PID. Tests: exact positive, benign real svchost, substring spoof, Info spoof, missing PID, internal destination, UDP contradiction, duplicate, out-of-order, Windows basename normalization, path/Info redaction, unchanged profile. **No trusted signer/hash/executable verification.**

**R268 (14):** Exact script-interpreter basename and PID with parser-attributed **cleartext HTTP request** or typed outbound DNS query to external resolver. Tests: two positive typed contracts, HTTPS-port-only negative, DNS-port-only negative, process substring spoof, Info spoof, missing PID, internal destination, UDP/HTTP contradiction, DNS response exclusion, invalid QNAME, replay, redaction, unchanged profile. **HTTPS is not decrypted; co-observation does not prove script execution.**

**R269 (14):** Three distinct DNS **response** packet IDs with typed SERVFAIL/REFUSED, exact known security-update QNAME, external resolver to internal client, same resolver/client/name/rcode in 30 minutes. Tests: three-response threshold, two below threshold, replay, out-of-order, NXDOMAIN, NOERROR, lookalike domain, Info spoof, query/response direction, contradictory HTTP, independent resolver isolation, window expiry, Info redaction, unchanged profile. **DNS resolution failure is not proof of deliberate security-tool update blocking or failed endpoint updates.** Exact host inventory is a conservative heuristic, not an approved endpoint inventory. PacketHandler populates DNS QNAME/QTYPE/RCODE/response, but live detection unverified.

**R270 (10):** **Intentional fail-closed safety gate.** Current TrafficRecord and packet capture do not contain trusted structured control-plane tamper events for journal deletion, rule disablement, outbox shutdown or sensor modification. Previous packet-description-driven Critical alerts were unsupported. The candidate therefore returns NoMatch until a real typed authenticated pipeline-health adapter is designed, approved and connected. Ten meaningful **negative/policy** facts cover Info spoof, process spoof, HTTP path, DNS label, TCP flags, journal text, process+Info corroboration, empty record, contradictory protocol, and preserved confidence/mode/threshold. **No synthetic positive was fabricated** because no trustworthy positive telemetry contract exists. This intentional detection-coverage gap requires owner review before promotion.

## State, privacy and safeguards

Instance-owned bounded first-observed state (R266) and distinct packet-ID/time windows (R267–R269) reject replay/out-of-order, isolate sources and cap memory. Shared EvasionInfra event path excludes raw process paths and untrusted packet Info for R266–R270 and redacts destinationHost. Rule evidence uses typed categories and one-way process identity fingerprints, not raw paths or DNS query strings. **ProcessId/ProcessName are not populated by PacketHandler itself**, so process-attributed positives are typed contract-only, not proof of live capture reachability.

No confidence floors, thresholds, severities, default Alert/Shadow/Disabled modes, asset approvals, baseline readiness, frozen holdout evidence or approved architecture were changed. R266=75/1/Alert; R267=82/1/Alert; R268=82/1/Alert; R269=75/3/Alert; R270=88/1/Alert (but deliberately NoMatch without trusted telemetry). Frozen V1 R102 **FAILED 4/6** immutable; V2 independent licensed PCAP and analyst approval **PENDING**.

Other known limitations: PacketHandler does not populate DnsTtl/DnsAnswers; R262 fragmentation and R227 Profinet L2 contract-only; R228 OPC UA live parser absent; Sni/TlsSni alias; no TLS decryption or full TCP reassembly; Content-Length declared not transferred; different /24 not approved segmentation. Earlier R001–R125 user-run tests and synthetic 48/48 do not validate this batch or field emitted-alert recall.

**Next: R271–R275, then R276–R280**, unless live branch/ledger advanced. No tests until owner explicitly says "now it's test time".
