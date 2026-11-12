# CARTHAGO detection qualification gate — existing rules, no new IDs

Owner direction: qualify and materially enhance previous rules before expanding beyond R965. Existing IDs and Candidate/Shadow stay unchanged. This is a source-hardening increment, not certification. Earlier local reports: R896–R925 171/171 and R926–R945 105/105 at their respective commits; R946–R965 not yet independently executed in the supplied record.

## Q1: capture-to-rule TFTP initial exchange

R946, R947, R949 previously accepted generic UDP port 69 payloads; R946 additionally accepted arbitrary reverse ephemeral UDP. This creates both false-positive and producer-evidence gaps. Existing `TftpRequestInspector` was isolated and is now wired into the IPv4 PacketHandler path using complete IP/UDP length agreement. New bounded tracker (1024 pending slots, 45 seconds, request ID, client/server/client port, lock, one consumed first response) validates RRQ→DATA block 1 and WRQ→ACK block 0; it rejects incorrect opcode/block/direction, unrelated UDP, missing requests and expired/reverse time. It deliberately does not claim OACK negotiation, transfer completion, filename, device role, firmware modification or authorization. RRQ/WRQ option envelope framing is validated by existing inspector; OACK reply is not accepted. No filename or file content retained. R946 requires the exact producer request reference; R947 and R949 require parsed RRQ/WRQ, not generic port data. Existing older R708/R715/R792/R819/R881 are not yet migrated; do not claim the entire TFTP family is qualified.

Raw IPv4 UDP synthetic frame integration tests exercise PacketHandler through rule evaluation, wrong opcode/block/peer/port, inconsistent lengths, independent captures, request ID isolation, expiry, and privacy. Previous R946/R947/R949 batch fixtures use actual capture producer rather than invented fields. Producer processing time is UTC wall-clock because PacketHandler currently does not receive capture timestamps; rule evaluation also enforces its event-time window. Capture loss/reordering, option negotiation, IPv6, full session lifecycle and transfer completion remain limitations. No new IDs, no production promotion.

## Next qualification work

1. Run focused and full regression tests for the TFTP change; then migrate remaining TFTP rules with direction-specific replay and benign datasets.
2. R962 and other DNS-answer rules: inspect actual producer path. PacketHandler.DnsLight currently parses only question name/type/rcode and does not populate DNS answer/TTL on the live UDP path; verify alternate producers before making coverage claims. Add bounded wire transaction ID and validated answer/TTL parsing; correlate queries/responses by transaction and tuple, then test realistic CDN negatives.
3. Audit all 965 original research mappings, source provenance, semantic overlap and unsupported producer dependencies. Each rule gets a record of source, actual producer, positive/negative corpus, runtime/accuracy and disposition (retain, improve, consolidate, retire). Never relabel simply based on authored fixtures.
4. Add independent capture replays, per-rule precision/recall, false positives per hour, throughput/memory and detection latency; only promote rules meeting explicit thresholds. Keep expansion paused until qualification reviewed.

References: existing TftpRequestInspector source; RFC 1350 https://www.rfc-editor.org/rfc/rfc1350 ; RFC 2347 https://www.rfc-editor.org/rfc/rfc2347 .

Status: source changes authored, not compiled or executed in this session. No CI triggered manually.


## Q2: DNS producer and transaction qualification — R916/R962

Live UDP PacketHandler previously did not populate answer address/TTL and did not establish the DNS ApplicationProtocol label for ordinary UDP messages. Added bounded complete IPv4 UDP/53 parser using existing lossless name codec: standard single IN/A question, exact wire transaction, direct single owner-matching A record, or no-answer NXDOMAIN; no truncated/multi-answer/CNAME responses, strict RR envelope bounds and length agreement. Capture-attested transaction and question/answer fields are internal-set. R916 requires matching validated query/NXDOMAIN transaction plus reverse tuple. R962 consumes matching transactions once, retains the actual query PID for distinct-address churn, and verifies answer/TTL against capture-attested values. Existing R916/R962 fixtures now originate in raw synthetic frames; additional tests cover malformed, mismatched owner/transaction/port, mixed PID and unsupported synthetic fields. The producer is not full DNS resolution and does not validate DNSSEC, CNAME chains, all authority semantics, TCP/IPv6, resolver trust, ASN/CDN baseline or malicious fast flux. Normal direct-A CDN churn can still match; process enrichment remains best effort. No promotion. Tests not executed.

Reference: RFC 1035 https://www.rfc-editor.org/rfc/rfc1035 ; RFC 2308 https://www.rfc-editor.org/rfc/rfc2308 .

## Verified owner checkpoint — 7303af2 (2026-11-12)

Owner supplied local Windows Release execution: 13/13 capture qualification tests, 241/241 affected regressions, full 12,185/12,185 tests, 0 failed/skipped, 166.2s test duration. Seven distinct nullable warnings repeated in WPF build. These apply to 7303af27804d9fbb9fd399c3ce88dabed26a9787, not subsequent changes. Synthetic packet integration is not live capture or independent accuracy validation.

## Q3 — migrate five older TFTP candidates

R708/R715 now require capture-attested RRQ/WRQ and exact first DATA1/ACK0 correlation, preserving opposing directions and 30s rule windows. R792/R819/R881 require a parsed WRQ (not RRQ or arbitrary UDP/69) for upload/file-placement-oriented sequences. Removed arbitrary UDP payload size restrictions in R819/R881; the inspector validates complete bounded request framing instead. This is a deliberate narrower semantic predicate; read-only workflows and OACK negotiation do not qualify. The prior ingress/FTP/HTTP stages retain existing limits, including no authentication, file identity, process ancestry or causality. Updated historical positive fixtures to use raw packet producer and added seven capture-to-rule theory cases for both directions, RRQ/WRQ, invalid payload and read/write distinction. No rule IDs added; Candidate/Shadow retained. **Q3 source authored, not compiled or executed; full regression and independent accuracy still required.**

## Verified owner checkpoint — 4cc680b (2026-11-12)

Owner Windows Release: 338/338 targeted TFTP/affected regression tests; full 12,192/12,192, zero failed/skipped, 180.2s. Earlier enrichment 47/47 at pre-Q3 HEAD. All ten Q1–Q3 enhanced rules locally regression-tested; independent accuracy/live capture still pending.

## Q4 — complete SMB2 WRITE capture evidence

R903/R908/R910/R919/R942/R950 now require capture-attested complete standalone plaintext SMB2 WRITE, not just legacy ApplicationProtocol. Existing legacy parser accepts a header and a declared data region within the declared frame even when bytes are missing. New bounded inspector requires exact direct-hosted frame length, synchronous non-compound WRITE, nonzero session/tree and non-placeholder file IDs, channel zero, no write-channel info, and complete data range. No raw session/file IDs or bytes retained. PacketHandler checks complete IP and untrimmed accepted TCP payload and excludes TLS-active traffic. Existing legacy classification retained for unmigrated rules. Historical positive fixtures now use raw frame producer; 13 new targeted cases test valid framing, truncation, compound, response/async/related, missing IDs, channel, offset, encrypted marker and JSON/label spoofing. This is a deliberately conservative subset; split/coalesced, encrypted/compressed, compound, RDMA and some valid padded messages are not covered. Session IDs are validated structurally, not authenticated; no response matching, actual file identity/share, write success or full TCP reassembly asserted. Candidate/Shadow unchanged. Source not compiled or executed.

## Q4 regression correction — owner test checkpoint 5d8bcb4

Owner Windows Release compilation succeeded, but targeted tests 359/376 and full suite 12,200/12,217 (17 failures, zero skipped, 168.6s). All six Q4 rules lost positive matches; the dedicated capture test failed at the producer flag assertion. Root cause identified by source inspection: SMB2 StructureSize was read at header offset 0 (protocol signature) instead of offset 4 (wire offset 8). Correct the offset only; retain all strict framing, length, flags and identifier requirements and all existing positive/negative tests. Add one direct valid-inspector test and three invalid-header-size cases. Q4 remains unverified until owner reruns; do not proceed to Q5 or new IDs before successful regression. No CI triggered. Earlier 12,192/12,192 remains the last supplied passing full-suite checkpoint.

## Verified owner checkpoint — 812b752 (2026-11-13)

Owner Windows Release: 17/17 SMB2 qualification, 380/380 selected regressions, full 12,237/12,237, zero failed/skipped, 170.6s. Corrected Q4 producer and six rule regressions verified. Concurrent DNS-to-connection enrichment included. All sixteen Q1–Q4 enhanced rules locally regression-tested, not production-qualified.

## Q5 — bounded SMB2 WRITE response corroboration

Keep six Q4 attempt predicates unchanged. One outstanding request per existing bounded TCP flow; both observed SYN anchors, complete untrimmed payload, no TLS/gaps; match reverse response message/session/tree IDs, TCP acknowledgment, complete standalone synchronous WRITE and 30s UTC. STATUS_SUCCESS reports nonzero count at most requested length (partial distinguished); simple final ERROR reports status without count. Raw IDs only in bounded flow state; response record retains request GUID/status/count. Subsequent payload consumes slot; pipelining unsupported; SYN/FIN/RST/TLS/gap/retransmission invalidate pending. Server-reported evidence, not authentication, share/path identity, durability or successful attack. Existing alerts unchanged; no new IDs/promotions. 15 new test cases; Windows execution pending. Concurrent enrichment preserved.

## Verified owner checkpoint — 6cb96d6 (2026-11-13)

Owner Windows Release: 32/32 SMB2 qualification, 395/395 affected suites, full 12,272/12,272, zero failed/skipped, 172.4s. Q5 and concurrent TLS identity enrichment locally regression-verified. Local MASTER_RULE_CATALOG.md edit not part of remote checkpoint; preserve it.

## Q6 — capture-correlated SMB2 target context

One-shot sequential TREE_CONNECT -> successful disk-share reply -> CREATE -> successful open reply -> complete WRITE, same TCP flow/session/tree, matched message IDs and ACK, exact returned file handle, 30s UTC from tree request. Only strict standalone plaintext frames, no DFS, encrypted shares, contexts, pipe/printer, directory opens or ambiguous/intervening payload; discard on reset, gap, FIN/RST/TLS, unexpected payload or consumed WRITE. Classify ADMIN$/drive-letter shares vs other disk shares and executable/script/other requested filename suffix; only categories and CREATE packet GUID leave bounded flow state, not raw share/path or handle. Enrich R908/R910/R950 event evidence when context exists, keep predicates/severity/confidence unchanged. Server reports successful open, not authenticated authorization, actual content type, malicious intent or durable write. Strict no-context CREATE and single operation chain limit recall; no full SMB session tracking. 16 new tests authored, not executed. No IDs/promotions; master catalog untouched.

Protocol references: Microsoft [MS-SMB2] sections 2.2.9–2.2.14 and 2.2.21; https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-smb2/832d2130-22e8-4afb-aafd-b30bb0901798 ; https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-smb2/e8fb45c1-a03d-44ca-b7ae-47385cfd7997 .

## Verified owner checkpoint — a3e1d27 (2026-11-13)

Owner Windows: initial DLL lock cleared; clean Release build succeeded (93.3s), then sequential --no-build --no-restore 48/48 SMB2 qualification, 411/411 affected suites, full 12,293/12,293, zero failed/skipped, 156.0s. Q6 locally regression-verified. Includes connection-intelligence tests. No new rule IDs or production promotion.

## Q7-v1 — synthetic paired accuracy baseline

25 new test cases (24 scenario-rule pairs plus aggregate report) covering all six Q4 SMB2 rules with separately authored raw WRITE frames, synthetic process/HTTP observations, malicious/benign identical-shape pairs, benign controls and producer-limited truncated requests. Report raw and effective alert metrics separately, exclude six producer gaps from supported metrics. Expected raw TP6/FP6/FN0/TN6; alert TP0/FP0/FN6/TN12 (Shadow); not yet executed, no production accuracy claim. Independent lab/field captures remain required. See docs/rules/SMB2_Q7_SYNTHETIC_ACCURACY_PROTOCOL.md. No detection predicate, score, registry or threshold changed.

## Verified owner checkpoint — e64e2df (2026-11-13)

Owner Windows Release build 36.3s; Q7 25/25, full 12,318/12,318, zero failed/skipped, 213.3s. Q7 measured raw TP6 FP6 FN0 TN6 (precision 50%, recall 100%, specificity 50%), effective alert TP0 FP0 FN6 TN12 (Shadow), six producer gaps. Both malicious and benign lookalikes confidence 0.90. Synthetic only, no production promotion.

## Q8-v1 — exact scoped maintenance annotation

Opt-in Approved.Smb2MaintenanceScopes for R910/R950 only; exact rule/source/destination/process/share/file categories, local TCP socket attribution, approved admin source, capture-correlated CREATE/WRITE, event packet identity, entire 45s rule window in UTC change interval, unique unambiguous scope. Return existing Shadow tuning disposition and explicit configured scope reason, never authorization proof. No rule or confidence change; Q7 frozen. Other four SMB2 rules excluded to avoid broad approvals. 22 tests authored, Windows pending. See docs/rules/SMB2_Q8_SCOPED_MAINTENANCE.md.
