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
