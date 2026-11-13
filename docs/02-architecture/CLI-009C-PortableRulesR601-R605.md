# CLI-009C — R602–R605 and R601 evidence gap

**SOURCE CANDIDATE — UNVERIFIED.** Reviewed 15016c0769591345fccac3a93f674476461d6af6.

Four original request predicates extracted into Core; original Windows wrappers retain evidence, confidence, severity and Shadow policy. R602 GET/POST, R603/R604 GET, R605 POST. R601 requires reliable absence of User-Agent and Referer, but portable processor only populates parsed header summary without a completeness contract. Defer R601, preserve original Windows rule, expose complete_http_header_evidence_required in capability lookup. Do not infer absent headers from partial data. No parser changes or new Windows IDs.

19 portable source registrations (R586–R600 and R602–R605), 981 of original 1000 target remain, including R601. 46 new cases (24 portable, 20 parity, one replay, one capability), zero executed. Pinned gate updated. Next: explicit header completeness producer and negative partial-capture tests for R601, then next compatible rules. No qualification claim.
