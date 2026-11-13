# CLI-009B — Portable rules R596–R600

**SOURCE CANDIDATE — UNVERIFIED.** Reviewed 60c32f03602f52fde35cb42b952893cabb5103c2.

Five original request predicates extracted into Core; Windows wrappers retain evidence, confidence, severity and Shadow policy. R596 consumes parsed User-Agent (already populated by portable processor); R600 POST-only metadata. R597–R599 GET/POST. No new Windows IDs, exploit outcome assertion or telemetry producer changes. Catalog R586–R600, 15 supported source IDs; 985 of original 1000 target remain.

29 portable cases (24 predicate rows, five cooldown/evidence rows), 24 Windows parity rows and one raw PCAP replay case authored, zero executed. Gate updated. Next R601–R605, review required HTTP headers and producer completeness. Before >64 portable rules, redesign selection and dispatch limits. Actual qualification remains pending.
