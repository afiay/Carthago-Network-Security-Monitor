# CLI-009A — Portable rules R591–R595

**SOURCE CANDIDATE — UNVERIFIED.** Reviewed fe1fa4222222e53b06dffc2b86bc8b3bc5269ebe.

Extract the original Windows predicates verbatim into five Core detectors and delegate the original wrappers. Retain descriptor, severity, evidence, candidate Shadow policy and cooldown. The catalog now has ten executable portable request detectors (R586–R595); all new rules accept GET/POST through the existing typed HTTP guard. No exploit-success assertion. No new rule IDs or Windows registry changes. 990 of the original 1000-rule target remain without portable registration. This is not detection accuracy qualification.

- R591: ADSelfService suspicious endpoint request
- R592: DEWMODE webshell-shaped query request
- R593: Apache Spark doAs backtick request
- R594: Bitbucket archive exec-prefix request
- R595: Grafana plugin traversal request

25 portable predicate/evidence cases, 20 Windows parity cases, one raw PCAP replay case authored, zero executed. Pinned qualification gate updated. Existing five-rule smoke remains a regression for the first batch; catalog smoke now expects ten. Next: execute qualification, then R596–R600 after checking producer dependencies. Native sample selects all catalog rules; current 64-rule selection bound must be redesigned before expanding beyond it.
