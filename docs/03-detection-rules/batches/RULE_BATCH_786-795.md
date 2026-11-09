# CARTHAGO — R786–R795 observable network source candidates

**SOURCE CANDIDATE — UNVERIFIED. 0 tests, 0 builds, 0 CI, 0 replays or holdouts executed.**

Original ranked owner workbook: `CARTHAGO_R586-R3085_2500_UNIFIED_PRIORITY_RULE_RESEARCH_AND_TESTS(1).xlsx`, Library `libfile_3dce02a91bac8191a6896c8e24e04839`. Ten **independent** packet predicates with individually owned, bounded correlation state. Original analytic narratives often depend on authenticated device configurations, TLS root-store logs, process execution audit, DNS answers, or completed transfer outcomes, none of which is inferred here.

| New rule | Workbook ID | Observed shape (not an outcome claim) |
|---|---|---|
| R786 | R1025 | TCP/53 DNS TXT question, payload 500–2000 B; ≥4 packets/45 s to one external resolver |
| R787 | R2021 | Process-attributed UDP DNS A question, then high-port public TCP SYN/40 s; DNS answer and derived-port link unobserved |
| R788 | R998 | Local named/unbound/dns.exe repeats one TXT question to ≥3 distinct external resolvers/90 s |
| R789 | R2063 | Local net/net.exe SMB2 WRITE request, then same-peer FIN/45 s; disconnect intent unobserved |
| R790 | R1020 | Captured server-side TLS certificate issuer changes for same subject and peer/180 s; root-store changes unobserved |
| R791 | R1238 | Public HTTP POST to /admin/* on private host, followed by curl-attributed public TLS egress/90 s |
| R792 | R1734 | hostd-attributed FTP STOR request followed by TFTP/69 UDP traffic to same external peer/60 s |
| R793 | R1873 | Public proxy-port 3128 SYN into private host followed by nginx-attributed outbound 8443 SYN/60 s |
| R794 | R1884 | Private A→relay B port 1080 SYN then relay B→third internal /24 TCP/3389 SYN/60 s |
| R795 | R1847 | ≥4 large HTTP POST packets to /system/firmware/upload from one public client/45 s (≥9 KB observed L4 total) |

## Selection and skip accounting

The workbook’s ranked first rows include ESXi hostd crash logs (R1116), signed VIB install audit (R1126), network device boot configuration updates (R1130), forged Windows parent PID event telemetry (R1139), Linux Python startup-file writes (R1344), and package update/install evidence (R1216). These were **SKIP_UNSUPPORTED**, because their requisite event producers/fields are not in the observed `TrafficRecord`; direct packet predicates cannot establish them. The appliance configuration queue at ranks 539–552 (including original IDs R786–R805) similarly requires authenticated device/vendor audit events and is deferred. Cross-check source predicates, not superficial title similarity; previously registered R706–R785 families were excluded from the exact predicate selections. The search crossed the ranked workbook rather than stopping on unsupported top rows.

## Honest evidence contract

- **R786** does not prove an AXFR or a DNS policy change; it counts large parsed TCP TXT questions. It does not duplicate R182's zone-transfer QTYPE.
- **R787** does not identify the DNS answer used by the follow-on connection: `DnsAnswers` is not populated by the live producer. Its evidence is only a process-associated ordered request→SYN, and the source analytic's calculated-port causal inference is unsupported.
- **R788** does not observe an upstream-forwarding configuration change or content confidentiality. Three destinations are packets, not proof of an unauthorized resolver.
- **R789** does not observe the `net use /delete` command or completion of a network-share disconnect. SMB2 WRITE followed by FIN is a weak temporal signal and remains Shadow.
- **R790** uses captured public-server certificate metadata, not endpoint trust-store or interception-root configuration.
- **R791** cannot prove server exploitation, login, RCE, or causal process lineage from its two network legs.
- **R792** sees `ftp.stor.request` and UDP/69 but no actual file movement, payload body, or ESXi host authorization.
- **R793–R794** do not establish configured NAT/proxy policies, only two independently bounded network-leg patterns. The latter requires three distinct private /24s and a middle host.
- **R795** observes public-to-private large HTTP upload-endpoint POST packet traffic, not firmware upload completion or firmware modification.

All ten are **Candidate** maturity and **Shadow** runtime mode, confidence floor 80, with xUnit source for positive/negative shapes, contradictory/absent fields, replay/reverse time, expiry, cooldown recovery, privacy, independent predicates and registry uniqueness. Source-only confidence is provisional. Original holdouts V1/V2, producer, UI and CI untouched.

## Workbook references

- R786 → R1025: https://attack.mitre.org/datacomponents/DC0085/
- R787 → R2021: https://attack.mitre.org/detectionstrategies/DET0262#AN0728
- R788 → R998: https://www.rfc-editor.org/rfc/rfc6811.html
- R789 → R2063: https://attack.mitre.org/detectionstrategies/DET0103#AN0286
- R790 → R1020: https://attack.mitre.org/datacomponents/DC0085/
- R791 → R1238: https://attack.mitre.org/detectionstrategies/DET0080#AN0225
- R792 → R1734: https://attack.mitre.org/detectionstrategies/DET0416#AN1172
- R793 → R1873: https://attack.mitre.org/detectionstrategies/DET0325#AN0926
- R794 → R1884: https://attack.mitre.org/detectionstrategies/DET0075#AN0208
- R795 → R1847: https://attack.mitre.org/detectionstrategies/DET0060#AN0169

**Next unallocated ID: R796. SOURCE CANDIDATE — UNVERIFIED.**

