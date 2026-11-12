# CARTHAGO — R896–R900 observable research candidates

**SOURCE CANDIDATE — UNVERIFIED.** Five independent Candidate/Shadow rules. Tests authored first; zero builds, test executions, CI jobs, runtime replays or accuracy gates executed. No promotion, convergence or producer changes.

| ID | Workbook origin | Observable predicate | Unobserved |
| --- | --- | --- | --- |
| R896 | R1730 | Regsvr32-attributed public HTTP scriptlet GET | scriptlet execution, module load, command line and authorization are unknown. |
| R897 | R1756 | CMSTP-attributed public HTTP INF GET | profile installation, command line, DLL load and privilege change are unknown. |
| R898 | R1896 | Net-attributed private SMB SYN peer fanout | share enumeration, SMB authentication and lateral success are unknown. |
| R899 | R1717 | VMware management-process TLS to public resolver SNI | HTTPS DNS requests, resolver identity, VMware asset role and tunneling are unknown. |
| R900 | R1706 | Regasm or Regsvcs-attributed public SYN then TLS data | COM registration, assembly load, execution and C2 are unknown. |

## Evidence boundaries and duplicate screen

R896 is distinct from R860 (regsvr32 UDP/1194 peer fanout) and other generic HTTP artifact rules by requiring regsvr32 process attribution and scriptlet suffix. R897 requires cmstp and INF rather than generic downloads. R898 requires three private SMB peers under a single source/PID, not R789 SMB WRITE→FIN, R797 WMIC RPC fanout, or generic share probes. R899 requires VMware management process and exact resolver SNI, unlike generic DoH rules R048/R194, R727 script DoT or R888 generic VMware TLS peer pair. R900 uses a registration-tool process plus same-flow public SYN→TLS; prior rare process SYN rules R846–R848 and R878 public inbound SSH are different.

Full workbook analytics remain unsupported without trusted process creation, command line, module load, registry, share enumeration, authentication, decrypted HTTP/DNS, or asset inventory. No claims of execution, authentication, exploitation, transfer completion, DNS tunneling, COM modification or compromise. A parser-observable GET is not a completed download. Resolver SNI is not proof of DoH. Legitimate administration can match.

State uses independent bounded per-rule windows, exact process names and positive PID, monotonic UTC, distinct packet IDs, and ten-minute cooldown. xUnit source includes positive, near miss, process and transport absence/conflict, duplicate/reverse timestamps, cooldown, peer/PID/tuple/window isolation, privacy and registry tests. **Not executed**; no accuracy claim. R898 cooldown is keyed by source and PID; other rules by source and peer.

## Owner workbook sources

- R896 / R1730: https://attack.mitre.org/detectionstrategies/DET0282#AN0785
- R897 / R1756: https://attack.mitre.org/detectionstrategies/DET0328#AN0932
- R898 / R1896: https://attack.mitre.org/detectionstrategies/DET0182#AN0513
- R899 / R1717: https://attack.mitre.org/detectionstrategies/DET0538#AN1486
- R900 / R1706: https://attack.mitre.org/detectionstrategies/DET0361#AN1028

Next unallocated ID: **R901**, subject to live registry inspection.
