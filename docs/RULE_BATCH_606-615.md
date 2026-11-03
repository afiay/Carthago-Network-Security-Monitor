# CARTHAGO — R606–R615 independent request/DNS candidates

**SOURCE CANDIDATE — UNVERIFIED. Tests authored; 0 executed. Builds, replay and CI not run.**

Branch: `feature/carthago-reliability-hardening`. Source: owner-provided workbook `CARTHAGO_R586-R3085_2500_UNIFIED_PRIORITY_RULE_RESEARCH_AND_TESTS(1).xlsx`. Original research IDs retained; no additional online research.

## Rule matrix

| Registered ID | Workbook ID | Independent predicate | Existing overlap review |
| --- | --- | --- | --- |
| R606 | R3035 | Pulse Guacamole query-embedded request | R414 broad VPN endpoint probe |
| R607 | R2312 | Kemp LoadMaster API enable GET | R089 generic injection; Authorization marker redacted, no exploit claim |
| R608 | R2273 | Exchange mastermailbox PowerShell SSRF request | R319 OWA generic, R609 distinct encoded-at variant |
| R609 | R2960 | Exchange encoded-at PowerShell SSRF request | R608 excludes mastermailbox, R319 broader |
| R610 | R3039 | Exchange OWA calendar endpoint POST | R319 broad OWA, R600 different resources path |
| R611 | R3042 | Fortinet SAML remoteserver POST with anomalous Referer | R291 generic Fortinet; Referer must be captured |
| R612 | R2158 | External OAST callback DNS query | R185 generic canary probes; explicit external OAST families |
| R613 | R3048 | Cobalt Strike-like staging label DNS query | R393 C2 URI and R103 periodic beaconing differ |
| R614 | R2965 | Historical DPRK-associated DNS domain query | R003 threat feed overlap possible; static historic IOC only |
| R615 | R2550 | Anonfiles file-sharing domain DNS query | R105 upload claims require different evidence; historical DNS only |

Six HTTP request-only rules use existing `WebSignatureRequestEvidence`, `HttpMethod`, `HttpUri`, `HttpUserAgent` and conditionally `HttpRequestHeaders`. Four DNS query-only rules use the new bounded `DnsSignatureRequestEvidence` input validator and the existing packet-produced `DnsQname`, `DnsQtype`, `DnsIsResponse`, `ApplicationService` fields. Each class retains its own predicate and instance-owned cooldown; **no convergence or rule merging**.

Precision: Candidate maturity; Shadow runtime; High HTTP/Medium DNS severity; minimum confidence 84/82; ten-minute cooldown and five-minute reported observation window; 1,024 keys maximum per rule via existing `WebSignatureCooldown`. Fixed redacted signature labels only. No raw URL, header, credential or full QNAME in event evidence.

Boundaries: observed packet request/query shape only. No authenticated user, response status, exploit success, actor attribution or upload outcome. Workbook R2312's special Authorization-prefix bytes are unavailable after redaction; R607 therefore detects only the API enable request. R2273's 200 response and R3039's response status exclusion cannot be asserted. R3042 requires preserved Referer headers, and live capture reachability remains unverified. R2965/R2550 are historical potentially stale indicators. Imported records can fill mutable fields; producer provenance is a separate verification requirement.

Authored xUnit cases: exact positive, benign negative, wrong HTTP method, DNS response/wrong port, forged Info, missing parser field, contradictory TLS/DNS, malformed QNAME, duplicate ID, stale time, cooldown, evidence redaction, independence of Exchange variants, and registry uniqueness. **Zero tests executed.** No frozen holdout, coordinator, runner or UI files changed.

Next unallocated ID after this source batch: R616. Do not promote before real producer and positive/negative verification.
