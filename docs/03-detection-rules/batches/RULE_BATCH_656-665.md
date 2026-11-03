# CARTHAGO — R656–R665 source candidate batch

**SOURCE CANDIDATE — UNVERIFIED: 0 builds, 0 xUnit tests, 0 replays executed.**

## Scope / provenance

Work on `feature/carthago-reliability-hardening` only. Source: existing owner-supplied `CARTHAGO_R586-R3085_2500_UNIFIED_PRIORITY_RULE_RESEARCH_AND_TESTS(1).xlsx`; research IDs kept separate from allocated Carthago R656–R665 IDs. **No web research** was used. All ten rules retain separate C# classes and predicates; the shared evidence helpers only validate typed fields and bound instance-owned observation windows. No convergence.

| Carthago ID | Workbook ID | Independent candidate detection | Existing overlap and why this is not merely the existing predicate |
|---|---|---|---|
| R656 | R1497 | Attributed Git smart-HTTP push request to official code host | R207 requires a first-seen unofficial remote host; this candidate requires a Git-attributed request to official GitHub/GitLab with /git-receive-pack, not a repository-exfiltration outcome. |
| R657 | R1518 | Script or CLI process posting to paste-service API | R220 and R503 count large or repeated paste-service POSTs. This candidate requires an exact API route and locally attributed scripting client for one request. |
| R658 | R1371 | Regular-size outbound TCP payload sequence from an attributed process | R254 counts repeated declared HTTP uploads; this matches four non-HTTP TCP payload observations with constrained lengths and spacing, without transfer claims. |
| R659 | R1808 | Public client probing SNMP, NETCONF, and HTTPS management ports | R585 tracks a triad of parsed administrative operations, not this exact cross-transport SNMP/NETCONF/HTTPS port triad. |
| R660 | R2731 | OT engineering process sends native DNS query directly to public resolver | R102 is DNS label tunneling; this rule requires attributed engineering process and a public resolver, without claiming DNS policy violation. |
| R661 | R1984 | PowerShell or script-host process to external mail-service port | R020 and R313 detect generic outbound SMTP; this specifically requires a scripting process with PID and also includes IMAP/POP3 port families. |
| R662 | R2024 | IDE process observed using Visual Studio developer-tunnel TLS SNI | R516/R517 handle other tunneling providers; this exact Visual Studio development-tunnel SNI and IDE process conjunction differs. |
| R663 | R1541 | FTP STOR then APPE requests to same external peer | R248 detects a single STOR/APPEND command and R652 requires script-host identity; this candidate requires both distinct request types in order. |
| R664 | R1977 | Script process GET carrying a long encoded query to public IP literal | R019 is generic encoded/long URI, while this requires a script process/PID, exact IP literal HTTP host, GET and explicit long URL-safe query parameter. |
| R665 | R1332 | Explorer WebDAV-like GET followed by SMB SYN to same public peer | R174 observes inbound WebDAV abuse; R351 requires NTLM-attributed telemetry. This candidate observes only two ordered outbound network attempts, never credential coercion. |

## Honest evidence scope

- R656 and R657 see *cleartext* outbound HTTP request method, URI, host and PID/name. They do not see Git HTTP response, private file reads, successful upload or repository action. Existing HTTPS production traffic is normally opaque; these are low-reachability source candidates pending producer testing.
- R658 observes four similarly sized process-associated TCP payload observations spaced approximately 9–21 seconds apart within 90 seconds; no uploaded bytes, server acknowledgment, data content or exfiltration success is established. Unlike R254 it does not use repeated HTTP POST declared body sizes. False positives include ordinary interactive or periodic TCP applications.
- R659 observes one public client reaching the same private IP on UDP/161, TCP/830 and TCP/443 within five minutes. Ports are **not** SNMP/NETCONF/HTTPS protocol proof; the event is a *management-port triad probe*, not confirmed configuration theft or unauthorized management.
- R660 uses parsed native DNS QNAME records plus best-effort OT/engineering process identity and one of five public DNS resolver IPs. It does not know asset role, resolver approval, DoH traffic or C2 attribution. Importable TrafficRecord process fields are not authoritative endpoint security events.
- R661 uses a limited exact script-host basename, positive PID and public SMTP/IMAP/POP3 *service-port flow* (not parsed mail semantics). Normal administrative jobs may match.
- R662 uses the TLS SNI for `*.devtunnels.ms` or `*.tunnels.api.visualstudio.com`, plus positive PID and exact IDE basename. SNI is not a verified tunnel session or persistent remote access.
- R663 observes two *different* FTP parsed upload requests (STOR and APPE) to the same external peer within five minutes; no response or data channel confirms delivery.
- R664 observes a URL-safe, long encoded GET parameter targeting an IP literal with an unusual local scripting client. It neither decodes data nor establishes a C2 channel; R019 provides the broader heuristic.
- R665 requires explorer-like process WebDAV-labeled GET followed in-order within three minutes by a TCP SYN to SMB port 445 for the same public peer and process PID. No NTLM exchange parser is present, so it cannot claim password/hash disclosure or credential coercion. It is distinct from R174 inbound DAV abuse and R351 NTLM-specific signals.

All ten default `Candidate` and `Shadow`, with per-rule instance-owned `WebSignatureCooldown` (10 minutes). Window state is bounded to 512 keys per rule and 96 IDs per key when applicable. Evidence contains only fixed research identifiers, named conditions and honestly scoped `*_unknown` labels. Do not infer confirmed compromise.

## Authored xUnit (not executed)

`Carthago.Tests/R656R665AdvancedAccuracyBatchTests.cs`: exact positive, benign path/host/process/port negatives, forged Info, missing PID, malformed parser classification, per-instance state, duplicate ID, out-of-order, timed matching, port triad, FTP pair, WebDAV→SMB sequence, encoded parameter redaction and registry uniqueness. **No tests have run.**

## Owner workbook sources

- R656 ← R1497, workbook rank from existing research; source URL retained in workbook, not re-fetched.
- R657 ← R1518, workbook rank from existing research; source URL retained in workbook, not re-fetched.
- R658 ← R1371, workbook rank from existing research; source URL retained in workbook, not re-fetched.
- R659 ← R1808, workbook rank from existing research; source URL retained in workbook, not re-fetched.
- R660 ← R2731, workbook rank from existing research; source URL retained in workbook, not re-fetched.
- R661 ← R1984, workbook rank from existing research; source URL retained in workbook, not re-fetched.
- R662 ← R2024, workbook rank from existing research; source URL retained in workbook, not re-fetched.
- R663 ← R1541, workbook rank from existing research; source URL retained in workbook, not re-fetched.
- R664 ← R1977, workbook rank from existing research; source URL retained in workbook, not re-fetched.
- R665 ← R1332, workbook rank from existing research; source URL retained in workbook, not re-fetched.

Next eligible contiguous rule allocation after published source-only batch: **R666–R675**. Preserve V1/V2 holdout policies, coordinator, UI automation, and existing confidence floors. Test execution requires explicit owner authorization.
