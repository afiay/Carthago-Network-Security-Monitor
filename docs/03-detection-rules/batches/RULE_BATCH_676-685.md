# CARTHAGO — R676–R685 independent workbook-derived source candidates

**SOURCE CANDIDATE — UNVERIFIED. 0 builds, 0 tests, 0 replays executed.**

## Original branch, research provenance and anti-duplication

These are ten distinct source candidates on `feature/carthago-reliability-hardening`, immediately following R675. The owner-supplied `CARTHAGO_R586-R3085_2500_UNIFIED_PRIORITY_RULE_RESEARCH_AND_TESTS(1).xlsx` supplies the original row IDs, descriptions and source URLs below. The original P0/P1 priorities and research record are not rewritten; no new web research was used. The predicates implement explicitly narrowed *observable packet shapes* only.

| New rule | Original workbook and rank | Observed independent pattern | Strongest nearby overlap and distinguishing gate | Unsupported claims |
| --- | --- | --- | --- | --- |
| R676 | R1137, rank 606 | Unicast–broadcast–network-address TCP SYN signaling sequence | Existing sweeps and R585 multi-service probes; requires one TCP port and an ordered unicast, .255 broadcast, .0 subnet-address sequence | No firewall activation, router change, magic packet acceptance or SSH session is observed. |
| R677 | R1716, rank 1296 | Outbound TLS observation on DNS port 53 or alternate HTTP port 8080 | R669 requires a named system utility and TLS on port 80, not TLS on 53/8080; R151 checks HTTP/2 ALPN | Unusual TLS port alone does not establish a tunnel, certificate abuse or encrypted C2. |
| R678 | R2789, rank 2331 | Sequential three-host internal-subnet ICMP echo discovery | R643 requires EtherNet/IP ListIdentity on 44818; R670 matches fixed-destination timed ICMP echoes; this walks successive IPs | No full network scan, unauthorized discovery or ARP probe is inferred. |
| R679 | R2782, rank 260 | Private OT-service listener TCP SYN-ACK to public client | R644/R648/R649 cover RDP/VNC/WinRM listener response; this requires one of 102/502/44818 OT service ports | Port-associated SYN-ACK alone does not verify an ICS device, protocol decoder success, successful authentication or NAT exposure. |
| R680 | R2040, rank 1308 | Unusual local process SYN fanout to three internal hosts | R650 Curl/Wget fanout requires public /24s; R674 is public-client inbound followed by external outbound; this is three private peer hosts | PID enrichment is best-effort, and an internal SYN fanout is not proof of proxying or lateral command execution. |
| R681 | R2019, rank 1970 | Unusual local process contacts two public peers on proxy-associated TCP ports | R263 may cover a single proxy-process egress; this requires two distinct public peers on 1080/3128/8080/8888 within five minutes | No SOCKS handshake, established proxy, C2 relay or forwarded payload is observed. |
| R682 | R1983, rank 2094 | Rundll32/MSHTA browser-agent HTTP heartbeat-shaped GET sequence | R642 requires a script-host HTTP POST with browser-like UA; this requires rundll32/mshta GET heartbeat route repeated three times with cadence | No browser impersonation intent, HTTP response, C2 beacon or executable identity proof is established. |
| R683 | R2777, rank 257 | Parsed cleartext HTTP POST on native Modbus TCP service port | R653 requires parsed Modbus non-write requests; this explicitly requires HTTP parser evidence instead of Modbus on TCP/502 | A legitimate nonstandard HTTP service may use port 502; no ICS protocol masquerade intent or exploit is proved. |
| R684 | R2780, rank 259 | Public OPC UA-port SYN and private-server SYN-ACK exchange | R679 observes an OT-port SYN-ACK on 102/502/44818; R684 requires both directions and OPC UA port 4840 | The TCP exchange does not prove OPC UA payload, API execution, user approval, login or completed TCP handshake. |
| R685 | R2758, rank 2351 | Large parsed S7Comm response records from three private devices | R654 requires public-client S7 requests to three hosts; this requires internal-client large S7Comm response fan-in, not request scanning | Large response records do not establish directory listing, point/tag identification, device inventory or compromise. |

## Producer contracts and limitations

- R676: three TCP SYNs from one private source, to one /24 network's host/unicast address, broadcast .255 and network .0, on one port, in order within 60 seconds. **No port-knock activation is observed.** Windows capture may suppress subnet or broadcast-address packets, so positive live reachability is not established.
- R677: parser-labeled TLS metadata with SNI to public IPv4 on TCP/53 or 8080. `TlsVersion` and `Sni` are mutable imported fields; a TLS-on-DNS-port observation does not establish DNS-over-TLS or tunneling.
- R678: three successive IPv4 private host destinations receiving source-private ICMP echo requests in one /24 within 90 seconds. The packet observation proves neither a full subnet inventory nor malicious discovery.
- R679: SYN-ACK on one common ICS-associated TCP port (102/502/44818) from private server to public client. Port association is not a decoded ICS service, nor accepted connection or authenticated login.
- R680: unusual attributed `rundll32/mshta/regsvr32` process emits SYNs toward three distinct private IPs in one /24; R681: separate unusual process contacts two different public peers at a constrained proxy-associated port set. Both are conditional on best-effort Windows PID-to-flow enrichment. Neither proves proxy relay, command execution or verified process creation.
- R682: three parser-labeled GET requests for `/api/v1/heartbeat` with a browser-like UA, attributed to `rundll32/mshta`, spaced by 9–31 seconds. A regular heartbeat-shaped request is not malware C2 proof.
- R683: actual HTTP parser classification and POST `/api/` on TCP/502; this is a concrete protocol/port mismatch, not a malicious ICS masquerade outcome.
- R684: public-client TCP SYN on port 4840 followed within 30 seconds by private server TCP SYN-ACK to the matching client ephemeral port. Neither message is an OPC UA API transaction, application authorization, successful TCP handshake or execution.
- R685: large parser-labeled S7Comm response payload observations (source port 102, 512–4096 bytes) from three private devices in one /24 to one private client in five minutes. Does **not** prove point or tag enumeration or directory-listing contents.

All rules: independent C# classes, distinct predicates and instance-owned `WebSignatureCooldown` (10 minutes, 1,024 peer keys); bounded sequence windows (512 keys) reuse evidence hygiene, not rule convergence. All Candidate maturity/Shadow runtime. Events use fixed research IDs and honest outcome names without unredacted URI, credentials, packet contents or usernames. Imported/mutable `TrafficRecord` values cannot alone establish live sensor provenance.

## xUnit authored, no execution

`Carthago.Tests/R676R685AdvancedAccuracyBatchTests.cs` includes exact positives, benign near misses, wrong directions/ports, missing protocol fields, process/PID gates, IP subnet ordering and target distinctness, SYN versus SYN-ACK, request-response matching, three-hit timed HTTP, duplicate/out-of-order IDs, cooldown, redacted outcome, and registry uniqueness/Candidate Shadow. **Zero builds, zero tests, zero packet replays performed.** Live producer reachability and false-positive verification remain gates before any promotion.

## Original workbook sources (not re-searched)

- R676 ← R1137 (rank 606): https://attack.mitre.org/detectionstrategies/DET0524#AN1451
- R677 ← R1716 (rank 1296): https://attack.mitre.org/detectionstrategies/DET0273#AN0763
- R678 ← R2789 (rank 2331): https://attack.mitre.org/detectionstrategies/DET0739#AN2172
- R679 ← R2782 (rank 260): https://attack.mitre.org/detectionstrategies/DET0796#AN2253
- R680 ← R2040 (rank 1308): https://attack.mitre.org/detectionstrategies/DET0075#AN0204
- R681 ← R2019 (rank 1970): https://attack.mitre.org/detectionstrategies/DET0325#AN0922
- R682 ← R1983 (rank 2094): https://attack.mitre.org/detectionstrategies/DET0027#AN0075
- R683 ← R2777 (rank 257): https://attack.mitre.org/detectionstrategies/DET0725#AN2287
- R684 ← R2780 (rank 259): https://attack.mitre.org/detectionstrategies/DET0742#AN2289
- R685 ← R2758 (rank 2351): https://attack.mitre.org/detectionstrategies/DET0788#AN2177

After successful publication, next unallocated sequential IDs: R686–R695. Preserve frozen V1, V2 holdout protocol, UI automation, and existing confidence floors.
