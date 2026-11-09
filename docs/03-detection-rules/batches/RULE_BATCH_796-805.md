# CARTHAGO — R796–R805 independent network source candidates

**SOURCE CANDIDATE — UNVERIFIED. Authored xUnit, 0 tests, 0 builds, 0 CI, 0 capture, 0 replay or holdouts executed.**

Canonical owner workbook: `CARTHAGO_R586-R3085_2500_UNIFIED_PRIORITY_RULE_RESEARCH_AND_TESTS(1).xlsx` (Library `libfile_3dce02a91bac8191a6896c8e24e04839`). Ten distinct original research rows were narrowed to typed fields CARTHAGO can represent, with no endpoint/identity/configuration events asserted.

| New rule | Original workbook | Independent observable predicate |
|---|---|---|
| R796 | R2634 | frpc/frpc.exe local PID makes private TCP/1080 SYN then public TCP/443 SYN within 60 s |
| R797 | R2002 | wmic/wmic.exe local PID sends TCP/135 SYN to four distinct private hosts in one /24 within 45 s |
| R798 | R1011 | powershell.exe makes DNS A request then 3 similar-size TLS/443 SNI packets for that name at 12–40 s intervals within 120 s |
| R799 | R1016 | curl/curl.exe makes a DNS TXT question then cleartext HTTP POST /api/* to the same DNS hostname within 45 s |
| R800 | R2700 | scada/scada.exe local PID makes private Modbus/502 SYN then HTTP/80 GET /api/* to public host within 90 s |
| R801 | R2690 | python/python.exe requests EtherNet/IP ListIdentity UDP/44818 then TCP/502 SYN to that same private device within 50 s |
| R802 | R2667 | python/python.exe probes TCP/102, TCP/502, and TCP/2404 on same private peer within 45 s |
| R803 | R2765 | iot-agent local PID sends CoAP/5683 multicast discovery then external DNS TXT within 45 s |
| R804 | R2791 | private UDP/161 packet followed by private TCP/22 SYN to same target within 50 s |
| R805 | R2816 | five distinct long base32-shaped DNS TXT subdomain questions under one domain from one private source within 50 s |

## Admission and exclusion reasoning

A scan of the ranked queue rejected several higher-priority but unsupported entries. Examples: R1116 needs ESXi crash/hostd audit; R1126 needs signed VIB installation logs; R1130 needs network-device configuration/boot events; R1139 needs Windows parent-PID spoofing ETW; R1344 needs Python startup-file writes; R999 requires DHCP client route-table changes; R1010 needs client certificate identity; and R1007/R1015/R2846 need DNS answer/policy data not produced by the current packet path. Vendor VPN appliance audit queue R786–R805 in the workbook is not observable in TrafficRecord; these **original workbook IDs are not CARTHAGO allocation IDs** and are not implemented by renumbering.

The selected rows have distinct predicates and independent rule instance state. Previously implemented process-specific SYN fanouts, generic port scans, DNS anomalies, public SNMP fanout, TFTP/FTP, and proxy relay families were screened for exact predicate duplication. Similarity remains provisional; candidates are Shadow until replay/holdout and benign production controls verify quality.

## Limits that must not be promoted into claims

- **R796**: two network legs of frpc, not proof of active or unauthorized proxy configuration.
- **R797**: targeted RPC connectivity, not proof of successful network service discovery, WMI execution, or host compromise.
- **R798**: DNS question and matching TLS/SNI cadence only. Newly delegated nameserver, file upload, process creation event, and exfiltration are not observed.
- **R799**: no TXT token bytes retained and no proof of token reuse, authentication, or spawned process. HTTP/80 cleartext only.
- **R800**: a process name resembling SCADA is not an approved OT asset role; the HTTP GET does not establish an unauthorized business endpoint.
- **R801**: ListIdentity then Modbus port SYN does not prove full point/tag namespace enumeration or read success.
- **R802**: 3 OT port SYNs do not identify an authenticated SCADA master or prove master-role control.
- **R803**: CoAP multicast plus DNS TXT has no device-specific approved resolver inventory or DNS C2 attribution.
- **R804**: UDP/161 contains no decoded SNMP OIDs; TCP/22 SYN is not an authenticated SSH login.
- **R805**: base32-shaped encoded labels can be benign and do not prove DNS tunnelling or C2 payload.

Each class is **Candidate**, **Shadow**, confidence floor 80, own state/cooldown, and static evidence containing only workbook identifier, matched condition identifier, and unknown-outcome marker. The xUnit source covers positive, benign near miss, contradictory/missing fields, replay, reverse time, expiry, cooldown recovery, privacy, non-convergence and registry uniqueness. No test was run.

## Original research references

- R796 / R2634: https://attack.mitre.org/detectionstrategies/DET0759#AN2275
- R797 / R2002: https://attack.mitre.org/detectionstrategies/DET0376#AN1057
- R798 / R1011: https://attack.mitre.org/datacomponents/DC0085/
- R799 / R1016: https://attack.mitre.org/datacomponents/DC0085/
- R800 / R2700: https://attack.mitre.org/detectionstrategies/DET0736#AN1869
- R801 / R2690: https://attack.mitre.org/detectionstrategies/DET0788#AN1920
- R802 / R2667: https://attack.mitre.org/detectionstrategies/DET0792#AN2278
- R803 / R2765: https://attack.mitre.org/detectionstrategies/DET0934#AN2096
- R804 / R2791: https://attack.mitre.org/detectionstrategies/DET0770#AN2184
- R805 / R2816: https://attack.mitre.org/detectionstrategies/DET0400#AN1124

**Next unallocated CARTHAGO ID: R806 — SOURCE CANDIDATE — UNVERIFIED.**

