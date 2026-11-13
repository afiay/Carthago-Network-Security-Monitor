# R988–R1000 — native industrial request quality-controlled completion

**SOURCE CANDIDATE — UNVERIFIED.** 13 registered Candidate/Shadow rules; 414 dedicated Windows xUnit cases authored, one shared registry fact, 27 portable xUnit cases authored. **Zero .NET tests executed in this session.** No rule promoted. No manual Actions run. The owner workbook Ranked 2500 rules and Real-world test matrix were both inspected. Each rule is a narrow request projection, not the complete workbook analytic.

| ID | Native operation | Workbook / analytic | Dedicated xUnit cases |
|---|---|---|---:|
| R988 | BacnetDeviceSystemStatusRead | [R2760 / AN1900 (T0868)](https://attack.mitre.org/detectionstrategies/DET0768#AN1900) | 28 |
| R989 | BacnetDeviceAllPropertiesRead | [R2690 / AN1920 (T0861)](https://attack.mitre.org/detectionstrategies/DET0788#AN1920) | 30 |
| R990 | BacnetInputOutOfService | [R2706 / AN2045 (T1692)](https://attack.mitre.org/detectionstrategies/DET0902#AN2045) | 32 |
| R991 | BacnetAtomicFileRead | [R2797 / AN2244 (T0893)](https://attack.mitre.org/detectionstrategies/DET0749#AN2244) | 31 |
| R992 | BacnetAtomicFileWrite | [R2706 / AN2045 (T1692)](https://attack.mitre.org/detectionstrategies/DET0902#AN2045) | 32 |
| R993 | FinsCpuStatusRead | [R2760 / AN1900 (T0868)](https://attack.mitre.org/detectionstrategies/DET0768#AN1900) | 27 |
| R994 | FinsBulkDataMemoryRead | [R2797 / AN2244 (T0893)](https://attack.mitre.org/detectionstrategies/DET0749#AN2244) | 32 |
| R995 | Dnp3IntegrityRead | [R2690 / AN1920 (T0861)](https://attack.mitre.org/detectionstrategies/DET0788#AN1920) | 31 |
| R996 | Dnp3AbsoluteTimeWrite | [R2706 / AN2045 (T1692)](https://attack.mitre.org/detectionstrategies/DET0902#AN2045) | 30 |
| R997 | ModbusReadWriteSamePairZero | [R2714 / AN1908 (T0836)](https://attack.mitre.org/detectionstrategies/DET0776#AN1908) | 38 |
| R998 | ModbusBulkFileWrite | [R2706 / AN2045 (T1692)](https://attack.mitre.org/detectionstrategies/DET0902#AN2045) | 40 |
| R999 | SnmpInterfaceAdminDown | [R2709 / AN2053 (T1695)](https://attack.mitre.org/detectionstrategies/DET0910#AN2053) | 32 |
| R1000 | SnmpIpv4ForwardingDisable | [R2709 / AN2053 (T1695)](https://attack.mitre.org/detectionstrategies/DET0910#AN2053) | 31 |
| Total | 13 | | 414 |

## Evidence boundaries and deduplication
- R988: BACnet Device System_Status property 112; R977 reads Object_List, not device status. R989: ReadPropertyMultiple ALL for one Device, not full namespace enumeration. R990: Out_Of_Service Boolean true for analog/binary input; not R485 scalar or R979 Event_Enable bit string; no claim of output safety role.
- R991: BACnet File stream read at offset 0, 512 bytes requested; R992: stream write 256 bytes at offset 0 with exact canonical octet length. File content/firmware identity, returned bytes, authorized source and acceptance unknown. R978 is Modbus file-read response.
- R993: FINS CPU status read 0601; R994: DM read 0101, exact 256 words, address 0–32512. Distinct from R985 STOP and R984 16-word write. No returned operating mode/data, device model or safe operating range inferred.
- R995: DNP3 integrity poll with all four distinct Group 60 class selectors 1–4 (06 qualifier), including static class 0. R981 is Disable Unsolicited for event classes only. No complete namespace or configuration returned. R996: DNP3 absolute-time WRITE Group 50 Variation 1, qualifier 07 count 1, exact six-byte timestamp. No timestamp retained or clock change inferred. Both use a single CRC-checked master unconfirmed frame; CRC is not authentication.
- R997: Modbus FC23 combined read/write exact same two-register range, both requested write words zero, verified SYN/SYN-ACK and first complete client payload. R998: FC21 single reference-6 file write, 100–120 words, nonzero file and bounded record range, exact byte counts, same TCP guard. R968/R982/R978 are distinct functions/outcomes. No server response or write success.
- R999: SNMP SET ifAdminStatus.<positive canonical ifIndex> down(2). R1000: ipForwarding.0 not-forwarding(2). Single canonical INTEGER binding, complete v1/v2c BER, exact OIDs; no enterprise/UPS overlap. Interface state and forwarding change/communication loss unknown. RFC 2863 https://www.rfc-editor.org/rfc/rfc2863.html and RFC 4293 https://www.rfc-editor.org/rfc/rfc4293.html. No community/OID/values retained.

The capture producer is Carthago.Core PortablePacketProcessor (not the Windows adapter). One typed capture-only enum value, explicit label and disjoint protocol predicates; no raw application data emitted. UDP must be complete and unfragmented; FINS/DNP3 require both native ports; BACnet allows valid client port; SNMP requires non-161 client port. Modbus requires verified handshake, sequence and opposite ACK, first client payload and no server payload; exact standalone plaintext frames, no reassembly. All rules public-to-private IPv4 and reject fabricated labels, contradictory typed fields and invalid protocol/scope. All use independent instance cooldown and fail-closed state.

## Quality and fidelity gates
Positive and negative fixtures exercise raw packet decoding, actual rule evaluation, independent DNP CRC, numeric/length/BER/tag boundaries, malformed/truncated/coalesced/IP fragment, wrong port/direction/scope, TCP handshake/ACK/replay controls, JSON marker forgery, contradictory fields, duplicate/reverse time/cooldown/peer isolation, all 13-way predicate separation, privacy and portable/Windows parity. The 13 per-rule classes have explicit test declarations for source-inventory association. Portable tests link the same wire fixtures and run without WPF. The Python catalog regression covers all 1,000 synthetic registry IDs and four-digit batch filenames, noncanonical IDs and positional descriptor support.

The original workbook benign controls require approved source, documented maintenance, authorization/change control, asset/point identity, baseline history, corroborating process/communication state and exact analytic-specific trusted records. Those producers and independent real-world replays are NOT supplied by this source batch. Authorized polls/writes may match in Shadow. Do not promote based on synthetic tests or registration count. No full malicious/benign accuracy claim. Thresholds and address subsets are explicitly chosen engineering bounds.

## Owner verification
```powershell
dotnet test .\Carthago.Cli.Tests\Carthago.Cli.Tests.csproj -c Release --filter "FullyQualifiedName~IndustrialBatchPortableQualityTests"
dotnet test .\Carthago.Tests\Carthago.Tests.csproj -c Release --filter "FullyQualifiedName~R988|FullyQualifiedName~R989|FullyQualifiedName~R990|FullyQualifiedName~R991|FullyQualifiedName~R992|FullyQualifiedName~R993|FullyQualifiedName~R994|FullyQualifiedName~R995|FullyQualifiedName~R996|FullyQualifiedName~R997|FullyQualifiedName~R998|FullyQualifiedName~R999|FullyQualifiedName~R1000|FullyQualifiedName~IndustrialBatchRegistryQualityTests"
dotnet test .\Carthago.Tests\Carthago.Tests.csproj -c Release
python scripts/test_rule_catalog_ids.py
python scripts/build_rule_catalog.py
python scripts/build_docs_index.py
python scripts/check_docs_links.py
```

Next ID R1001 only after live registry and qualification review. The 1,000-source-rule milestone is not a verified detection-quality milestone.

## Four-digit milestone compatibility

R1000 is classified as a canonical core ID (not a content-pack ID), and the core catalog, available catalog, and session catalog export use numeric core ordering while retaining ordinal pack ordering. The shared registry test checks R999/R1000/R3085, invalid numeric IDs, 410 pack IDs, catalog consistency, and export ordering. The documentation generator accepts canonical four-digit IDs and ranges; regenerate the master catalog from a full checkout after the batch.

### Isolated Python regression execution

The four-digit catalog regression was executed against the copied source catalog parser functions in a temporary Python environment. The initial assertion expected `Medium` where the positional parser contract returns `SeverityLevel.Medium`; the test expectation was corrected, and the rerun passed (1 test). No .NET tests or full-checkout catalog generation were executed.
