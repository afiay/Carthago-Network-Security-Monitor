# Live Traffic protocol-header presentation (2026-11-17)

## Scope and provenance

The Live Traffic grid and the packet-details window now display TCP and ICMP header
fields with **protocol-aware status semantics**. The change is presentation-only:

- **TCP Flags**: shows the parsed textual label when available; otherwise derives
  standard names (NS, SYN, ACK, FIN, RST, PSH, URG, ECE, CWR) from the raw TCP bitmask,
  without writing back to the captured `TrafficRecord`.
- **TCP Flags (hex/dec)**: shows the original numeric `TrafficRecord.TcpFlags` in
  hexadecimal and decimal, e.g. `0x012 (18)`. A missing raw value remains **—**
  even if text flags are available; no inferred bitmask is presented as evidence.
- **ICMP Type** and **ICMP Code**: unpack the original 16-bit
  `TrafficRecord.IcmpTypeCode` using `type = value >> 8` and
  `code = value & 0xFF`. For example, ICMPv4 Echo Request `0x0800`
  displays type **8** and code **0**; ICMPv6 Echo Request `0x8000`
  displays type **128** and code **0**.
- **N/A**: the field does not apply to the known protocol (e.g. TCP flags
  on a UDP/ICMP row).
- **—**: the field would apply but is missing/unobserved, or there is
  insufficient protocol information to establish applicability.
- **NONE**: a zero raw TCP flags bitmask was actually observed. This is not
  equivalent to missing flags.

Displayed values are derived using the internal, testable
`LiveTrafficHeaderFormatter` and a thin WPF
`LiveTrafficHeaderConverter`. The columns expose full text on hover,
with accessible help text distinguishing N/A from unavailable.

**Source paths unchanged:** raw packet decoding
(`Carthago.Core/PortableTransportHeaders.cs`), `TrafficRecord` model,
`PortablePacketProcessor`, detection rules, event journaling, and
exports are unchanged. A nullable header value is not forcibly set to zero.
The GUI continues to use the existing bounded `TrafficGrid` collection
and virtualization. Source support still depends on the capture backend;
the change cannot reconstruct missing headers from ETW or truncated frames.

## Focused tests

```powershell
git pull --ff-only origin feature/carthago-reliability-hardening
dotnet build .\Carthago\Carthago.csproj -c Release
dotnet test .\Carthago.Tests\Carthago.Tests.csproj -c Release --filter "FullyQualifiedName~LiveTrafficHeaderFormatterTests"
```

Tests check TCP SYN/ACK, raw bitmask formatting, NS+ACK+PSH, zero vs
missing flags, text-only evidence, ICMPv4/v6 packing, UDP/ARP non-applicability,
and unknown protocol/data. UI formatting is not a validation of packet capture
accuracy and must not be reported as such.

## Windows live UI acceptance

1. Start capture on a known Npcap-enabled interface. On Windows, run
   `ping 1.1.1.1` and `curl.exe -I https://example.com` to generate
   permitted ICMP and TCP traffic. The rows depend on the actual interface,
   firewall, VPN, and whether traffic reaches the capture path.
2. Inspect matching **TCP** records: flags should show their text and the
   raw hexadecimal/decimal value if the decoder observed those fields.
3. Inspect matching **ICMP/ICMPv6** records: type and code should show as
   two separate integers. `0` is a valid ICMP code and must not be hidden.
4. Inspect **UDP/ARP** records: these header fields should display `N/A`.
   Missing applicable fields should show **—**, not `N/A` or invented zero.
5. Double-click rows and compare the packet-details presentation against
   the Live Traffic columns. Verify copy/export and rules preserve the original
   numeric `TcpFlags` / packed `IcmpTypeCode` values.
6. Test scrolling, tooltip content, narrow-window truncation, live updates,
   and Npcap versus ETW capture provenance; do not claim operational
   acceptance without this observed Windows evidence.

## Status

Source changes and focused tests committed to the existing
`feature/carthago-reliability-hardening` branch.
**Windows build, tests and GUI live-capture acceptance for these changes are pending.**
