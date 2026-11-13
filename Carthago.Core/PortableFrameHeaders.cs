// SPDX-License-Identifier: MIT
using System.Buffers.Binary;
using System.Net;
using System.Text;

namespace Carthago.Services;

/// <summary>Host-independent framing. No capture driver or rule evaluation required.</summary>
internal static class PortableFrameHeaders
{
    internal readonly record struct LinkHeader(int Offset, ushort EtherType, string MacSource, string MacDestination);
    internal readonly record struct IpHeader(bool IsIPv4, string Source, string Destination, string Ttl,
        string Version, int PayloadLength, byte TransportProtocol, int TransportOffset,
        int PacketLength, int End, bool Complete);

    internal static LinkHeader? ParseLink(ReadOnlySpan<byte> frame, int linkLayerType)
    {
        if (frame.IsEmpty) return null;
        string macDst = string.Empty;
        string macSrc = string.Empty;
        int off;
        ushort etherType;

        switch (linkLayerType)
        {
            case 1: // Ethernet
                if (frame.Length < 14) return null;
                macDst = MacToString(frame.Slice(0, 6));
                macSrc = MacToString(frame.Slice(6, 6));
                off = 12;
                etherType = BinaryPrimitives.ReadUInt16BigEndian(frame.Slice(off, 2));
                off += 2;
                break;

            case 0: // BSD loopback/null
                if (frame.Length < 5) return null;
                uint family = BinaryPrimitives.ReadUInt32LittleEndian(frame.Slice(0, 4));
                off = 4;
                etherType = family == 2
                    ? (ushort)0x0800
                    : family is 23 or 24 or 28 or 30
                        ? (ushort)0x86DD
                        : (ushort)0;
                break;

            case 12:  // DLT_RAW
            case 101: // LINKTYPE_RAW
            case 228: // LINKTYPE_IPV4
            case 229: // LINKTYPE_IPV6
                off = 0;
                etherType = (frame[0] >> 4) switch
                {
                    4 => (ushort)0x0800,
                    6 => (ushort)0x86DD,
                    _ => (ushort)0
                };
                break;

            case 113: // Linux cooked capture v1
                if (frame.Length < 16) return null;
                off = 16;
                etherType = BinaryPrimitives.ReadUInt16BigEndian(frame.Slice(14, 2));
                break;

            case 276: // Linux cooked capture v2
                if (frame.Length < 20) return null;
                off = 20;
                etherType = BinaryPrimitives.ReadUInt16BigEndian(frame.Slice(0, 2));
                break;

            default:
                return null;
        }

        // VLAN tags (802.1Q/AD stacked)
        int vlanDepth = 0;
        while (etherType == 0x8100 || etherType == 0x88A8)
        {
            if (++vlanDepth > 8) return null;
            if (off + 2 > frame.Length) return null;
            // skip TCI (2) and read next EtherType
            off += 2;
            if (off + 2 > frame.Length) return null;
            etherType = BinaryPrimitives.ReadUInt16BigEndian(frame.Slice(off, 2));
            off += 2;
        }
        return new LinkHeader(off, etherType, macSrc, macDst);
    }

    internal static IpHeader? ParseIp(ReadOnlySpan<byte> frame, LinkHeader link)
    {
        int off = link.Offset;
        ushort etherType = link.EtherType;
        if (off < 0 || off > frame.Length) return null;
        // ====== L3: IPv4 / IPv6 ======
        bool isIPv4 = etherType == 0x0800;
        bool isIPv6 = etherType == 0x86DD;

        if (!isIPv4 && !isIPv6)
        {
            // Nothing to do for non-IP on fast path. No fallback needed.
            return null;
        }

        string srcIp, dstIp, ttlStr, ipVersionStr;
        int ipPayloadLen;
        byte l4Proto;
        int l4Offset;
        int ipPacketLength;
        int ipEnd;
        bool completeIpPacket;

        if (isIPv4)
        {
            if (off + 20 > frame.Length) return null;
            byte vihl = frame[off];
            int ihl = (vihl & 0x0F) * 4;
            if ((vihl >> 4) != 4 || ihl < 20 || off + ihl > frame.Length) return null;

            ushort totalLen = BinaryPrimitives.ReadUInt16BigEndian(frame.Slice(off + 2, 2));
            if (totalLen < ihl) return null;

            // No fragment reassembly: do not misinterpret fragment bytes as L4 headers.
            ushort fragmentField = BinaryPrimitives.ReadUInt16BigEndian(frame.Slice(off + 6, 2));
            if ((fragmentField & 0x3FFF) != 0) return null;

            byte ttl = frame[off + 8];
            l4Proto = frame[off + 9];
            ipPacketLength = totalLen;
            ipEnd = Math.Min(frame.Length, off + totalLen);
            completeIpPacket = frame.Length - off >= totalLen;

            srcIp = new IPAddress(frame.Slice(off + 12, 4).ToArray()).ToString();
            dstIp = new IPAddress(frame.Slice(off + 16, 4).ToArray()).ToString();

            ttlStr = ttl.ToString();
            ipVersionStr = "4";
            l4Offset = off + ihl;
            ipPayloadLen = Math.Max(0, ipEnd - l4Offset);
        }
        else
        {
            // IPv6 (basic extension-header walk; drop non-first fragments)
            if (off + 40 > frame.Length) return null;
            if ((frame[off] >> 4) != 6) return null;

            ushort payloadLen = BinaryPrimitives.ReadUInt16BigEndian(frame.Slice(off + 4, 2));
            byte nextHeader = frame[off + 6];
            byte hopLimit = frame[off + 7];

            srcIp = new IPAddress(frame.Slice(off + 8, 16).ToArray()).ToString();
            dstIp = new IPAddress(frame.Slice(off + 24, 16).ToArray()).ToString();

            ttlStr = hopLimit.ToString();
            ipVersionStr = "6";

            int cursor = off + 40;
            ipPacketLength = 40 + payloadLen;
            ipEnd = Math.Min(frame.Length, cursor + payloadLen);
            completeIpPacket = frame.Length - off >= ipPacketLength;
            int remaining = ipEnd - cursor;
            // IPv6 extension length rules differ for AH (RFC 4302).
            for (int i = 0; i < 16; i++)
            {
                // Fragment header (44) => drop non-first fragments
                if (nextHeader == 44)
                {
                    if (remaining < 8) return null;
                    ushort fragOffFlags = BinaryPrimitives.ReadUInt16BigEndian(frame.Slice(cursor + 2, 2));
                    int fragOffset8 = (fragOffFlags >> 3) & 0x1FFF;
                    byte nh = frame[cursor];
                    if ((fragOffFlags & 0xFFF9) != 0) return null; // no fragment reassembly; permit atomic fragments only
                    nextHeader = nh;
                    int hdrLen = 8;
                    cursor += hdrLen; remaining -= hdrLen;
                    continue;
                }
                // Hop-by-hop (0), Routing (43), DestOpts(60), AH(51) – skip length-based
                if (nextHeader is 0 or 43 or 60 or 51)
                {
                    if (remaining < 8) return null;
                    byte hdrExtLen = frame[cursor + 1]; // in 8-octet units (not counting first 8 octets)
                    int hdrLen = nextHeader == 51
                        ? (hdrExtLen + 2) * 4
                        : (hdrExtLen + 1) * 8;
                    byte nh = frame[cursor];
                    if (hdrLen > remaining) return null;
                    nextHeader = nh;
                    cursor += hdrLen; remaining -= hdrLen;
                    continue;
                }
                break;
            }

            l4Proto = nextHeader;
            l4Offset = cursor;
            // Do not inspect packets with more extension headers than supported.
            if (nextHeader is 0 or 43 or 44 or 51 or 60) return null;
            ipPayloadLen = Math.Max(0, Math.Min(remaining, ipEnd - cursor));
        }
        return new IpHeader(isIPv4, srcIp, dstIp, ttlStr, ipVersionStr, ipPayloadLen, l4Proto,
            l4Offset, ipPacketLength, ipEnd, completeIpPacket);
    }

        internal static string MacToString(ReadOnlySpan<byte> mac)
        {
            if (mac.Length < 6) return "N/A";
            var sb = new StringBuilder(17);
            for (int i = 0; i < 6; i++)
            {
                if (i > 0) sb.Append(':');
                sb.Append(mac[i].ToString("X2"));
            }
            return sb.ToString();
        }
}
