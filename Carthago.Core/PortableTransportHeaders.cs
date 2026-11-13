// SPDX-License-Identifier: MIT
using System.Buffers.Binary;

namespace Carthago.Services;

/// <summary>Bounded transport decoding over a previously decoded IP frame.</summary>
internal static class PortableTransportHeaders
{
    internal readonly record struct TransportHeader(string Protocol, int? SourcePort, int? DestinationPort,
        bool IsTcp, bool IsUdp, ushort? TcpFlags, ushort? IcmpTypeCode, int? PayloadLength,
        int PayloadOffset, int PayloadCount, uint Sequence, uint Acknowledgment, bool Syn, bool Ack);

    internal static TransportHeader? Parse(ReadOnlySpan<byte> frame, PortableFrameHeaders.IpHeader ip)
    {
        int l4Offset = ip.TransportOffset, ipEnd = ip.End, ipPayloadLen = ip.PayloadLength;
        byte l4Proto = ip.TransportProtocol;
        if (l4Offset < 0 || ipEnd < l4Offset || ipEnd > frame.Length ||
            ipPayloadLen < 0 || ipPayloadLen > ipEnd - l4Offset) return null;
        // ====== L4: TCP / UDP / ICMP ======
        int? sport = null, dport = null;
        string protoLabel;
        bool isTcp = false, isUdp = false;
        ushort? tcpFlagsField = null;
        ushort? icmpTypeCode = null;
        int? l4PayloadLen = null;
        int payloadOffset = 0, payloadCount = 0;
        int tcpDataOffset = 0;
        uint seq = 0, ack = 0;
        bool tcpSyn = false, tcpAck = false;

        switch (l4Proto)
        {
            case 6: // TCP
                {
                    if (ipPayloadLen < 20 || l4Offset + 20 > ipEnd) return null;
                    isTcp = true;
                    sport = BinaryPrimitives.ReadUInt16BigEndian(frame.Slice(l4Offset, 2));
                    dport = BinaryPrimitives.ReadUInt16BigEndian(frame.Slice(l4Offset + 2, 2));
                    seq = BinaryPrimitives.ReadUInt32BigEndian(frame.Slice(l4Offset + 4, 4));
                    ack = BinaryPrimitives.ReadUInt32BigEndian(frame.Slice(l4Offset + 8, 4));
                    byte doRes = frame[l4Offset + 12];
                    byte flags = frame[l4Offset + 13];
                    tcpDataOffset = (doRes >> 4) * 4;
                    tcpSyn = (flags & 0x02) != 0;
                    tcpAck = (flags & 0x10) != 0;

                    // Include NS flag from low bit of doRes if you want 9+ flags
                    tcpFlagsField = (ushort)((doRes & 0x01) << 8 | flags);

                    if (tcpDataOffset < 20 || tcpDataOffset > ipPayloadLen ||
                        l4Offset + tcpDataOffset > ipEnd)
                        return null;

                    int tcpAvail = Math.Min(ipPayloadLen - tcpDataOffset, ipEnd - (l4Offset + tcpDataOffset));
                    payloadOffset = l4Offset + tcpDataOffset;
                    payloadCount = Math.Max(0, tcpAvail);
                    l4PayloadLen = tcpAvail;

                    protoLabel = "TCP";
                    break;
                }

            case 17: // UDP
                {
                    if (ipPayloadLen < 8 || l4Offset + 8 > ipEnd) return null;
                    isUdp = true;
                    sport = BinaryPrimitives.ReadUInt16BigEndian(frame.Slice(l4Offset, 2));
                    dport = BinaryPrimitives.ReadUInt16BigEndian(frame.Slice(l4Offset + 2, 2));
                    ushort udpLen = BinaryPrimitives.ReadUInt16BigEndian(frame.Slice(l4Offset + 4, 2));
                    if (udpLen < 8 || udpLen > ipPayloadLen) return null;
                    int payloadLen = Math.Min(udpLen - 8, ipEnd - (l4Offset + 8));
                    payloadOffset = l4Offset + 8;
                    payloadCount = payloadLen;
                    l4PayloadLen = payloadLen;
                    protoLabel = "UDP";
                    break;
                }

            case 1: // ICMPv4
                {
                    if (ipPayloadLen < 2 || l4Offset + 2 > ipEnd) return null;
                    icmpTypeCode = (ushort)((frame[l4Offset] << 8) | frame[l4Offset + 1]);
                    l4PayloadLen = Math.Max(0, ipPayloadLen);
                    protoLabel = "ICMP";
                    break;
                }

            case 58: // ICMPv6
                {
                    if (ipPayloadLen < 2 || l4Offset + 2 > ipEnd) return null;
                    icmpTypeCode = (ushort)((frame[l4Offset] << 8) | frame[l4Offset + 1]);
                    l4PayloadLen = Math.Max(0, ipPayloadLen);
                    protoLabel = "ICMPv6";
                    break;
                }

            default:
                return null; // Fast path only tracks TCP/UDP/ICMP
        }
        return new TransportHeader(protoLabel, sport, dport, isTcp, isUdp, tcpFlagsField,
            icmpTypeCode, l4PayloadLen, payloadOffset, payloadCount, seq, ack, tcpSyn, tcpAck);
    }
}
