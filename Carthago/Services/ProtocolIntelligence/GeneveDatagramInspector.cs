// SPDX-License-Identifier: MIT
using System;
using System.Buffers.Binary;

namespace Carthago.Services.ProtocolIntelligence
{
    /// <summary>
    /// Isolated RFC 8926 Geneve data-envelope inspector. Requires a trusted,
    /// complete UDP/6081 payload. Supports Ethernet payloads and bounded
    /// noncritical options only; no critical-option interpretation, decapsulation,
    /// tunnel authorization, alerting, or retention of inner addresses.
    /// </summary>
    public static class GeneveDatagramInspector
    {
        public static bool TryInspect(ReadOnlySpan<byte> datagram, ushort destinationPort,
            bool verifiedCompleteUdpPayload, out GeneveDatagramObservation observation)
        {
            observation = default;
            if (!verifiedCompleteUdpPayload || destinationPort != 6081
                || datagram.Length is < 42 or > 65535
                || (datagram[0] & 0xc0) != 0
                || datagram[1] != 0 || datagram[7] != 0)
                return false; // Only v0 data packets without unknown critical options.

            int optionBytes = (datagram[0] & 0x3f) * 4;
            int payloadOffset = 8 + optionBytes;
            if (payloadOffset > datagram.Length - 14)
                return false;

            ushort protocolType = BinaryPrimitives.ReadUInt16BigEndian(datagram.Slice(2, 2));
            if (protocolType != 0x6558)
                return false; // Only transparent Ethernet bridging; no speculative L3.

            int optionsSeen = 0;
            for (int index = 8; index < payloadOffset;)
            {
                if (payloadOffset - index < 4 || (datagram[index + 3] & 0xe0) != 0
                    || (datagram[index + 2] & 0x80) != 0)
                    return false; // Unknown critical option: fail closed.
                int optionSize = 4 + (datagram[index + 3] & 0x1f) * 4;
                if (optionSize > payloadOffset - index)
                    return false;
                index += optionSize;
                optionsSeen++;
            }

            int vni = (datagram[4] << 16) | (datagram[5] << 8) | datagram[6];
            ReadOnlySpan<byte> inner = datagram.Slice(payloadOffset);
            ushort etherType = BinaryPrimitives.ReadUInt16BigEndian(inner.Slice(12, 2));
            bool vlan = etherType is 0x8100 or 0x88a8;
            int innerOffset = 14;
            if (vlan)
            {
                if (inner.Length < 18)
                    return false;
                etherType = BinaryPrimitives.ReadUInt16BigEndian(inner.Slice(16, 2));
                if (etherType is 0x8100 or 0x88a8)
                    return false; // Nested VLAN needs a separately reviewed adapter.
                innerOffset = 18;
            }

            ReadOnlySpan<byte> payload = inner.Slice(innerOffset);
            if (etherType == 0x0800)
            {
                if (payload.Length < 20 || (payload[0] >> 4) != 4)
                    return false;
                int ihl = (payload[0] & 0x0f) * 4;
                if (ihl < 20 || ihl > payload.Length)
                    return false;
                int totalLength = BinaryPrimitives.ReadUInt16BigEndian(payload.Slice(2, 2));
                if (totalLength < ihl || totalLength > payload.Length)
                    return false;
            }
            else if (etherType == 0x86dd)
            {
                if (payload.Length < 40 || (payload[0] >> 4) != 6)
                    return false;
                int length = BinaryPrimitives.ReadUInt16BigEndian(payload.Slice(4, 2));
                if (length == 0 || length > payload.Length - 40)
                    return false; // No jumbograms or zero-length IPv6 payload claims.
            }
            else if (etherType == 0x0806)
            {
                if (payload.Length < 28)
                    return false; // ARP envelope only, not an ARP semantic decoder.
            }
            else
            {
                return false;
            }

            observation = new GeneveDatagramObservation(vni, etherType, vlan,
                optionsSeen, datagram.Length);
            return true;
        }
    }

    public readonly record struct GeneveDatagramObservation(
        int Vni, ushort InnerEtherType, bool HasVlanTag,
        int NonCriticalOptionCount, int DatagramLength);
}
