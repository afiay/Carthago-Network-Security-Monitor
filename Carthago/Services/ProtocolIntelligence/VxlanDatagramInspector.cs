// SPDX-License-Identifier: MIT
using System;
using System.Buffers.Binary;

namespace Carthago.Services.ProtocolIntelligence
{
    /// <summary>
    /// Isolated strict RFC 7348 base VXLAN/UDP envelope inspector. Requires
    /// a caller-attested complete UDP payload; does not decapsulate, verify
    /// tunnel authorization, retain MAC/IP addresses, or emit detections.
    /// Extensions with nonzero reserved bits are deliberately unsupported.
    /// </summary>
    public static class VxlanDatagramInspector
    {
        public static bool TryInspect(ReadOnlySpan<byte> datagram, ushort destinationPort,
            bool verifiedCompleteUdpPayload, out VxlanDatagramObservation observation)
        {
            observation = default;
            if (!verifiedCompleteUdpPayload || destinationPort != 4789
                || datagram.Length is < 23 or > 65535
                || datagram[0] != 0x08 || datagram[1] != 0
                || datagram[2] != 0 || datagram[3] != 0 || datagram[7] != 0)
                return false;

            int vni = (datagram[4] << 16) | (datagram[5] << 8) | datagram[6];
            ReadOnlySpan<byte> inner = datagram.Slice(8);
            if (inner.Length < 15)
                return false;

            ushort etherType = BinaryPrimitives.ReadUInt16BigEndian(inner.Slice(12, 2));
            bool hasVlan = etherType is 0x8100 or 0x88a8;
            int payloadOffset = 14;
            if (hasVlan)
            {
                if (inner.Length < 19)
                    return false;
                etherType = BinaryPrimitives.ReadUInt16BigEndian(inner.Slice(16, 2));
                payloadOffset = 18;
                // One VLAN tag supported; nested tags need separate adapter review.
                if (etherType is 0x8100 or 0x88a8)
                    return false;
            }

            if (etherType < 0x0600)
                return false; // No 802.3 LLC interpretation.
            ReadOnlySpan<byte> payload = inner.Slice(payloadOffset);
            if (etherType == 0x0800)
            {
                if (payload.Length < 20 || (payload[0] >> 4) != 4)
                    return false;
                int ihl = (payload[0] & 15) * 4;
                if (ihl < 20 || ihl > payload.Length)
                    return false;
                int total = BinaryPrimitives.ReadUInt16BigEndian(payload.Slice(2, 2));
                if (total < ihl || total > payload.Length)
                    return false;
            }
            else if (etherType == 0x86dd)
            {
                if (payload.Length < 40 || (payload[0] >> 4) != 6)
                    return false;
                int size = BinaryPrimitives.ReadUInt16BigEndian(payload.Slice(4, 2));
                if (size == 0 || size > payload.Length - 40)
                    return false; // IPv6 jumbograms not supported.
            }
            else if (etherType == 0x0806 && payload.Length < 28)
            {
                return false; // Common Ethernet/IPv4 ARP shape, not ARP parsing.
            }

            observation = new VxlanDatagramObservation(vni, etherType,
                hasVlan, datagram.Length);
            return true;
        }
    }

    public readonly record struct VxlanDatagramObservation(
        int Vni, ushort InnerEtherType, bool HasVlanTag, int DatagramLength);
}
