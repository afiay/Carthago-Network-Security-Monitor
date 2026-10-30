// SPDX-License-Identifier: MIT
using System;
using System.Buffers.Binary;

namespace Carthago.Services.ProtocolIntelligence
{
    /// <summary>
    /// Isolated RFC 2784 / RFC 2890 GRE envelope recognition. Caller must attest
    /// a complete IP protocol 47 payload. No decapsulation, tunnel authentication,
    /// routing, alerts, key/sequence retention, or live-capture registration.
    /// </summary>
    public static class GrePacketInspector
    {
        public static bool TryInspect(ReadOnlySpan<byte> packet, byte ipProtocol,
            bool verifiedCompleteIpPayload, out GrePacketObservation observation)
        {
            observation = default;
            if (!verifiedCompleteIpPayload || ipProtocol != 47
                || packet.Length is < 18 or > 65535)
                return false;

            ushort flags = BinaryPrimitives.ReadUInt16BigEndian(packet);
            // Only RFC 2784 checksum and RFC 2890 key/sequence extensions.
            // Reject other flags, deprecated routing, and nonzero versions.
            if ((flags & 0x4fff) != 0)
                return false;

            bool hasChecksum = (flags & 0x8000) != 0;
            bool hasKey = (flags & 0x2000) != 0;
            bool hasSequence = (flags & 0x1000) != 0;
            int headerLength = 4 + (hasChecksum ? 4 : 0)
                + (hasKey ? 4 : 0) + (hasSequence ? 4 : 0);
            if (headerLength >= packet.Length)
                return false;

            ushort innerType = BinaryPrimitives.ReadUInt16BigEndian(packet.Slice(2, 2));
            if (innerType is not (0x0800 or 0x86dd or 0x6558))
                return false;

            if (hasChecksum)
            {
                if (packet[6] != 0 || packet[7] != 0)
                    return false;
                uint sum = 0;
                for (int i = 0; i < packet.Length; i += 2)
                {
                    ushort word = (ushort)(packet[i] << 8);
                    if (i + 1 < packet.Length)
                        word |= packet[i + 1];
                    sum += word;
                    sum = (sum & 0xffff) + (sum >> 16);
                }
                sum = (sum & 0xffff) + (sum >> 16);
                if (sum != 0xffff)
                    return false;
            }

            ReadOnlySpan<byte> inner = packet.Slice(headerLength);
            if (innerType == 0x0800)
            {
                if (inner.Length < 20 || (inner[0] >> 4) != 4)
                    return false;
                int ihl = (inner[0] & 15) * 4;
                if (ihl < 20 || ihl > inner.Length)
                    return false;
                int total = BinaryPrimitives.ReadUInt16BigEndian(inner.Slice(2, 2));
                if (total < ihl || total > inner.Length)
                    return false;
            }
            else if (innerType == 0x86dd)
            {
                if (inner.Length < 40 || (inner[0] >> 4) != 6)
                    return false;
                int payloadLength = BinaryPrimitives.ReadUInt16BigEndian(inner.Slice(4, 2));
                if (payloadLength == 0 || payloadLength > inner.Length - 40)
                    return false; // IPv6 jumbograms deliberately unsupported.
            }
            else
            {
                if (inner.Length < 14
                    || BinaryPrimitives.ReadUInt16BigEndian(inner.Slice(12, 2)) < 0x0600)
                    return false; // Transparent Ethernet bridging envelope only.
            }

            observation = new GrePacketObservation(innerType, headerLength,
                packet.Length, hasChecksum, hasKey, hasSequence);
            return true;
        }
    }

    public readonly record struct GrePacketObservation(
        ushort InnerEtherType, int HeaderLength, int PacketLength,
        bool HasChecksum, bool HasKey, bool HasSequence);
}
