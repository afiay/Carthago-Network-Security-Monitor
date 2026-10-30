// SPDX-License-Identifier: MIT
using System;
using System.Buffers.Binary;

namespace Carthago.Services.ProtocolIntelligence
{
    /// <summary>
    /// Isolated RFC 2328 OSPFv2 packet-envelope validation, not LSA parsing,
    /// neighbor authentication, adjacency validation or route-change detection.
    /// Requires a complete caller-attested IP protocol 89 payload. Authenticated
    /// packets are deliberately unsupported rather than falsely verified.
    /// </summary>
    public static class OspfV2PacketInspector
    {
        public static bool TryInspect(ReadOnlySpan<byte> packet, byte ipProtocol,
            bool verifiedCompleteIpPayload, out OspfV2PacketObservation observation)
        {
            observation = default;
            if (!verifiedCompleteIpPayload || ipProtocol != 89
                || packet.Length is < 24 or > 65535
                || packet[0] != 2 || packet[1] is < 1 or > 5
                || BinaryPrimitives.ReadUInt16BigEndian(packet.Slice(2, 2)) != packet.Length)
                return false;

            // Only AuType 0 (Null). Do not infer valid cryptographic authentication.
            if (packet[14] != 0 || packet[15] != 0)
                return false;
            for (int index = 16; index < 24; index++)
                if (packet[index] != 0)
                    return false;

            int bodyLength = packet.Length - 24;
            switch (packet[1])
            {
                case 1: // Hello: fixed 20 bytes followed by 4-byte neighbor IDs.
                    if (bodyLength < 20 || (bodyLength - 20) % 4 != 0)
                        return false;
                    break;
                case 2: // Database description: fixed 8 bytes, optional 20-byte LSA headers.
                    if (bodyLength < 8 || (bodyLength - 8) % 20 != 0)
                        return false;
                    break;
                case 3: // Link state request: 12-byte request entries.
                    if (bodyLength < 12 || bodyLength % 12 != 0)
                        return false;
                    break;
                case 4: // Link state update: 4-byte count, then at least 20 bytes per LSA.
                    if (bodyLength < 24)
                        return false;
                    uint lsaCount = BinaryPrimitives.ReadUInt32BigEndian(packet.Slice(24, 4));
                    if (lsaCount == 0 || lsaCount > (uint)((bodyLength - 4) / 20))
                        return false;
                    break;
                case 5: // Link state acknowledgment: 20-byte LSA headers.
                    if (bodyLength < 20 || bodyLength % 20 != 0)
                        return false;
                    break;
            }

            // RFC 2328 checksum excludes authentication field bytes 16..23.
            uint sum = 0;
            for (int index = 0; index < packet.Length; index += 2)
            {
                if (index is >= 16 and < 24)
                    continue;
                ushort word = (ushort)(packet[index] << 8);
                if (index + 1 < packet.Length)
                    word |= packet[index + 1];
                sum += word;
                sum = (sum & 0xffff) + (sum >> 16);
            }
            sum = (sum & 0xffff) + (sum >> 16);
            if (sum != 0xffff)
                return false;

            // Router ID, area ID, LSA bodies and authentication bytes are never retained.
            observation = new OspfV2PacketObservation((OspfV2PacketKind)packet[1], packet.Length);
            return true;
        }
    }

    public enum OspfV2PacketKind : byte
    {
        Hello = 1,
        DatabaseDescription = 2,
        LinkStateRequest = 3,
        LinkStateUpdate = 4,
        LinkStateAcknowledgment = 5
    }

    public readonly record struct OspfV2PacketObservation(
        OspfV2PacketKind Kind, int PacketLength);
}
