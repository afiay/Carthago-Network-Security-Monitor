// SPDX-License-Identifier: MIT
using System;
using System.Buffers.Binary;

namespace Carthago.Services.ProtocolIntelligence
{
    /// <summary>
    /// Source-only MS-TDS 7.x plaintext packet-envelope observation. Requires one
    /// caller-attested complete, reassembled TCP TDS packet and a trusted SQL
    /// endpoint. Does not inspect SQL text, login, credentials, results or TLS.
    /// TDS 8.0 TLS-first traffic is not observable through this inspector.
    /// </summary>
    public static class TdsPacketEnvelopeInspector
    {
        private const int HeaderLength = 8;
        private const int MaximumPacketLength = 4096; // conservative pre-negotiation limit

        public static bool TryInspect(ReadOnlySpan<byte> packet,
            bool verifiedCompletePlaintextPacket, out TdsPacketEnvelopeObservation observation)
        {
            observation = default;
            if (!verifiedCompletePlaintextPacket ||
                packet.Length is < HeaderLength or > MaximumPacketLength)
                return false;

            byte type = packet[0];
            if (type is not (0x01 or 0x03 or 0x04 or 0x06 or 0x07
                or 0x0e or 0x10 or 0x11 or 0x12))
                return false;

            byte status = packet[1];
            if ((status & ~0x1b) != 0 || (status & 0x18) == 0x18)
                return false;

            int declaredLength = BinaryPrimitives.ReadUInt16BigEndian(packet.Slice(2, 2));
            if (declaredLength != packet.Length || packet[7] != 0)
                return false;

            // ATTENTION has no body. Other supported message types require
            // a payload; no claim about its contents or successful execution.
            if (type == 0x06 ? packet.Length != HeaderLength : packet.Length == HeaderLength)
                return false;

            observation = new TdsPacketEnvelopeObservation(
                type, (status & 0x01) != 0, packet.Length,
                type == 0x12);
            return true;
        }
    }

    public readonly record struct TdsPacketEnvelopeObservation(
        byte PacketType, bool EndOfMessage, int PacketLength,
        bool PreloginMayEncapsulateTls);
}
