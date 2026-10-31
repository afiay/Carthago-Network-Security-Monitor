// SPDX-License-Identifier: MIT
using System;
using System.Buffers.Binary;

namespace Carthago.Services.ProtocolIntelligence
{
    /// <summary>
    /// Source-only AJP/1.3 message envelope inspection (Apache mod_jk reference).
    /// Requires one complete plaintext TCP AJP packet and independently trusted
    /// proxy/container endpoint provenance. No URL, headers, request attributes,
    /// secrets, body, authentication or server outcome is inspected or retained.
    /// </summary>
    public static class Ajp13EnvelopeInspector
    {
        private const int HeaderLength = 4;
        private const int MaximumPacketLength = 8192;

        public static bool TryInspect(ReadOnlySpan<byte> packet,
            bool verifiedCompletePlaintextPacket, bool verifiedAjpEndpoint,
            out Ajp13EnvelopeObservation observation)
        {
            observation = default;
            if (!verifiedCompletePlaintextPacket || !verifiedAjpEndpoint ||
                packet.Length is < 5 or > MaximumPacketLength)
                return false;

            ushort magic = BinaryPrimitives.ReadUInt16BigEndian(packet.Slice(0, 2));
            bool proxyToContainer = magic == 0x1234;
            if (!proxyToContainer && magic != 0x4142)
                return false;

            int payloadLength = BinaryPrimitives.ReadUInt16BigEndian(packet.Slice(2, 2));
            if (payloadLength != packet.Length - HeaderLength)
                return false;

            byte code = packet[HeaderLength];
            bool supported = proxyToContainer
                ? code switch
                {
                    0x02 => payloadLength >= 3, // Forward Request; body not decoded
                    0x07 or 0x08 or 0x0A => payloadLength == 1,
                    _ => false // AJP request body has no prefix; cannot classify here
                }
                : code switch
                {
                    0x03 or 0x04 or 0x06 => payloadLength >= 3,
                    0x05 => payloadLength == 2,
                    0x09 => payloadLength == 1,
                    _ => false
                };

            if (!supported)
                return false;

            observation = new Ajp13EnvelopeObservation(
                proxyToContainer, code, packet.Length);
            return true;
        }
    }

    public readonly record struct Ajp13EnvelopeObservation(
        bool ProxyToContainer, byte MessageCode, int PacketLength);
}
