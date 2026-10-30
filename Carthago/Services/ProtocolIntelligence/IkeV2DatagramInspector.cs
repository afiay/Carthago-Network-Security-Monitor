// SPDX-License-Identifier: MIT
using System;
using System.Buffers.Binary;

namespace Carthago.Services.ProtocolIntelligence
{
    /// <summary>
    /// Isolated bounded IKEv2 header/payload-envelope inspection for one complete
    /// caller-attested UDP datagram on ports 500 or 4500. Never decrypts SK/SKF,
    /// authenticates peers, parses certificates or asserts CVE exploitation.
    /// NAT-T's four-byte non-ESP marker is excluded from the IKE length.
    /// </summary>
    public static class IkeV2DatagramInspector
    {
        private const int HeaderLength = 28;
        private const int MaxDatagramBytes = 65_535;
        private const int MaxPayloads = 24;

        public static bool TryInspect(
            ReadOnlySpan<byte> datagram,
            int sourcePort,
            int destinationPort,
            bool verifiedUdpDatagramBoundary,
            out IkeV2DatagramObservation observation)
        {
            observation = default;
            if (!verifiedUdpDatagramBoundary || datagram.Length > MaxDatagramBytes
                || (sourcePort != 500 && destinationPort != 500
                    && sourcePort != 4500 && destinationPort != 4500))
                return false;

            bool natTraversal = sourcePort == 4500 || destinationPort == 4500;
            if (natTraversal)
            {
                if (datagram.Length < 4 + HeaderLength + 4
                    || datagram[0] != 0 || datagram[1] != 0
                    || datagram[2] != 0 || datagram[3] != 0)
                    return false;
                datagram = datagram.Slice(4);
            }

            if (datagram.Length < HeaderLength + 4)
                return false;

            bool nonzeroInitiatorSpi = false;
            for (int i = 0; i < 8; i++)
                nonzeroInitiatorSpi |= datagram[i] != 0;
            if (!nonzeroInitiatorSpi)
                return false;

            byte version = datagram[17];
            byte exchange = datagram[18];
            byte flags = datagram[19];
            if ((version >> 4) != 2 || exchange is < 34 or > 37
                || (flags & 0xC7) != 0)
                return false;

            uint messageId = BinaryPrimitives.ReadUInt32BigEndian(datagram.Slice(20, 4));
            uint declaredLength = BinaryPrimitives.ReadUInt32BigEndian(datagram.Slice(24, 4));
            if (declaredLength != (uint)datagram.Length)
                return false;

            byte payloadType = datagram[16];
            if (payloadType == 0)
                return false;

            int cursor = HeaderLength;
            int count = 0;
            bool encrypted = false;
            while (payloadType != 0)
            {
                if (++count > MaxPayloads || datagram.Length - cursor < 4)
                    return false;

                byte nextType = datagram[cursor];
                int payloadLength = BinaryPrimitives.ReadUInt16BigEndian(datagram.Slice(cursor + 2, 2));
                if (payloadLength < 4 || payloadLength > datagram.Length - cursor)
                    return false;

                // SK and SKF bodies are ciphertext. The next-payload byte in
                // their generic header describes encrypted *inner* payloads.
                // It is not a visible outer payload-chain continuation.
                if (payloadType == 46 || payloadType == 53)
                {
                    if (payloadLength < (payloadType == 53 ? 8 : 5)
                        || cursor + payloadLength != datagram.Length)
                        return false;
                    encrypted = true;
                    cursor += payloadLength;
                    break;
                }

                cursor += payloadLength;
                payloadType = nextType;
            }

            if (cursor != datagram.Length)
                return false;

            observation = new IkeV2DatagramObservation(
                exchange, (flags & 0x20) != 0, natTraversal,
                messageId, count, encrypted);
            return true;
        }
    }

    /// <summary>Untrusted IKEv2 envelope metadata, not authenticated negotiation.</summary>
    public readonly record struct IkeV2DatagramObservation(
        byte ExchangeType,
        bool IsResponse,
        bool NatTraversalMarkerPresent,
        uint MessageId,
        int OuterPayloadCount,
        bool ContainsEncryptedPayload);
}
