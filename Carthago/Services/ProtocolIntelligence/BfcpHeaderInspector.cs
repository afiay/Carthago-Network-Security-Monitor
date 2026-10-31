// SPDX-License-Identifier: MIT
using System;
using System.Buffers.Binary;

namespace Carthago.Services.ProtocolIntelligence
{
    /// <summary>
    /// RFC 8855 BFCP COMMON-HEADER envelope only. The caller must attest
    /// a complete TCP message or UDP datagram, a negotiated BFCP session,
    /// and trusted plaintext (e.g. an authorized endpoint/proxy after TLS/DTLS).
    /// Does not decode attributes, reassemble fragments, authenticate peers,
    /// determine floor-control outcomes, or retain conference/user IDs.
    /// ISOLATED: no capture registration, journal or alert integration.
    /// </summary>
    public static class BfcpHeaderInspector
    {
        private const int HeaderLength = 12;
        private const int FragmentHeaderLength = 4;
        private const int MaximumMessageLength = 4096;

        public static bool TryInspect(ReadOnlySpan<byte> message,
            BfcpTransportKind transport,
            bool verifiedCompleteTransportUnit,
            bool verifiedNegotiatedBfcpSession,
            bool verifiedPlaintextSource,
            out BfcpHeaderObservation observation)
        {
            observation = default;
            if (!verifiedCompleteTransportUnit ||
                !verifiedNegotiatedBfcpSession ||
                !verifiedPlaintextSource ||
                message.Length is < HeaderLength or > MaximumMessageLength)
                return false;

            byte version = (byte)(message[0] >> 5);
            bool response = (message[0] & 0x10) != 0;
            bool fragmented = (message[0] & 0x08) != 0;
            // Reserved bits are sender-zero. Reject rather than infer from
            // ambiguous/untrusted bytes; this is an inspector, not a receiver.
            if ((message[0] & 0x07) != 0)
                return false;

            if (transport == BfcpTransportKind.ReliableTcp)
            {
                if (version != 1 || response || fragmented)
                    return false;
            }
            else if (transport == BfcpTransportKind.UnreliableUdp)
            {
                if (version != 2)
                    return false;
            }
            else
            {
                return false;
            }

            byte primitive = message[1];
            if (primitive is < 1 or > 17 ||
                (version == 1 && primitive > 13))
                return false;

            int payloadWords = BinaryPrimitives.ReadUInt16BigEndian(message.Slice(2, 2));
            int payloadBytes = payloadWords * 4;
            if (payloadBytes > MaximumMessageLength - HeaderLength)
                return false;

            int observedPayloadBytes;
            if (fragmented)
            {
                if (message.Length < HeaderLength + FragmentHeaderLength)
                    return false;

                int offsetWords = BinaryPrimitives.ReadUInt16BigEndian(message.Slice(12, 2));
                int fragmentWords = BinaryPrimitives.ReadUInt16BigEndian(message.Slice(14, 2));
                if (fragmentWords == 0 ||
                    offsetWords + fragmentWords > payloadWords ||
                    message.Length != HeaderLength + FragmentHeaderLength + fragmentWords * 4)
                    return false;
                observedPayloadBytes = fragmentWords * 4;
            }
            else
            {
                if (message.Length != HeaderLength + payloadBytes)
                    return false;
                observedPayloadBytes = payloadBytes;
            }

            observation = new BfcpHeaderObservation(
                version, primitive, response, fragmented,
                payloadBytes, observedPayloadBytes);
            return true;
        }
    }

    /// <summary>
    /// Unauthenticated structural metadata only. No conference ID,
    /// transaction ID, user ID, attribute, credential or payload is retained.
    /// A primitive is not proof of authorization, floor ownership or abuse.
    /// </summary>
    public readonly record struct BfcpHeaderObservation(
        byte Version, byte Primitive, bool IsResponseUnverified,
        bool IsFragment, int DeclaredPayloadBytes, int ObservedPayloadBytes);

    public enum BfcpTransportKind
    {
        ReliableTcp = 1,
        UnreliableUdp = 2
    }
}
