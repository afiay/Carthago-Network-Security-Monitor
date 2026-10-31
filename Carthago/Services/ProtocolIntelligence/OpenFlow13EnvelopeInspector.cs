// SPDX-License-Identifier: MIT
using System;
using System.Buffers.Binary;

namespace Carthago.Services.ProtocolIntelligence
{
    /// <summary>
    /// Bounded OpenFlow 1.3 (wire version 0x04) message envelope only.
    /// Caller must attest one complete plaintext TCP message and controller/
    /// switch endpoint role. Does not validate message bodies, flow changes,
    /// switch acceptance, TLS, authentication, or transaction correlation.
    /// </summary>
    public static class OpenFlow13EnvelopeInspector
    {
        private const int HeaderLength = 8;
        private const int MaximumMessageLength = 4096;

        public static bool TryInspect(ReadOnlySpan<byte> message,
            bool verifiedCompletePlaintextMessage, out OpenFlow13EnvelopeObservation observation)
        {
            observation = default;
            if (!verifiedCompletePlaintextMessage ||
                message.Length is < HeaderLength or > MaximumMessageLength ||
                message[0] != 0x04)
                return false;

            byte type = message[1];
            int length = BinaryPrimitives.ReadUInt16BigEndian(message.Slice(2, 2));
            if (length != message.Length)
                return false;

            // Conservative subset of OpenFlow 1.3 message types; only the
            // common header and minimum envelope lengths are established.
            bool supported = type switch
            {
                0 or 2 or 3 => true,               // HELLO / ECHO
                1 => length >= 12,                 // ERROR
                5 or 7 or 20 or 21 => length == 8, // fixed-size requests
                14 => length >= 56,                // FLOW_MOD, body unexamined
                18 or 19 => length >= 16,          // multipart envelope
                _ => false
            };
            if (!supported)
                return false;

            observation = new OpenFlow13EnvelopeObservation(
                type, message.Length, type == 14);
            return true;
        }
    }

    public readonly record struct OpenFlow13EnvelopeObservation(
        byte MessageType, int MessageLength, bool ClaimedFlowModification);
}
