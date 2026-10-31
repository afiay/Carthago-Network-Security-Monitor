// SPDX-License-Identifier: MIT
using System;
using System.Buffers.Binary;

namespace Carthago.Services.ProtocolIntelligence
{
    /// <summary>
    /// Conservative GigE Vision Control Protocol request-envelope inspector.
    /// Caller attests a complete UDP datagram, an independently identified
    /// GVCP control endpoint (normally UDP/3956), and plaintext provenance.
    /// No camera register, MAC, IP, request ID, payload, ACK, authentication,
    /// device state or successful configuration outcome is decoded/retained.
    /// ISOLATED — NOT LIVE-CAPTURE INTEGRATED.
    /// </summary>
    public static class GvcpCommandInspector
    {
        private const int HeaderLength = 8;
        private const int MaximumDatagramLength = 4096;
        private const byte RequestKey = 0x42;
        private const byte AcknowledgementRequested = 0x01;
        private const byte BroadcastRequest = 0x11;

        public static bool TryInspect(ReadOnlySpan<byte> udpPayload,
            bool verifiedCompleteUdpDatagram,
            bool verifiedGvcpControlEndpoint,
            bool verifiedPlaintextSource,
            out GvcpCommandObservation observation)
        {
            observation = default;
            if (!verifiedCompleteUdpDatagram || !verifiedGvcpControlEndpoint ||
                !verifiedPlaintextSource ||
                udpPayload.Length is < HeaderLength or > MaximumDatagramLength ||
                udpPayload[0] != RequestKey)
                return false;

            byte flags = udpPayload[1];
            if (flags != AcknowledgementRequested && flags != BroadcastRequest)
                return false;

            ushort command = BinaryPrimitives.ReadUInt16BigEndian(udpPayload.Slice(2, 2));
            int declaredLength = BinaryPrimitives.ReadUInt16BigEndian(udpPayload.Slice(4, 2));
            if (declaredLength != udpPayload.Length - HeaderLength)
                return false;

            // Deliberately narrow request-only recognition. ACK packets have
            // a different header and are not evidence of a successful command.
            GvcpCommandKind kind;
            switch (command)
            {
                case 0x0002 when declaredLength == 0:
                    kind = GvcpCommandKind.Discovery;
                    break;
                case 0x0004 when flags == BroadcastRequest && declaredLength == 56:
                    kind = GvcpCommandKind.ForceIp;
                    break;
                case 0x0080 when flags == AcknowledgementRequested && declaredLength == 4:
                    kind = GvcpCommandKind.ReadRegister;
                    break;
                case 0x0082 when flags == AcknowledgementRequested &&
                                 declaredLength >= 8 && declaredLength <= 1024 &&
                                 declaredLength % 8 == 0:
                    kind = GvcpCommandKind.WriteRegister;
                    break;
                default:
                    return false;
            }

            observation = new GvcpCommandObservation(
                kind, flags == BroadcastRequest, declaredLength,
                kind is GvcpCommandKind.ForceIp or GvcpCommandKind.WriteRegister);
            return true;
        }
    }

    /// <summary>
    /// Unauthenticated request-shape metadata, not a configuration outcome.
    /// Excludes request ID, register addresses/values, MAC, IP and raw bytes.
    /// </summary>
    public readonly record struct GvcpCommandObservation(
        GvcpCommandKind Command,
        bool IsBroadcastRequestUnverified,
        int DeclaredPayloadBytes,
        bool IsPotentialConfigurationAttemptUnverified);

    public enum GvcpCommandKind
    {
        Discovery = 1,
        ForceIp = 2,
        ReadRegister = 3,
        WriteRegister = 4
    }
}
