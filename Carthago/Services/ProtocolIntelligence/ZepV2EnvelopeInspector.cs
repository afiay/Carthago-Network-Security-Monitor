// SPDX-License-Identifier: MIT
using System;
using System.Buffers.Binary;

namespace Carthago.Services.ProtocolIntelligence
{
    /// <summary>
    /// Stateless ZigBee Encapsulation Protocol v2 UDP envelope inspector.
    /// Requires a complete plaintext UDP datagram and independent endpoint,
    /// capture, and provenance attestations. This is not an IEEE 802.15.4
    /// frame decoder, Zigbee network decoder, FCS checker, authentication
    /// verifier, or evidence of a radio transmission or attack.
    /// ISOLATED — NOT LIVE-CAPTURE INTEGRATED.
    /// </summary>
    public static class ZepV2EnvelopeInspector
    {
        private const int DataHeaderBytes = 32;
        private const int AckHeaderBytes = 8;
        private const int MaximumFrameBytes = 127;
        private const int MaximumDatagramBytes = DataHeaderBytes + MaximumFrameBytes;

        public static bool TryInspect(
            ReadOnlySpan<byte> udpDatagram,
            bool verifiedCompleteUdpDatagram,
            bool verifiedZepEndpoint,
            bool verifiedPlaintext,
            bool verifiedCaptureProvenance,
            out ZepEnvelopeObservation observation)
        {
            observation = default;

            if (!verifiedCompleteUdpDatagram ||
                !verifiedZepEndpoint ||
                !verifiedPlaintext ||
                !verifiedCaptureProvenance ||
                udpDatagram.Length < AckHeaderBytes ||
                udpDatagram.Length > MaximumDatagramBytes ||
                udpDatagram[0] != (byte)'E' ||
                udpDatagram[1] != (byte)'X' ||
                udpDatagram[2] != 2)
                return false;

            switch (udpDatagram[3])
            {
                case (byte)ZepPacketKind.Acknowledgement:
                    if (udpDatagram.Length != AckHeaderBytes)
                        return false;

                    observation = new ZepEnvelopeObservation(
                        2, ZepPacketKind.Acknowledgement, null, 0,
                        BinaryPrimitives.ReadUInt32BigEndian(
                            udpDatagram.Slice(4, 4)));
                    return true;

                case (byte)ZepPacketKind.Data:
                    if (udpDatagram.Length <= DataHeaderBytes)
                        return false;

                    byte channel = udpDatagram[4];
                    byte crcLqiMode = udpDatagram[7];
                    byte declaredFrameLength = udpDatagram[31];

                    // This conservative inspector accepts only the standard
                    // 802.15.4 channel-number range and single-bit mode.
                    // Other variants remain unsupported, not malicious.
                    if (channel > 26 ||
                        crcLqiMode > 1 ||
                        declaredFrameLength == 0 ||
                        declaredFrameLength > MaximumFrameBytes ||
                        udpDatagram.Length != DataHeaderBytes + declaredFrameLength)
                        return false;

                    observation = new ZepEnvelopeObservation(
                        2, ZepPacketKind.Data, channel, declaredFrameLength,
                        BinaryPrimitives.ReadUInt32BigEndian(
                            udpDatagram.Slice(17, 4)));
                    return true;

                default:
                    return false;
            }
        }
    }

    public enum ZepPacketKind : byte
    {
        Data = 1,
        Acknowledgement = 2
    }

    /// <summary>
    /// Unauthenticated, untrusted ZEP header metadata. No device identity,
    /// raw frame, radio timestamp, location, MAC, key, or payload is retained.
    /// Sequence numbers are advisory, not proof of replay or injection.
    /// </summary>
    public readonly record struct ZepEnvelopeObservation(
        byte Version, ZepPacketKind PacketKind, byte? Channel,
        byte FrameLength, uint SequenceNumber);
}
