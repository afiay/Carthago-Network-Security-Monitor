// SPDX-License-Identifier: MIT
using System;
using System.Buffers.Binary;

namespace Carthago.Services.ProtocolIntelligence
{
    /// <summary>
    /// Bounded source-only RTP/RTCP v2 UDP envelope inspectors (RFC 3550).
    /// Caller must attest a complete plaintext datagram and correct media context.
    /// No stream association, SRTP/SRTCP decryption, authentication, SSRC retention,
    /// codec parsing, quality measurement, journal or live registration.
    /// </summary>
    public static class RtpRtcpDatagramInspector
    {
        private const int MaximumDatagramLength = 8192;
        private const int MaximumCompoundPackets = 32;

        public static bool TryInspectRtp(ReadOnlySpan<byte> datagram,
            bool verifiedCompletePlaintextDatagram, out RtpEnvelopeObservation observation)
        {
            observation = default;
            if (!verifiedCompletePlaintextDatagram
                || datagram.Length is < 12 or > MaximumDatagramLength
                || (datagram[0] >> 6) != 2)
                return false;

            // Conservative RTP/RTCP multiplex discriminator (RFC 5761).
            // This rejects some valid RTP marker/payload combinations by design.
            if (datagram[1] is >= 200 and <= 207) return false;
            int csrcCount = datagram[0] & 0x0f;
            int headerEnd = 12 + 4 * csrcCount;
            if (headerEnd > datagram.Length) return false;
            bool extension = (datagram[0] & 0x10) != 0;
            bool padding = (datagram[0] & 0x20) != 0;
            if (extension)
            {
                if (datagram.Length - headerEnd < 4) return false;
                int extensionWords = BinaryPrimitives.ReadUInt16BigEndian(
                    datagram.Slice(headerEnd + 2, 2));
                int extensionBytes = 4 + 4 * extensionWords;
                if (extensionBytes > datagram.Length - headerEnd) return false;
                headerEnd += extensionBytes;
            }
            if (padding)
            {
                int padCount = datagram[^1];
                if (padCount == 0 || padCount > datagram.Length - headerEnd)
                    return false;
            }
            observation = new(datagram.Length, (byte)(datagram[1] & 0x7f),
                BinaryPrimitives.ReadUInt16BigEndian(datagram.Slice(2, 2)),
                (byte)csrcCount, extension, padding);
            return true;
        }

        public static bool TryInspectRtcp(ReadOnlySpan<byte> datagram,
            bool verifiedCompletePlaintextDatagram, out RtcpCompoundObservation observation)
        {
            observation = default;
            if (!verifiedCompletePlaintextDatagram
                || datagram.Length is < 8 or > MaximumDatagramLength)
                return false;

            int offset = 0;
            int packets = 0;
            byte firstType = 0;
            bool bye = false, feedback = false;
            while (offset < datagram.Length)
            {
                if (++packets > MaximumCompoundPackets || datagram.Length - offset < 4)
                    return false;
                var packet = datagram.Slice(offset);
                byte flags = packet[0];
                byte type = packet[1];
                if ((flags >> 6) != 2 || type is < 200 or > 207)
                    return false;
                if (packets == 1 && type is not (200 or 201))
                    return false;
                int reportCount = flags & 0x1f;
                int length = (BinaryPrimitives.ReadUInt16BigEndian(packet.Slice(2, 2)) + 1) * 4;
                if (length > packet.Length) return false;

                int minimumLength = type switch
                {
                    200 => 28 + 24 * reportCount, // Sender Report
                    201 => 8 + 24 * reportCount,  // Receiver Report
                    202 => 4 + 4 * reportCount,  // SDES, variable chunks not decoded
                    203 => 4 + 4 * reportCount,  // BYE, optional reason not decoded
                    204 => 12,                    // APP
                    205 or 206 => 12,             // RTPFB/PSFB
                    207 => 8,                     // XR
                    _ => int.MaxValue
                };
                if (length < minimumLength) return false;
                if ((flags & 0x20) != 0)
                {
                    // Padding is legal only on the final RTCP packet.
                    if (offset + length != datagram.Length
                        || packet[length - 1] == 0
                        || packet[length - 1] > length - minimumLength)
                        return false;
                }
                if (packets == 1) firstType = type;
                bye |= type == 203;
                feedback |= type is 205 or 206;
                offset += length;
            }
            observation = new(datagram.Length, (byte)packets, firstType, bye, feedback);
            return true;
        }
    }

    public readonly record struct RtpEnvelopeObservation(
        int DatagramLength, byte PayloadType, ushort SequenceNumber,
        byte CsrcCount, bool HeaderExtensionPresent, bool PaddingPresent);

    public readonly record struct RtcpCompoundObservation(
        int DatagramLength, byte PacketCount, byte FirstPacketType,
        bool HasBye, bool HasFeedback);
}
