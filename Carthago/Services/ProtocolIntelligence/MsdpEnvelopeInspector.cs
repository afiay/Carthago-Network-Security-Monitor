// SPDX-License-Identifier: MIT
using System;
using System.Buffers.Binary;

namespace Carthago.Services.ProtocolIntelligence
{
    /// <summary>
    /// RFC 3618 MSDP KeepAlive or IPv4 Source-Active TLV shape only.
    /// Requires one caller-attested, reassembled plaintext TCP PDU, TCP/639
    /// endpoint and trusted capture provenance. No peering, route, multicast
    /// delivery, device state or exploit outcome is authenticated.
    /// ISOLATED — NOT LIVE-CAPTURE INTEGRATED.
    /// </summary>
    public static class MsdpEnvelopeInspector
    {
        private const int MaximumTlvBytes = 9192;

        public static bool TryInspect(
            ReadOnlySpan<byte> message,
            bool verifiedCompleteTcpPdu,
            bool verifiedPlaintext,
            bool verifiedCaptureProvenance,
            bool verifiedTcp639Endpoint,
            out MsdpEnvelopeObservation observation)
        {
            observation = default;
            if (!verifiedCompleteTcpPdu || !verifiedPlaintext ||
                !verifiedCaptureProvenance || !verifiedTcp639Endpoint ||
                message.Length < 3 || message.Length > MaximumTlvBytes ||
                BinaryPrimitives.ReadUInt16BigEndian(message.Slice(1, 2)) != message.Length)
                return false;

            if (message[0] == 4)
            {
                if (message.Length != 3) return false;
                observation = new MsdpEnvelopeObservation(false, 0, false);
                return true;
            }

            // Other TLVs (including reserved type 5 and traceroute 6/7) are
            // intentionally not decoded or treated as Source-Active.
            if (message[0] != 1 || message.Length < 20)
                return false;

            int entryCount = message[3];
            int controlLength = 8 + 12 * entryCount;
            if (entryCount == 0 || controlLength > message.Length)
                return false;

            for (int i = 0; i < entryCount; i++)
            {
                int offset = 8 + 12 * i;
                // RFC 3618 requires /32 source prefix; reserved bits must
                // be ignored by receivers rather than interpreted as flags.
                if (message[offset + 3] != 32 ||
                    message[offset + 4] < 224 || message[offset + 4] > 239)
                    return false;
            }

            int encapsulatedLength = message.Length - controlLength;
            if (encapsulatedLength > 0)
            {
                if (encapsulatedLength < 20 ||
                    (message[controlLength] >> 4) != 4)
                    return false;

                int ipHeaderLength = (message[controlLength] & 15) * 4;
                if (ipHeaderLength < 20 || ipHeaderLength > encapsulatedLength ||
                    BinaryPrimitives.ReadUInt16BigEndian(message.Slice(controlLength + 2, 2))
                        != encapsulatedLength)
                    return false;

                int lastEntry = controlLength - 12;
                // The encapsulated IP source/destination must match the last
                // advertised (S,G). Do not retain addresses or packet bytes.
                if (!message.Slice(controlLength + 12, 4)
                        .SequenceEqual(message.Slice(lastEntry + 8, 4)) ||
                    !message.Slice(controlLength + 16, 4)
                        .SequenceEqual(message.Slice(lastEntry + 4, 4)))
                    return false;
            }

            observation = new MsdpEnvelopeObservation(
                true, entryCount, encapsulatedLength != 0);
            return true;
        }
    }

    /// <summary>
    /// Untrusted, privacy-minimized message-shape counters only.
    /// Does not expose source/group/RP addresses or encapsulated traffic.
    /// </summary>
    public readonly record struct MsdpEnvelopeObservation(
        bool IsSourceActive,
        int AdvertisedSourceGroupCountUnverified,
        bool HasEncapsulatedIpv4Unverified);
}
