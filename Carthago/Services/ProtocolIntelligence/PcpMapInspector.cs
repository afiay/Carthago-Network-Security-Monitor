// SPDX-License-Identifier: MIT
using System;
using System.Buffers.Binary;

namespace Carthago.Services.ProtocolIntelligence
{
    /// <summary>
    /// RFC 6887 PCP v2 MAP request/response envelope inspector.
    /// The caller must independently attest complete UDP framing, an unfragmented
    /// IP packet, a PCP endpoint and plaintext/source provenance.
    /// A response result code is untrusted wire data, not a verified NAT change.
    /// ISOLATED — NOT LIVE-CAPTURE INTEGRATED.
    /// </summary>
    public static class PcpMapInspector
    {
        private const int MapEnvelopeLength = 60;
        private const int MaximumDatagramLength = 1100;
        private const int MaximumOptions = 32;

        public static bool TryInspect(
            ReadOnlySpan<byte> udpPayload,
            bool verifiedCompleteUdpDatagram,
            bool verifiedUnfragmentedIpPacket,
            bool verifiedPcpEndpoint,
            bool verifiedPlaintextSource,
            out PcpMapObservation observation)
        {
            observation = default;
            if (!verifiedCompleteUdpDatagram || !verifiedUnfragmentedIpPacket ||
                !verifiedPcpEndpoint || !verifiedPlaintextSource ||
                udpPayload.Length < MapEnvelopeLength ||
                udpPayload.Length > MaximumDatagramLength ||
                (udpPayload.Length & 3) != 0 ||
                udpPayload[0] != 2 || (udpPayload[1] & 0x7f) != 1)
                return false;

            bool isResponse = (udpPayload[1] & 0x80) != 0;
            int optionCount = 0;
            bool hasThirdParty = false;
            bool hasFilter = false;
            bool hasPreferFailure = false;

            // RFC 6887: 24-byte common header + 36-byte MAP body.
            // Reserved bytes are ignored on reception, as the RFC requires.
            int offset = MapEnvelopeLength;
            while (offset < udpPayload.Length)
            {
                if (++optionCount > MaximumOptions ||
                    udpPayload.Length - offset < 4)
                    return false;

                byte code = udpPayload[offset];
                int valueLength = BinaryPrimitives.ReadUInt16BigEndian(
                    udpPayload.Slice(offset + 2, 2));
                int remaining = udpPayload.Length - offset - 4;
                int paddedLength = (valueLength + 3) & ~3;
                if (paddedLength > remaining)
                    return false;

                // RFC 6887 mandates zero padding, distinct from reserved bits.
                for (int i = valueLength; i < paddedLength; i++)
                    if (udpPayload[offset + 4 + i] != 0)
                        return false;

                switch (code)
                {
                    case 1: // THIRD_PARTY
                        if (valueLength != 16 || hasThirdParty) return false;
                        hasThirdParty = true;
                        break;
                    case 2: // PREFER_FAILURE
                        if (valueLength != 0 || hasPreferFailure) return false;
                        hasPreferFailure = true;
                        break;
                    case 3: // FILTER
                        if (valueLength != 20) return false;
                        hasFilter = true;
                        break;
                    default:
                        // Unknown mandatory options have unverified semantics.
                        // Unknown optional options are skipped, never decoded.
                        if ((code & 0x80) == 0) return false;
                        break;
                }

                offset += 4 + paddedLength;
            }

            observation = new PcpMapObservation(
                IsResponseUnverified: isResponse,
                ResultCodeUnverified: isResponse ? udpPayload[3] : (byte)0,
                LifetimeSecondsUnverified: BinaryPrimitives.ReadUInt32BigEndian(
                    udpPayload.Slice(4, 4)),
                TransportProtocolUnverified: udpPayload[36],
                InternalPortUnverified: BinaryPrimitives.ReadUInt16BigEndian(
                    udpPayload.Slice(40, 2)),
                ExternalPortUnverified: BinaryPrimitives.ReadUInt16BigEndian(
                    udpPayload.Slice(42, 2)),
                HasThirdPartyOptionUnverified: hasThirdParty,
                HasFilterOptionUnverified: hasFilter,
                HasPreferFailureOptionUnverified: hasPreferFailure,
                OptionCount: optionCount);
            return true;
        }
    }

    /// <summary>
    /// Untrusted MAP envelope metadata only. No nonce, IP address, option
    /// contents, credential, authorization, device state or actual mapping
    /// outcome is retained. No journal, alert, sink or UI side effects.
    /// </summary>
    public readonly record struct PcpMapObservation(
        bool IsResponseUnverified,
        byte ResultCodeUnverified,
        uint LifetimeSecondsUnverified,
        byte TransportProtocolUnverified,
        ushort InternalPortUnverified,
        ushort ExternalPortUnverified,
        bool HasThirdPartyOptionUnverified,
        bool HasFilterOptionUnverified,
        bool HasPreferFailureOptionUnverified,
        int OptionCount);
}
