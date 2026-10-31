// SPDX-License-Identifier: MIT
using System;

namespace Carthago.Services.ProtocolIntelligence
{
    /// <summary>
    /// RFC 3488 IPv4 Router-port Group Management Protocol message shapes.
    /// Caller must attest a complete unfragmented IPv4 protocol-2 payload and
    /// trustworthy capture provenance; this method does not establish either.
    /// No runtime registration, switch-port state, authentication or alerts.
    /// ISOLATED — NOT LIVE-CAPTURE INTEGRATED.
    /// </summary>
    public static class RgmpMessageInspector
    {
        private static readonly byte[] Destination = { 224, 0, 0, 25 };

        public static bool TryInspect(
            ReadOnlySpan<byte> ipPayload,
            byte ipProtocol,
            byte timeToLive,
            ReadOnlySpan<byte> destinationIpv4,
            bool verifiedCompleteIpv4Payload,
            bool verifiedUnfragmentedIpv4Packet,
            bool verifiedCaptureSource,
            out RgmpObservation observation)
        {
            observation = default;
            if (!verifiedCompleteIpv4Payload || !verifiedUnfragmentedIpv4Packet ||
                !verifiedCaptureSource || ipProtocol != 2 || timeToLive != 1 ||
                destinationIpv4.Length != 4 ||
                !destinationIpv4.SequenceEqual(Destination) ||
                ipPayload.Length != 8)
                return false;

            byte messageType = ipPayload[0];
            if (messageType is < 0xfc or > 0xff)
                return false;

            // RFC 3488 §2.2: IGMP one's-complement checksum over the whole payload.
            uint sum = 0;
            for (int i = 0; i < 8; i += 2)
                sum += (uint)((ipPayload[i] << 8) | ipPayload[i + 1]);
            while ((sum >> 16) != 0)
                sum = (sum & 0xffff) + (sum >> 16);
            if (sum != 0xffff)
                return false;

            bool groupSpecific = messageType is 0xfc or 0xfd;
            bool hasZeroGroup = ipPayload[4] == 0 && ipPayload[5] == 0 &&
                ipPayload[6] == 0 && ipPayload[7] == 0;
            if (!groupSpecific && !hasZeroGroup)
                return false;
            if (groupSpecific && (ipPayload[4] < 224 || ipPayload[4] > 239))
                return false;

            // RFC 3488 §3.1 forbids routers from transmitting Join/Leave for
            // 224.0.0/24 and 224.0.1.39/.40. Preserve suspicious wire shapes
            // as metadata rather than pretending a switch accepted them.
            bool forbiddenGroup = groupSpecific && ipPayload[4] == 224 &&
                ipPayload[5] == 0 &&
                (ipPayload[6] == 0 ||
                 (ipPayload[6] == 1 && ipPayload[7] is 39 or 40));

            // RFC 3488 says receiver MUST ignore the reserved byte.
            observation = new RgmpObservation(
                (RgmpMessageKind)messageType,
                groupSpecific,
                forbiddenGroup,
                ipPayload[1] != 0);
            return true;
        }
    }

    public enum RgmpMessageKind : byte
    {
        Leave = 0xfc,
        Join = 0xfd,
        Bye = 0xfe,
        Hello = 0xff
    }

    /// <summary>
    /// Untrusted wire-shape metadata only. Group/source addresses and raw
    /// bytes are not retained. No evidence of actual forwarding changes.
    /// </summary>
    public readonly record struct RgmpObservation(
        RgmpMessageKind MessageKindUnverified,
        bool IsGroupSpecific,
        bool HasForbiddenGroupUnverified,
        bool ReservedByteNonZeroUnverified);
}
