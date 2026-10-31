// SPDX-License-Identifier: MIT
using System;
using System.Buffers.Binary;

namespace Carthago.Services.ProtocolIntelligence
{
    // Source-only, stateless IGRP v1 envelope inspector. No PacketHandler registration.
    // The caller must attest a complete IPv4 protocol-9 payload from a trusted producer.
    // No route addresses, metrics, identities, payload bytes or alerts are retained.
    internal readonly record struct IgrpObservation(
        byte Opcode,
        byte Edition,
        ushort AutonomousSystem,
        ushort InteriorRoutes,
        ushort SystemRoutes,
        ushort ExteriorRoutes)
    {
        internal int TotalRoutes => InteriorRoutes + SystemRoutes + ExteriorRoutes;
        internal bool IsRequest => Opcode == 2;
    }

    internal static class IgrpPacketInspector
    {
        private const int HeaderLength = 12;
        private const int RouteLength = 14;
        private const int MaximumRoutes = 104;
        private const int MaximumLength = HeaderLength + RouteLength * MaximumRoutes;

        internal static bool TryInspect(
            ReadOnlySpan<byte> ipv4Payload,
            byte ipProtocol,
            bool completeIpv4Datagram,
            bool trustedIpv4Producer,
            out IgrpObservation observation)
        {
            observation = default;
            if (ipProtocol != 9 || !completeIpv4Datagram || !trustedIpv4Producer
                || ipv4Payload.Length < HeaderLength || ipv4Payload.Length > MaximumLength
                || (ipv4Payload.Length & 1) != 0)
                return false;

            byte version = (byte)(ipv4Payload[0] >> 4);
            byte opcode = (byte)(ipv4Payload[0] & 0x0f);
            if (version != 1 || opcode is not (1 or 2))
                return false;

            byte edition = ipv4Payload[1];
            ushort autonomousSystem = BinaryPrimitives.ReadUInt16BigEndian(ipv4Payload.Slice(2, 2));
            ushort interior = BinaryPrimitives.ReadUInt16BigEndian(ipv4Payload.Slice(4, 2));
            ushort system = BinaryPrimitives.ReadUInt16BigEndian(ipv4Payload.Slice(6, 2));
            ushort exterior = BinaryPrimitives.ReadUInt16BigEndian(ipv4Payload.Slice(8, 2));
            int totalRoutes = (int)interior + system + exterior;

            if (opcode == 2)
            {
                // Cisco IGRP requests carry only the header. Other fields are zero.
                if (ipv4Payload.Length != HeaderLength || edition != 0 || totalRoutes != 0)
                    return false;
            }
            else if (totalRoutes is < 1 or > MaximumRoutes
                     || ipv4Payload.Length != HeaderLength + RouteLength * totalRoutes)
            {
                return false;
            }

            // The IGRP checksum covers its complete header and route data, not
            // an IPv4 pseudo-header. Valid one's-complement sum equals 0xffff.
            uint sum = 0;
            for (int i = 0; i < ipv4Payload.Length; i += 2)
            {
                sum += BinaryPrimitives.ReadUInt16BigEndian(ipv4Payload.Slice(i, 2));
                sum = (sum & 0xffff) + (sum >> 16);
            }
            sum = (sum & 0xffff) + (sum >> 16);
            if (sum != 0xffff)
                return false;

            observation = new IgrpObservation(opcode, edition, autonomousSystem,
                interior, system, exterior);
            return true;
        }
    }
}
