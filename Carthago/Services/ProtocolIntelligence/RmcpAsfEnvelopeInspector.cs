// SPDX-License-Identifier: MIT
using System;
using System.Buffers.Binary;

namespace Carthago.Services.ProtocolIntelligence
{
    /// <summary>
    /// DMTF DSP0136 RMCP v1 / ASF-class envelope only (UDP/623).
    /// Requires one complete UDP payload and independently verified management
    /// endpoint provenance. RMCP+ security extensions (UDP/644), IPMI class 7,
    /// OEM classes, command authorization and device outcomes are NOT decoded.
    /// No network I/O, session tracking, credentials or identifiers are retained.
    /// </summary>
    public static class RmcpAsfEnvelopeInspector
    {
        private const int HeaderLength = 4;
        private const int AsfEnvelopeLength = 12;
        private const int MaximumDatagramLength = AsfEnvelopeLength + byte.MaxValue;
        private const uint AsfEnterpriseNumber = 4542;

        public static bool TryInspect(ReadOnlySpan<byte> datagram,
            ushort sourcePort, ushort destinationPort,
            bool verifiedCompleteUdpPayload, bool verifiedManagementEndpoint,
            out RmcpAsfObservation observation)
        {
            observation = default;
            if (!verifiedCompleteUdpPayload || !verifiedManagementEndpoint ||
                (sourcePort != 623 && destinationPort != 623) ||
                datagram.Length is < HeaderLength or > MaximumDatagramLength ||
                datagram[0] != 0x06 || datagram[1] != 0x00)
                return false;

            byte messageClass = datagram[3];
            if ((messageClass & 0x7f) != 0x06)
                return false; // ASF only; IPMI and OEM frames require other parsers.

            bool acknowledge = (messageClass & 0x80) != 0;
            if (acknowledge)
            {
                if (datagram.Length != HeaderLength || datagram[2] == 0xff)
                    return false; // ACK has no data; FF means no acknowledgement.
                observation = new RmcpAsfObservation(null, true, false, HeaderLength);
                return true;
            }

            if (datagram.Length < AsfEnvelopeLength ||
                BinaryPrimitives.ReadUInt32BigEndian(datagram.Slice(4, 4)) != AsfEnterpriseNumber ||
                datagram[10] != 0 ||
                datagram[11] != datagram.Length - AsfEnvelopeLength)
                return false;

            byte messageType = datagram[8];
            bool supported = messageType is
                0x10 or 0x11 or 0x12 or 0x13 or
                0x40 or 0x41 or 0x42 or
                0x80 or 0x81 or 0x82;
            if (!supported)
                return false; // Unknown/secure-session/OEM message types not claimed.

            observation = new RmcpAsfObservation(messageType, false,
                messageType is 0x10 or 0x11 or 0x12 or 0x13, datagram.Length);
            return true;
        }
    }

    /// <summary>
    /// Only structural, unauthenticated metadata. In particular the RMCP sequence,
    /// ASF message tag, enterprise data and payload are never returned.
    /// </summary>
    public readonly record struct RmcpAsfObservation(
        byte? MessageType, bool IsAcknowledge,
        bool IsPowerControlRequestUnverified, int DatagramLength);
}
