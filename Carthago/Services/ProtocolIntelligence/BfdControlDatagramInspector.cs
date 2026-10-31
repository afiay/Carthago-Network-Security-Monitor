// SPDX-License-Identifier: MIT
using System;
using System.Buffers.Binary;

namespace Carthago.Services.ProtocolIntelligence
{
    /// <summary>
    /// RFC 5880 BFD v1 Control datagram shape only. Requires a complete UDP
    /// datagram and a trusted link/interface and TTL/hop-limit provenance.
    /// Never authenticates keys, verifies timers, or infers link state.
    /// Authentication bytes, discriminators and timer values are not retained.
    /// </summary>
    public static class BfdControlDatagramInspector
    {
        private const int HeaderLength = 24;
        private const int MaximumDatagramLength = 64;

        public static bool TryInspect(ReadOnlySpan<byte> datagram,
            bool verifiedCompleteUdpDatagram, out BfdControlObservation observation)
        {
            observation = default;
            if (!verifiedCompleteUdpDatagram ||
                datagram.Length is < HeaderLength or > MaximumDatagramLength)
                return false;

            if ((datagram[0] >> 5) != 1 ||
                datagram[2] == 0 || datagram[3] != datagram.Length)
                return false;

            byte flags = datagram[1];
            byte state = (byte)(flags >> 6);
            bool authenticated = (flags & 0x04) != 0;
            if ((flags & 0x01) != 0 || (flags & 0x30) == 0x30)
                return false;

            uint myDiscriminator = BinaryPrimitives.ReadUInt32BigEndian(datagram.Slice(4, 4));
            uint yourDiscriminator = BinaryPrimitives.ReadUInt32BigEndian(datagram.Slice(8, 4));
            uint desiredTx = BinaryPrimitives.ReadUInt32BigEndian(datagram.Slice(12, 4));
            if (myDiscriminator == 0 || desiredTx == 0 ||
                (state is 2 or 3 && yourDiscriminator == 0))
                return false;

            byte authType = 0;
            if (!authenticated)
            {
                if (datagram.Length != HeaderLength)
                    return false;
            }
            else
            {
                if (datagram.Length < HeaderLength + 4)
                    return false;
                authType = datagram[HeaderLength];
                int authLength = datagram[HeaderLength + 1];
                if (authLength != datagram.Length - HeaderLength)
                    return false;
                bool supportedAuthShape = authType switch
                {
                    1 => authLength is >= 4 and <= 19,
                    2 or 3 => authLength == 24,
                    4 or 5 => authLength == 28,
                    _ => false
                };
                if (!supportedAuthShape)
                    return false;
            }

            observation = new BfdControlObservation(
                state, (byte)(datagram[0] & 0x1f), datagram[2],
                authenticated, authType, datagram.Length);
            return true;
        }
    }

    public readonly record struct BfdControlObservation(
        byte ClaimedState, byte Diagnostic, byte DetectMultiplier,
        bool AuthenticationPresentUnverified, byte AuthenticationType,
        int DatagramLength);
}
