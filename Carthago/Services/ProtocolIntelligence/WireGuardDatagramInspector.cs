// SPDX-License-Identifier: MIT
using System;

namespace Carthago.Services.ProtocolIntelligence
{
    /// <summary>
    /// WireGuard datagram-shape inspection at an attested complete UDP payload boundary.
    /// No MAC/AEAD verification, peer identity, replay decision, decryption, or live registration.
    /// Caller must provide a trusted datagram boundary; a port hint is not enough.
    /// </summary>
    public static class WireGuardDatagramInspector
    {
        private const int MaxDatagramBytes = 65_535;

        public static bool TryInspect(
            ReadOnlySpan<byte> datagram,
            bool verifiedUdpDatagramBoundary,
            out WireGuardDatagramObservation observation)
        {
            observation = default;
            if (!verifiedUdpDatagramBoundary || datagram.Length < 4
                || datagram.Length > MaxDatagramBytes
                || datagram[1] != 0 || datagram[2] != 0 || datagram[3] != 0)
                return false;

            WireGuardMessageKind kind;
            bool opaque;
            switch (datagram[0])
            {
                case 1 when datagram.Length == 148:
                    kind = WireGuardMessageKind.HandshakeInitiation;
                    opaque = true;
                    break;
                case 2 when datagram.Length == 92:
                    kind = WireGuardMessageKind.HandshakeResponse;
                    opaque = true;
                    break;
                case 3 when datagram.Length == 64:
                    kind = WireGuardMessageKind.CookieReply;
                    opaque = true;
                    break;
                case 4 when datagram.Length >= 32 && datagram.Length % 16 == 0:
                    kind = WireGuardMessageKind.TransportData;
                    opaque = true;
                    break;
                default:
                    return false;
            }

            // Deliberately omit sender/receiver indices, counters, keys and ciphertext.
            // Shape matching alone cannot authenticate the source or establish VPN success.
            observation = new WireGuardDatagramObservation(kind, datagram.Length, opaque);
            return true;
        }
    }

    public enum WireGuardMessageKind : byte
    {
        HandshakeInitiation = 1,
        HandshakeResponse = 2,
        CookieReply = 3,
        TransportData = 4
    }

    /// <summary>Untrusted wire-shape metadata, not an authenticated session or detection.</summary>
    public readonly record struct WireGuardDatagramObservation(
        WireGuardMessageKind Kind,
        int DatagramLength,
        bool ContainsOpaqueContent);
}
