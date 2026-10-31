// SPDX-License-Identifier: MIT
using System;

namespace Carthago.Services.ProtocolIntelligence
{
    /// <summary>
    /// Isolated RFC 6143 RFB/VNC ProtocolVersion greeting inspector.
    /// Requires a complete, separately framed 12-byte plaintext greeting
    /// and caller-attested direction. This is not RDP, authentication,
    /// negotiated security, desktop activity or session-success evidence.
    /// </summary>
    public static class RfbVersionInspector
    {
        public static bool TryInspect(ReadOnlySpan<byte> greeting,
            ushort sourcePort, ushort destinationPort, bool serverToClient,
            bool verifiedCompleteVersionMessage, out RfbVersionObservation observation)
        {
            observation = default;
            int serverPort = serverToClient ? sourcePort : destinationPort;
            if (!verifiedCompleteVersionMessage || serverPort is < 5900 or > 5999
                || greeting.Length != 12)
                return false;

            if (greeting[0] != (byte)'R' || greeting[1] != (byte)'F'
                || greeting[2] != (byte)'B' || greeting[3] != (byte)' '
                || greeting[4] != (byte)'0' || greeting[5] != (byte)'0'
                || greeting[6] != (byte)'3' || greeting[7] != (byte)'.'
                || greeting[8] != (byte)'0' || greeting[9] != (byte)'0'
                || greeting[11] != (byte)'\n')
                return false;

            byte minorDigit = greeting[10];
            if (minorDigit != (byte)'3' && minorDigit != (byte)'7'
                && minorDigit != (byte)'8')
                return false; // Conservative published-version subset.

            observation = new RfbVersionObservation(3, minorDigit - (byte)'0', serverToClient);
            return true;
        }
    }

    public readonly record struct RfbVersionObservation(
        int MajorVersion, int MinorVersion, bool ServerToClient);
}
