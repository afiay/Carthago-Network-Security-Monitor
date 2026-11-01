// SPDX-License-Identifier: MIT
using System;

namespace Carthago.Services.ProtocolIntelligence
{
    /// <summary>
    /// Source-only recognition of a complete plaintext BSD rsh/rcmd request.
    /// The caller must independently attest the TCP stream start, direction,
    /// complete request boundary, service binding, plaintext and provenance.
    /// No user names or commands are decoded, retained, logged or emitted.
    /// This does not prove successful authentication or command execution.
    /// ISOLATED — NOT LIVE-CAPTURE INTEGRATED.
    /// </summary>
    public static class RshRequestInspector
    {
        private const int MaximumRequestBytes = 2048;
        private const int MaximumUserBytes = 256; // Oracle rshd upper bound; legacy BSD may use 16.
        private const int MaximumCommandBytes = 1024;

        public static bool TryInspect(
            ReadOnlySpan<byte> request,
            int? clientSourcePort,
            int? serverDestinationPort,
            bool verifiedTcpStreamStart,
            bool verifiedClientDirection,
            bool verifiedCompleteRequest,
            bool verifiedPlaintext,
            bool verifiedRshServiceBinding,
            bool verifiedCaptureProvenance,
            out RshRequestObservation observation)
        {
            observation = default;
            if (!verifiedTcpStreamStart || !verifiedClientDirection ||
                !verifiedCompleteRequest || !verifiedPlaintext ||
                !verifiedRshServiceBinding || !verifiedCaptureProvenance ||
                !clientSourcePort.HasValue ||
                clientSourcePort.Value < 512 || clientSourcePort.Value > 1023 ||
                serverDestinationPort != 514 ||
                request.Length < 7 || request.Length > MaximumRequestBytes)
                return false;

            int cursor = 0;
            if (!TryField(request, ref cursor, 5, out var stderrPortBytes) ||
                !TrySecondaryPort(stderrPortBytes, out int stderrPort) ||
                !TryField(request, ref cursor, MaximumUserBytes, out var clientUser) ||
                clientUser.IsEmpty || !IsUserAscii(clientUser) ||
                !TryField(request, ref cursor, MaximumUserBytes, out var targetUser) ||
                targetUser.IsEmpty || !IsUserAscii(targetUser) ||
                !TryField(request, ref cursor, MaximumCommandBytes, out var command) ||
                command.IsEmpty || !IsCommandAscii(command) ||
                cursor != request.Length)
                return false;

            observation = new RshRequestObservation(stderrPort, true);
            return true;
        }

        private static bool TryField(ReadOnlySpan<byte> bytes, ref int cursor,
            int maximumLength, out ReadOnlySpan<byte> field)
        {
            field = default;
            if (cursor >= bytes.Length)
                return false;
            int terminator = bytes.Slice(cursor).IndexOf((byte)0);
            if (terminator < 0 || terminator > maximumLength)
                return false;
            field = bytes.Slice(cursor, terminator);
            cursor += terminator + 1;
            return true;
        }

        private static bool TrySecondaryPort(ReadOnlySpan<byte> bytes, out int port)
        {
            port = 0;
            if (bytes.IsEmpty || bytes.Length > 5)
                return false;
            foreach (byte digit in bytes)
            {
                if (digit < (byte)'0' || digit > (byte)'9')
                    return false;
                port = port * 10 + digit - (byte)'0';
                if (port > 1023)
                    return false;
            }
            return port == 0 || port >= 512;
        }

        private static bool IsUserAscii(ReadOnlySpan<byte> bytes)
        {
            foreach (byte value in bytes)
                if (value < 0x21 || value > 0x7e)
                    return false;
            return true;
        }

        private static bool IsCommandAscii(ReadOnlySpan<byte> bytes)
        {
            foreach (byte value in bytes)
                if (value != (byte)'\t' && (value < 0x20 || value > 0x7e))
                    return false;
            return true;
        }
    }

    /// <summary>Unverified request syntax only; no identities, command or execution result.</summary>
    public readonly record struct RshRequestObservation(
        int StandardErrorPort, bool HasCommandField);
}
