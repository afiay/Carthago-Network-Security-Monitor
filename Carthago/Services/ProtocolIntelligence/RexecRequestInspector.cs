// SPDX-License-Identifier: MIT
using System;

namespace Carthago.Services.ProtocolIntelligence
{
    /// <summary>
    /// Privacy-safe inspection of a complete, plaintext rexec client request.
    /// Caller must attest the start of the TCP stream, client direction, endpoint,
    /// complete request boundary, readable plaintext, and capture provenance.
    /// No credentials, usernames, commands or payload bytes are retained.
    /// ISOLATED — NOT LIVE-CAPTURE INTEGRATED.
    /// </summary>
    public static class RexecRequestInspector
    {
        private const int MaximumRequestBytes = 2048;
        private const int MaximumUsernameBytes = 128;
        private const int MaximumPasswordBytes = 256;
        private const int MaximumCommandBytes = 1024;

        public static bool TryInspect(
            ReadOnlySpan<byte> request,
            bool verifiedTcpConnectionStart,
            bool verifiedClientDirection,
            bool verifiedCompleteRequest,
            bool verifiedPlaintext,
            bool verifiedRexecEndpoint,
            bool verifiedCaptureProvenance,
            out RexecRequestObservation observation)
        {
            observation = default;
            if (!verifiedTcpConnectionStart || !verifiedClientDirection ||
                !verifiedCompleteRequest || !verifiedPlaintext ||
                !verifiedRexecEndpoint || !verifiedCaptureProvenance ||
                request.Length < 6 || request.Length > MaximumRequestBytes)
                return false;

            int cursor = 0;
            if (!TryField(request, ref cursor, 5, out var portBytes) ||
                !TryPort(portBytes, out int stderrPort) ||
                !TryField(request, ref cursor, MaximumUsernameBytes, out var username) ||
                username.IsEmpty || !IsVisibleAscii(username) ||
                !TryField(request, ref cursor, MaximumPasswordBytes, out _) ||
                !TryField(request, ref cursor, MaximumCommandBytes, out var command) ||
                command.IsEmpty || !IsCommandAscii(command) ||
                cursor != request.Length)
                return false;

            // Syntactic shape only. Credentials and command are never decoded,
            // copied, logged or included in the result. No execution outcome.
            observation = new RexecRequestObservation(stderrPort, true, true);
            return true;
        }

        private static bool TryField(ReadOnlySpan<byte> request, ref int cursor,
            int maximumLength, out ReadOnlySpan<byte> field)
        {
            field = default;
            if (cursor >= request.Length)
                return false;
            int terminator = request.Slice(cursor).IndexOf((byte)0);
            if (terminator < 0 || terminator > maximumLength)
                return false;
            field = request.Slice(cursor, terminator);
            cursor += terminator + 1;
            return true;
        }

        private static bool TryPort(ReadOnlySpan<byte> bytes, out int port)
        {
            port = 0;
            if (bytes.IsEmpty || bytes.Length > 5)
                return false;
            foreach (byte digit in bytes)
            {
                if (digit < (byte)'0' || digit > (byte)'9')
                    return false;
                port = port * 10 + digit - (byte)'0';
                if (port > 65535)
                    return false;
            }
            return true;
        }

        private static bool IsVisibleAscii(ReadOnlySpan<byte> bytes)
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

    /// <summary>Unverified request-shape metadata, not an authentication or execution result.</summary>
    public readonly record struct RexecRequestObservation(
        int StandardErrorPort, bool HasCredentialField, bool HasCommandField);
}
