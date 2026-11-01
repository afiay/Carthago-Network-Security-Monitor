// SPDX-License-Identifier: MIT
using System;

namespace Carthago.Services.ProtocolIntelligence
{
    /// <summary>
    /// Inspects a bounded prefix of a plaintext distcc v1/v2 client request.
    /// The caller must attest TCP connection start, client direction, readable
    /// plaintext, a known distcc endpoint and trusted capture provenance.
    /// The first ARGV body is only length-checked, never decoded or retained.
    /// No TCP reassembly, command inspection, authorization, server outcome,
    /// or exploit detection. ISOLATED — NOT LIVE-CAPTURE INTEGRATED.
    /// </summary>
    public static class DistccRequestPrefixInspector
    {
        private const int TokenBytes = 12;
        private const int MinimumPrefixBytes = TokenBytes * 3 + 1;
        private const int MaximumPrefixBytes = 4096;
        private const uint MaximumArgumentCount = 128;
        private const uint MaximumFirstArgumentBytes = 256;

        public static bool TryInspect(
            ReadOnlySpan<byte> tcpPrefix,
            bool verifiedTcpConnectionStart,
            bool verifiedClientToServer,
            bool verifiedReadablePlaintext,
            bool verifiedDistccEndpoint,
            bool verifiedCaptureProvenance,
            out DistccRequestPrefixObservation observation)
        {
            observation = default;
            if (!verifiedTcpConnectionStart || !verifiedClientToServer ||
                !verifiedReadablePlaintext || !verifiedDistccEndpoint ||
                !verifiedCaptureProvenance ||
                tcpPrefix.Length < MinimumPrefixBytes ||
                tcpPrefix.Length > MaximumPrefixBytes)
                return false;

            if (!TryReadToken(tcpPrefix, 0, "DIST"u8, out uint version) ||
                version is not (1 or 2) ||
                !TryReadToken(tcpPrefix, TokenBytes, "ARGC"u8, out uint count) ||
                count is 0 or > MaximumArgumentCount ||
                !TryReadToken(tcpPrefix, TokenBytes * 2, "ARGV"u8, out uint firstLength) ||
                firstLength is 0 or > MaximumFirstArgumentBytes ||
                firstLength > tcpPrefix.Length - TokenBytes * 3)
                return false;

            // This is a request-prefix shape, not evidence that the remaining
            // arguments/source, compiler execution or server response exist.
            observation = new DistccRequestPrefixObservation(
                (int)version, (int)count, (int)firstLength);
            return true;
        }

        private static bool TryReadToken(
            ReadOnlySpan<byte> bytes,
            int offset,
            ReadOnlySpan<byte> expectedTag,
            out uint value)
        {
            value = 0;
            if (offset < 0 || bytes.Length - offset < TokenBytes ||
                !bytes.Slice(offset, 4).SequenceEqual(expectedTag))
                return false;

            for (int i = offset + 4; i < offset + TokenBytes; i++)
            {
                byte digit = bytes[i];
                int hex = digit switch
                {
                    >= (byte)'0' and <= (byte)'9' => digit - '0',
                    >= (byte)'a' and <= (byte)'f' => digit - 'a' + 10,
                    >= (byte)'A' and <= (byte)'F' => digit - 'A' + 10,
                    _ => -1
                };
                if (hex < 0)
                    return false;
                value = (value << 4) | (uint)hex;
            }
            return true;
        }
    }

    /// <summary>
    /// Unverified syntactic metadata only. No compiler name, arguments,
    /// source, peer address, command, or authentication material is retained.
    /// </summary>
    public readonly record struct DistccRequestPrefixObservation(
        int ProtocolVersion,
        int DeclaredArgumentCount,
        int FirstArgumentLength);
}
