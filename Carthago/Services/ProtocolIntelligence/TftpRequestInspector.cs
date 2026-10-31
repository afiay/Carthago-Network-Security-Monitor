// SPDX-License-Identifier: MIT
using System;

namespace Carthago.Services.ProtocolIntelligence
{
    /// <summary>
    /// Isolated RFC 1350 / RFC 2347 TFTP initial RRQ/WRQ envelope inspector.
    /// Requires a caller-attested complete UDP payload sent to port 69.
    /// No transfer-ID tracking, data/ACK/OACK classification, file access,
    /// transfer success, authentication, or device-compromise assertion.
    /// Filenames, option names and option values are never returned.
    /// </summary>
    public static class TftpRequestInspector
    {
        private const int MaximumRequestLength = 1024;
        private const int MaximumOptions = 8;

        public static bool TryInspect(ReadOnlySpan<byte> datagram,
            ushort sourcePort, ushort destinationPort,
            bool verifiedCompleteUdpPayload, out TftpRequestObservation observation)
        {
            observation = default;
            if (!verifiedCompleteUdpPayload || sourcePort == 69 || destinationPort != 69
                || datagram.Length is < 10 or > MaximumRequestLength
                || datagram[0] != 0 || datagram[1] is not (1 or 2))
                return false;

            int offset = 2;
            if (!TryReadAsciiToken(datagram, ref offset, 255, allowSpace: true, out _, out _)
                || !TryReadAsciiToken(datagram, ref offset, 16, allowSpace: false,
                    out int modeOffset, out int modeLength))
                return false;

            var mode = datagram.Slice(modeOffset, modeLength);
            TftpTransferMode transferMode;
            if (AsciiEqualsIgnoreCase(mode, "octet"))
                transferMode = TftpTransferMode.Octet;
            else if (AsciiEqualsIgnoreCase(mode, "netascii"))
                transferMode = TftpTransferMode.Netascii;
            else if (AsciiEqualsIgnoreCase(mode, "mail"))
                transferMode = TftpTransferMode.Mail;
            else
                return false;

            // RFC 2347 request extensions: complete, nonempty option/value pairs.
            // Only bounded framing is inspected; option semantics are not validated.
            Span<int> nameOffsets = stackalloc int[MaximumOptions];
            Span<int> nameLengths = stackalloc int[MaximumOptions];
            int optionCount = 0;
            while (offset < datagram.Length)
            {
                if (optionCount == MaximumOptions
                    || !TryReadAsciiToken(datagram, ref offset, 32, allowSpace: false,
                        out int nameOffset, out int nameLength)
                    || !TryReadAsciiToken(datagram, ref offset, 64, allowSpace: false,
                        out _, out _))
                    return false;

                var name = datagram.Slice(nameOffset, nameLength);
                for (int i = 0; i < optionCount; i++)
                {
                    if (AsciiEqualsIgnoreCase(name,
                        datagram.Slice(nameOffsets[i], nameLengths[i])))
                        return false; // Duplicate options are ambiguous.
                }
                nameOffsets[optionCount] = nameOffset;
                nameLengths[optionCount] = nameLength;
                optionCount++;
            }

            observation = new TftpRequestObservation(
                datagram[1] == 1 ? TftpRequestKind.Read : TftpRequestKind.Write,
                transferMode, optionCount, datagram.Length);
            return true;
        }

        private static bool TryReadAsciiToken(ReadOnlySpan<byte> data,
            ref int offset, int maximumLength, bool allowSpace,
            out int tokenOffset, out int tokenLength)
        {
            tokenOffset = offset;
            tokenLength = 0;
            if (offset >= data.Length)
                return false;

            int start = offset;
            while (offset < data.Length && data[offset] != 0)
            {
                byte value = data[offset];
                if (value < (allowSpace ? 0x20 : 0x21) || value > 0x7e
                    || offset - start >= maximumLength)
                    return false;
                offset++;
            }

            if (offset == data.Length || offset == start)
                return false;
            tokenLength = offset - start;
            offset++; // Skip the mandatory NUL terminator.
            return true;
        }

        private static bool AsciiEqualsIgnoreCase(ReadOnlySpan<byte> bytes, string expected)
        {
            if (bytes.Length != expected.Length)
                return false;
            for (int i = 0; i < bytes.Length; i++)
            {
                byte value = bytes[i];
                if (value is >= (byte)'A' and <= (byte)'Z')
                    value = (byte)(value + 32);
                if (value != expected[i])
                    return false;
            }
            return true;
        }

        private static bool AsciiEqualsIgnoreCase(ReadOnlySpan<byte> left, ReadOnlySpan<byte> right)
        {
            if (left.Length != right.Length)
                return false;
            for (int i = 0; i < left.Length; i++)
            {
                byte a = left[i], b = right[i];
                if (a is >= (byte)'A' and <= (byte)'Z') a = (byte)(a + 32);
                if (b is >= (byte)'A' and <= (byte)'Z') b = (byte)(b + 32);
                if (a != b) return false;
            }
            return true;
        }
    }

    public enum TftpRequestKind : byte { Read = 1, Write = 2 }

    public enum TftpTransferMode : byte { Octet = 1, Netascii = 2, Mail = 3 }

    public readonly record struct TftpRequestObservation(
        TftpRequestKind RequestKind, TftpTransferMode Mode,
        int OptionCount, int DatagramLength);
}
