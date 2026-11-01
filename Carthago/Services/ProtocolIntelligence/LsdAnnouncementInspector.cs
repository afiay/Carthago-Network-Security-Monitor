// SPDX-License-Identifier: MIT
using System;

namespace Carthago.Services.ProtocolIntelligence
{
    /// <summary>
    /// Bounded, stateless BitTorrent BEP 14 Local Service Discovery inspector.
    /// Requires independently attested complete UDP datagram, matching
    /// multicast destination, plaintext and trusted capture provenance.
    /// Never retains torrent infohashes, cookies, peers or raw headers.
    /// ISOLATED — NOT LIVE-CAPTURE INTEGRATED.
    /// </summary>
    public static class LsdAnnouncementInspector
    {
        private const int MaximumDatagramBytes = 1400;
        private const int MaximumHeaderLines = 32;
        private const int MaximumLineBytes = 256;
        private const int MaximumInfohashes = 16;
        private static ReadOnlySpan<byte> Preface => "BT-SEARCH * HTTP/1.1\r\n"u8;

        public static bool TryInspect(
            ReadOnlySpan<byte> datagram,
            int destinationPort,
            bool verifiedCompleteUdpDatagram,
            bool verifiedMatchingMulticastDestination,
            bool verifiedPlaintext,
            bool verifiedCaptureProvenance,
            out LsdAnnouncementObservation observation)
        {
            observation = default;
            if (!verifiedCompleteUdpDatagram || !verifiedMatchingMulticastDestination ||
                !verifiedPlaintext || !verifiedCaptureProvenance ||
                destinationPort != 6771 || datagram.Length > MaximumDatagramBytes ||
                !datagram.StartsWith(Preface))
                return false;

            int cursor = Preface.Length;
            bool hasHost = false, hasPort = false, terminated = false;
            int announcePort = 0, infohashCount = 0;
            for (int lineIndex = 0; lineIndex < MaximumHeaderLines; lineIndex++)
            {
                if (!TryReadLine(datagram, ref cursor, out var line))
                    return false;
                if (line.IsEmpty)
                {
                    terminated = true;
                    break;
                }

                int colon = line.IndexOf((byte)':');
                if (colon <= 0 || colon >= line.Length - 1)
                    return false;
                var name = line.Slice(0, colon);
                var value = line.Slice(colon + 1);
                if (value.Length > 0 && value[0] == (byte)' ')
                    value = value.Slice(1);
                if (value.IsEmpty)
                    return false;

                if (EqualAsciiIgnoreCase(name, "Host"u8))
                {
                    if (hasHost || !(value.SequenceEqual("239.192.152.143:6771"u8) ||
                        EqualAsciiIgnoreCase(value, "[ff15::efc0:988f]:6771"u8)))
                        return false;
                    hasHost = true;
                }
                else if (EqualAsciiIgnoreCase(name, "Port"u8))
                {
                    if (hasPort || !TryPort(value, out announcePort))
                        return false;
                    hasPort = true;
                }
                else if (EqualAsciiIgnoreCase(name, "Infohash"u8))
                {
                    if (infohashCount == MaximumInfohashes || value.Length != 40 ||
                        !IsHex(value))
                        return false;
                    infohashCount++;
                }
                else if (EqualAsciiIgnoreCase(name, "Cookie"u8))
                {
                    if (value.Length > 128 || !IsVisibleAscii(value))
                        return false;
                }
                else if (!IsVisibleAscii(name) || !IsVisibleAscii(value))
                    return false; // Unknown extension headers are allowed, but bounded.
            }

            // BEP 14 uses an HTTP-like header terminator. Permit one optional
            // additional blank line, but never accept arbitrary trailing bytes.
            if (!terminated || !hasHost || !hasPort || infohashCount == 0 ||
                !(cursor == datagram.Length ||
                  (cursor + 2 == datagram.Length &&
                   datagram[cursor] == (byte)'\r' &&
                   datagram[cursor + 1] == (byte)'\n')))
                return false;

            observation = new LsdAnnouncementObservation(announcePort, infohashCount);
            return true;
        }

        private static bool TryReadLine(ReadOnlySpan<byte> bytes,
            ref int cursor, out ReadOnlySpan<byte> line)
        {
            line = default;
            if (cursor >= bytes.Length)
                return false;
            int offset = bytes.Slice(cursor).IndexOf("\r\n"u8);
            if (offset < 0 || offset > MaximumLineBytes)
                return false;
            line = bytes.Slice(cursor, offset);
            cursor += offset + 2;
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
            return port != 0;
        }

        private static bool IsHex(ReadOnlySpan<byte> bytes)
        {
            foreach (byte value in bytes)
                if (!((value >= '0' && value <= '9') ||
                      (value >= 'a' && value <= 'f') ||
                      (value >= 'A' && value <= 'F')))
                    return false;
            return true;
        }

        private static bool IsVisibleAscii(ReadOnlySpan<byte> bytes)
        {
            foreach (byte value in bytes)
                if (value < 0x20 || value > 0x7e)
                    return false;
            return true;
        }

        private static bool EqualAsciiIgnoreCase(ReadOnlySpan<byte> actual,
            ReadOnlySpan<byte> expected)
        {
            if (actual.Length != expected.Length)
                return false;
            for (int i = 0; i < actual.Length; i++)
            {
                byte a = actual[i], b = expected[i];
                if (a >= 'A' && a <= 'Z') a = (byte)(a + 32);
                if (b >= 'A' && b <= 'Z') b = (byte)(b + 32);
                if (a != b) return false;
            }
            return true;
        }
    }

    /// <summary>Unverified syntactic metadata; not a verified peer or file transfer.</summary>
    public readonly record struct LsdAnnouncementObservation(
        int AnnouncedPort, int InfohashCount);
}
