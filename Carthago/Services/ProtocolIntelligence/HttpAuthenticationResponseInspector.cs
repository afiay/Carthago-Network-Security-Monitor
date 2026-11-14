// SPDX-License-Identifier: MIT
using System;

namespace Carthago.Services.ProtocolIntelligence
{
    // A deliberately narrow response framing primitive for future R118 correlation.
    // No flow association or authentication success is inferred here.
    internal static class HttpAuthenticationResponseInspector
    {
        internal static bool TryInspect(ReadOnlySpan<byte> payload, out int status)
        {
            status = 0;
            if (payload.Length is < 20 or > 4096) return false;
            int end = payload.IndexOf("\r\n\r\n"u8);
            if (end < 0) return false;
            int first = payload.IndexOf("\r\n"u8);
            if (first < 13 || first > end) return false;
            var line = payload[..first];
            if (!line.StartsWith("HTTP/1.1 "u8) && !line.StartsWith("HTTP/1.0 "u8))
                return false;
            if (line[12] != (byte)' ') return false;
            int code = line.Slice(9, 3).SequenceEqual("401"u8) ? 401 :
                line.Slice(9, 3).SequenceEqual("403"u8) ? 403 : 0;
            if (code == 0 || !ValidValue(line[13..])) return false;

            int length = -1;
            int offset = first + 2;
            while (offset < end)
            {
                int next = payload[offset..].IndexOf("\r\n"u8);
                if (next <= 0 || offset + next > end) return false;
                var field = payload.Slice(offset, next);
                int colon = field.IndexOf((byte)':');
                if (colon <= 0) return false;
                var name = field[..colon];
                foreach (byte c in name)
                    if (!IsToken(c)) return false;
                var value = field[(colon + 1)..];
                if (!ValidValue(value)) return false;
                if (EqualsAscii(name, "Transfer-Encoding"u8)) return false;
                if (EqualsAscii(name, "Content-Length"u8))
                {
                    if (length >= 0) return false;
                    while (!value.IsEmpty && (value[0] == 32 || value[0] == 9))
                        value = value[1..];
                    while (!value.IsEmpty && (value[^1] == 32 || value[^1] == 9))
                        value = value[..^1];
                    if (value.IsEmpty) return false;
                    length = 0;
                    foreach (byte c in value)
                    {
                        if (c < 48 || c > 57 || length > 4096) return false;
                        length = length * 10 + c - 48;
                    }
                }
                offset += next + 2;
            }
            // Explicit singleton length only; no close-delimited or chunked bodies.
            if (length < 0 || length != payload.Length - end - 4) return false;
            status = code;
            return true;
        }

        private static bool ValidValue(ReadOnlySpan<byte> value)
        {
            foreach (byte c in value)
                if ((c < 32 && c != 9) || c == 127) return false;
            return true;
        }

        private static bool IsToken(byte c) =>
            (c >= 48 && c <= 57) || (c >= 65 && c <= 90) ||
            (c >= 97 && c <= 122) || "!#$%&'*+-.^_`|~"u8.IndexOf(c) >= 0;

        private static bool EqualsAscii(ReadOnlySpan<byte> a, ReadOnlySpan<byte> b)
        {
            if (a.Length != b.Length) return false;
            for (int i = 0; i < a.Length; i++)
            {
                int x = a[i], y = b[i];
                if (x >= 65 && x <= 90) x += 32;
                if (y >= 65 && y <= 90) y += 32;
                if (x != y) return false;
            }
            return true;
        }
    }
}
