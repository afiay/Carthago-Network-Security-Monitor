// SPDX-License-Identifier: MIT
using System;

namespace Carthago.Services.ProtocolIntelligence
{
    // Conservative single-segment bodyless GET subset; no credentials retained.
    internal static class HttpAuthenticationRequestInspector
    {
        internal static bool IsCompleteGet(ReadOnlySpan<byte> payload)
        {
            if (payload.Length is < 18 or > 4096) return false;
            int end = payload.IndexOf("\r\n\r\n"u8);
            if (end < 0 || end + 4 != payload.Length) return false;
            int first = payload.IndexOf("\r\n"u8);
            if (first < 14 || first > end) return false;
            var line = payload[..first];
            if (!line.StartsWith("GET /"u8) || !line.EndsWith(" HTTP/1.1"u8))
                return false;
            var target = line[4..^9];
            foreach (byte c in target)
                if (c <= 32 || c >= 127) return false;
            int offset = first + 2;
            bool host = false, length = false, authorization = false;
            while (offset < end)
            {
                int next = payload[offset..].IndexOf("\r\n"u8);
                if (next <= 0 || offset + next > end) return false;
                var field = payload.Slice(offset, next);
                int colon = field.IndexOf((byte)':');
                if (colon <= 0) return false;
                var name = field[..colon];
                foreach (byte c in name)
                    if (!((c >= 48 && c <= 57) || (c >= 65 && c <= 90) ||
                          (c >= 97 && c <= 122) || "!#$%&'*+-.^_`|~"u8.IndexOf(c) >= 0))
                        return false;
                var value = field[(colon + 1)..];
                foreach (byte c in value)
                    if ((c < 32 && c != 9) || c == 127) return false;
                while (!value.IsEmpty && (value[0] == 32 || value[0] == 9)) value = value[1..];
                while (!value.IsEmpty && (value[^1] == 32 || value[^1] == 9)) value = value[..^1];
                if (Equal(name, "Transfer-Encoding"u8)) return false;
                if (Equal(name, "Content-Length"u8))
                {
                    if (length || !value.SequenceEqual("0"u8)) return false;
                    length = true;
                }
                if (Equal(name, "Host"u8))
                {
                    if (host || value.IsEmpty) return false;
                    foreach (byte c in value)
                        if (c <= 32 || c >= 127) return false;
                    host = true;
                }
                if (Equal(name, "Authorization"u8))
                {
                    if (authorization || value.IsEmpty) return false;
                    authorization = true;
                }
                offset += next + 2;
            }
            return host;
        }

        private static bool Equal(ReadOnlySpan<byte> a, ReadOnlySpan<byte> b)
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
