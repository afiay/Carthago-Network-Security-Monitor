// SPDX-License-Identifier: MIT
using System;
using System.Text;

namespace Carthago.Services.ProtocolIntelligence
{
    // R501 prerequisite only: callers must supply a complete, trusted HTTP body and
    // independently authenticated upload outcome. This parser never raises an alert.
    internal static class MultipartFilenameEntropyInspector
    {
        internal static bool TryInspect(
            ReadOnlySpan<byte> body,
            string boundary,
            bool completePlaintextBody,
            out double entropyBitsPerCharacter)
        {
            entropyBitsPerCharacter = 0;
            if (!completePlaintextBody || body.Length == 0 || body.Length > 1024 * 1024 ||
                string.IsNullOrEmpty(boundary) || boundary.Length > 70)
                return false;
            foreach (char c in boundary)
                if (!(char.IsLetterOrDigit(c) || c == '-' || c == '_' || c == '.'))
                    return false;
            // Restrict inspection to ASCII header bytes. Never decode or retain file contents.
            var marker = Encoding.ASCII.GetBytes("--" + boundary + "\r\n");
            if (!body.StartsWith(marker)) return false;
            var headerEnd = body.Slice(marker.Length).IndexOf("\r\n\r\n"u8);
            if (headerEnd < 0 || headerEnd > 8192) return false;
            var header = body.Slice(marker.Length, headerEnd);
            foreach (byte b in header)
                if (b > 0x7e || (b < 0x20 && b != 0x0d && b != 0x0a))
                    return false;
            var headerText = Encoding.ASCII.GetString(header);
            var lines = headerText.Split(new[] { "\r\n" }, StringSplitOptions.None);
            if (lines.Length == 0 ||
                !lines[0].StartsWith("Content-Disposition: form-data; ", StringComparison.OrdinalIgnoreCase))
                return false;
            var filenameTag = "filename=\"";
            var pos = lines[0].IndexOf(filenameTag, StringComparison.OrdinalIgnoreCase);
            if (pos < 0 || lines[0].IndexOf(filenameTag, pos + filenameTag.Length, StringComparison.OrdinalIgnoreCase) >= 0)
                return false;
            pos += filenameTag.Length;
            var end = lines[0].IndexOf('"', pos);
            if (end < 0 || end - pos < 16 || end - pos > 128) return false;
            var filename = lines[0].Substring(pos, end - pos);
            if (filename.IndexOfAny(new[] { '/', '\\', '\r', '\n' }) >= 0) return false;
            // Entropy applies to the basename, not extensions or multipart metadata.
            var dot = filename.LastIndexOf('.');
            var stem = dot > 0 ? filename.Substring(0, dot) : filename;
            if (stem.Length < 16) return false;
            var counts = new int[128];
            foreach (char c in stem)
            {
                if (c < 33 || c > 126) return false;
                counts[c]++;
            }
            foreach (int count in counts)
                if (count > 0)
                {
                    var p = (double)count / stem.Length;
                    entropyBitsPerCharacter -= p * Math.Log2(p);
                }
            return entropyBitsPerCharacter >= 3.5;
        }
    }
}
