// SPDX-License-Identifier: MIT
using System;
using System.Net;
using System.Text;

namespace Carthago.Services.ProtocolIntelligence
{
    /// <summary>Strict, bounded HTTP/1.1 CONNECT request framing prerequisite for R521.
    /// Caller attestations are not trusted provenance; this parser never emits detections.</summary>
    public static class HttpConnectRequestInspector
    {
        public static bool TryInspect(ReadOnlySpan<byte> bytes, bool completePlaintextRequest,
            out string authorityHost, out int authorityPort)
        {
            authorityHost = string.Empty;
            authorityPort = 0;
            if (!completePlaintextRequest || bytes.Length < 24 || bytes.Length > 8192)
                return false;
            for (int i = 0; i < bytes.Length; i++)
                if (bytes[i] == 0 || (bytes[i] < 32 && bytes[i] != 13 && bytes[i] != 10))
                    return false;
            var raw = Encoding.ASCII.GetString(bytes);
            if (!raw.EndsWith("\r\n\r\n", StringComparison.Ordinal))
                return false;
            var lines = raw.Split(new[] { "\r\n" }, StringSplitOptions.None);
            if (lines.Length < 4 || lines[^1].Length != 0 || lines[^2].Length != 0)
                return false;
            var first = lines[0];
            if (!first.StartsWith("CONNECT ", StringComparison.Ordinal)
                || !first.EndsWith(" HTTP/1.1", StringComparison.Ordinal))
                return false;
            var target = first.Substring(8, first.Length - 17);
            if (target.Length == 0 || target.Contains(' ') || target.Contains('@')
                || target.Contains('/') || target.Contains('#'))
                return false;
            string host;
            string portText;
            if (target[0] == '[')
            {
                var close = target.IndexOf(']');
                if (close < 2 || close + 1 >= target.Length || target[close + 1] != ':'
                    || !IPAddress.TryParse(target.Substring(1, close - 1), out var ip)
                    || ip.AddressFamily != System.Net.Sockets.AddressFamily.InterNetworkV6)
                    return false;
                host = target.Substring(0, close + 1);
                portText = target.Substring(close + 2);
            }
            else
            {
                var colon = target.LastIndexOf(':');
                if (colon < 1 || target.IndexOf(':') != colon)
                    return false;
                host = target.Substring(0, colon);
                portText = target.Substring(colon + 1);
                foreach (var c in host)
                    if (!(char.IsAsciiLetterOrDigit(c) || c == '.' || c == '-'))
                        return false;
            }
            if (!int.TryParse(portText, out var port) || port < 1 || port > 65535
                || portText != port.ToString(System.Globalization.CultureInfo.InvariantCulture))
                return false;
            var hostHeaders = 0;
            for (var i = 1; i < lines.Length - 2; i++)
            {
                var line = lines[i];
                if (line.Length == 0 || line[0] == ' ' || line[0] == '\t')
                    return false;
                var separator = line.IndexOf(':');
                if (separator < 1)
                    return false;
                if (line.Substring(0, separator).Equals("Host", StringComparison.OrdinalIgnoreCase))
                {
                    hostHeaders++;
                    if (!line.Substring(separator + 1).Trim().Equals(target, StringComparison.OrdinalIgnoreCase))
                        return false;
                }
                if (line.Substring(0, separator).Equals("Content-Length", StringComparison.OrdinalIgnoreCase)
                    || line.Substring(0, separator).Equals("Transfer-Encoding", StringComparison.OrdinalIgnoreCase))
                    return false;
            }
            if (hostHeaders != 1)
                return false;
            authorityHost = host;
            authorityPort = port;
            return true;
        }
    }
}
