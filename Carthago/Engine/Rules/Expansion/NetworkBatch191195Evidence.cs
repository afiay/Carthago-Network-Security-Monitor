// SPDX-License-Identifier: MIT
using System;
using System.Globalization;
using System.Linq;
using System.Net;
using Carthago.Models;

namespace Carthago.Engine.Rules.Expansion
{
    // Candidate request/handshake attribution only. Do not claim decoded DoH/DoT
    // DNS payload or resolver approval from arbitrary packet Info text.
    internal static class NetworkBatch191195Evidence
    {
        private static bool ExternalIp(string? address)
        {
            if (!IPAddress.TryParse(address, out var ip) || IPAddress.IsLoopback(ip)
                || ip.IsIPv6LinkLocal || ip.IsIPv6Multicast || ip.IsIPv6SiteLocal)
                return false;
            var b = ip.GetAddressBytes();
            if (ip.AddressFamily == System.Net.Sockets.AddressFamily.InterNetworkV6)
                return (b[0] & 0xfe) != 0xfc; // IPv6 unique-local fc00::/7
            if (b[0] is 0 or 10 or 127 || b[0] >= 224
                || b[0] == 169 && b[1] == 254
                || b[0] == 172 && b[1] is >= 16 and <= 31
                || b[0] == 192 && b[1] == 168
                || b[0] == 100 && b[1] is >= 64 and <= 127
                || b[0] == 198 && b[1] is 18 or 19)
                return false;
            return true;
        }

        internal static bool ValidPunycode(string label)
        {
            if (!label.StartsWith("xn--", StringComparison.OrdinalIgnoreCase)
                || label.Length is < 8 or > 63) return false;
            try
            {
                var unicode = new IdnMapping().GetUnicode(label);
                return unicode.Any(c => c > 127) && !unicode.Equals(label, StringComparison.OrdinalIgnoreCase);
            }
            catch (ArgumentException) { return false; }
        }

        // GET dns= must decode to a DNS query with a complete first question.
        // This checks observable request bytes, not an encrypted DNS response.
        private static bool ValidDnsWireQuestion(string encoded)
        {
            try
            {
                var raw = encoded.Replace('-', '+').Replace('_', '/');
                raw = raw.PadRight((raw.Length + 3) / 4 * 4, '=');
                var bytes = Convert.FromBase64String(raw);
                if (bytes.Length is < 18 or > 512 || (bytes[2] & 0x80) != 0
                    || bytes[4] != 0 || bytes[5] != 1) return false;
                var index = 12;
                var labels = 0;
                while (index < bytes.Length)
                {
                    var length = bytes[index++];
                    if (length == 0) break;
                    if (length > 63 || index + length > bytes.Length) return false;
                    index += length; labels++;
                    if (labels > 20) return false;
                }
                return labels > 0 && index + 4 <= bytes.Length
                    && (bytes[index] != 0 || bytes[index + 1] != 0)
                    && bytes[index + 2] == 0 && bytes[index + 3] == 1;
            }
            catch (FormatException) { return false; }
        }

        internal static bool Doh(TrafficRecord r, out string host, out string method)
        {
            host = "";
            method = "";
            if (!NetworkBatch166170Evidence.Http(r) || r.IsQuic || !r.IsTcp || r.IsUdp
                || string.IsNullOrWhiteSpace(r.HttpHost)
                || !ExternalIp(r.Destination))
                return false;
            host = r.HttpHost!.TrimEnd('.').ToLowerInvariant();
            if (host.Length is < 4 or > 253 || host.Contains('/') || host.Contains('@')
                || host.EndsWith(".local", StringComparison.OrdinalIgnoreCase)
                || host.EndsWith(".internal", StringComparison.OrdinalIgnoreCase))
                return false;
            if (!NetworkBatch156165Evidence.UriOf(r, out var uri))
                return false;
            var path = uri.AbsolutePath;
            var standard = path.Equals("/dns-query", StringComparison.OrdinalIgnoreCase);
            if (string.Equals(r.HttpMethod, "GET", StringComparison.OrdinalIgnoreCase))
            {
                if (!standard || !NetworkBatch166170Evidence.Header(r, "Accept", out var accept)
                    || !accept.Equals("application/dns-message", StringComparison.OrdinalIgnoreCase))
                    return false;
                foreach (var pair in uri.Query.TrimStart('?').Split('&', StringSplitOptions.RemoveEmptyEntries))
                {
                    var p = pair.Split('=', 2);
                    if (p.Length != 2 || !p[0].Equals("dns", StringComparison.OrdinalIgnoreCase)
                        || p[1].Length is < 16 or > 2048
                        || !ValidDnsWireQuestion(p[1]))
                        continue;
                    method = "GET"; return true;
                }
                return false;
            }
            if (string.Equals(r.HttpMethod, "POST", StringComparison.OrdinalIgnoreCase)
                && NetworkBatch166170Evidence.Header(r, "Content-Type", out var contentType)
                && contentType.Equals("application/dns-message", StringComparison.OrdinalIgnoreCase)
                && NetworkBatch166170Evidence.Header(r, "Content-Length", out var length)
                && long.TryParse(length, NumberStyles.None, CultureInfo.InvariantCulture, out var bytes)
                && bytes is >= 12 and <= 65535)
            {
                method = "POST"; return true;
            }
            return false;
        }

        internal static bool Dot(TrafficRecord r, out string host)
        {
            host = "";
            if (r.Id == Guid.Empty || !r.IsTcp || r.IsUdp || r.IsQuic
                || r.DestinationPort != 853 || r.SourcePort == 853
                || !ExternalIp(r.Destination)
                || !string.IsNullOrWhiteSpace(r.HttpMethod)
                || !string.IsNullOrWhiteSpace(r.HttpHost)
                || !string.IsNullOrWhiteSpace(r.HttpUri)
                || !string.IsNullOrWhiteSpace(r.HttpRequestHeaders)
                || !string.IsNullOrWhiteSpace(r.DnsQname)
                || !new[] { "TCP", "TLS", "SSL" }.Contains(r.Protocol, StringComparer.OrdinalIgnoreCase)
                || r.ApplicationProtocol != null && !new[] { "TLS", "DNS-over-TLS", "DoT" }.Contains(r.ApplicationProtocol, StringComparer.OrdinalIgnoreCase)
                || r.ApplicationService != null && !new[] { "TLS", "DNS-over-TLS", "DoT" }.Contains(r.ApplicationService, StringComparer.OrdinalIgnoreCase)
                || string.IsNullOrWhiteSpace(r.Sni) || string.IsNullOrWhiteSpace(r.TlsVersion)
                || r.Alpn is "h2" or "http/1.1" or "http/1.0")
                return false;
            host = r.Sni!.TrimEnd('.').ToLowerInvariant();
            if (host.Length is < 4 or > 253 || host.Contains('@') || host.Contains('/')
                || host.EndsWith(".local", StringComparison.OrdinalIgnoreCase)
                || host.EndsWith(".internal", StringComparison.OrdinalIgnoreCase)
                || !(r.TlsVersion!.Contains("1.2", StringComparison.OrdinalIgnoreCase)
                    || r.TlsVersion.Contains("1.3", StringComparison.OrdinalIgnoreCase)))
                return false;
            return true;
        }
    }
}
