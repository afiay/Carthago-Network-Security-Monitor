// SPDX-License-Identifier: MIT
using System;
using System.Linq;
using System.Net;
using System.Text.RegularExpressions;
using Carthago.Models;
namespace Carthago.Engine.Rules.Expansion
{
    // Only wire-attributed fields. Packet Info is not request content or DNS evidence.
    internal static class NetworkBatch176180Evidence
    {
        internal static bool Http(TrafficRecord r) => NetworkBatch171175Evidence.Http(r);
        internal static bool HostAbuse(TrafficRecord r, out string reason)
        {
            reason = "";
            if (!Http(r) || !NetworkBatch166170Evidence.Header(r, "Host", out var host)
                || !host.Equals(r.HttpHost, StringComparison.OrdinalIgnoreCase)) return false;
            if (NetworkBatch166170Evidence.Header(r, "X-Forwarded-Host", out var forwarded))
            {
                if (!HostName(forwarded, out var target)) return false;
                if (!target.Equals(host, StringComparison.OrdinalIgnoreCase)
                    && (Internal(target) || !SameBoundary(host, target)))
                { reason = "forwarded_host_boundary_mismatch"; return true; }
            }
            foreach (var name in new[] { "X-Original-URL", "X-Rewrite-URL" })
            {
                if (!NetworkBatch166170Evidence.Header(r, name, out var value)) continue;
                if (value.Length > 256 || !value.StartsWith("/", StringComparison.Ordinal)
                    || value.StartsWith("//", StringComparison.Ordinal)) return false;
                var path = value.Split('?')[0];
                if (path.Equals("/.env", StringComparison.OrdinalIgnoreCase)
                    || path.StartsWith("/admin/", StringComparison.OrdinalIgnoreCase)
                    || path.StartsWith("/.git/", StringComparison.OrdinalIgnoreCase))
                { reason = "sensitive_rewrite_target"; return true; }
            }
            return false;
        }
        private static bool HostName(string value, out string host)
        {
            host = "";
            if (value.Length is < 2 or > 255 || value.Any(char.IsWhiteSpace)
                || value.Contains('/') || value.Contains('@') || value.Contains(',')
                || value.Contains('#') || value.Contains('?')) return false;
            if (!Uri.TryCreate("http://" + value, UriKind.Absolute, out var uri)
                || uri.Port != 80 || uri.UserInfo.Length != 0) return false;
            host = uri.Host;
            return host.Length > 1;
        }
        private static bool Internal(string host)
            => host.Equals("localhost", StringComparison.OrdinalIgnoreCase)
                || host.EndsWith(".internal", StringComparison.OrdinalIgnoreCase)
                || host.EndsWith(".local", StringComparison.OrdinalIgnoreCase)
                || host.EndsWith(".lan", StringComparison.OrdinalIgnoreCase)
                || IPAddress.TryParse(host, out var ip) && (IPAddress.IsLoopback(ip)
                    || ip.ToString().StartsWith("10.", StringComparison.Ordinal)
                    || ip.ToString().StartsWith("192.168.", StringComparison.Ordinal)
                    || ip.ToString().StartsWith("172.16.", StringComparison.Ordinal));
        private static bool SameBoundary(string a, string b)
        {
            var left = a.Split('.'); var right = b.Split('.');
            return left.Length >= 3 && right.Length >= 3
                && string.Equals(left[^1], right[^1], StringComparison.OrdinalIgnoreCase)
                && string.Equals(left[^2], right[^2], StringComparison.OrdinalIgnoreCase);
        }
        private static readonly Regex Filename = new(
            @"(?:^|;)\s*filename\s*=\s*(?:""(?<f>[^""\r\n]{1,180})""|(?<f>[^;\s\r\n]{1,180}))",
            RegexOptions.Compiled | RegexOptions.CultureInvariant | RegexOptions.IgnoreCase);
        internal static bool Upload(TrafficRecord r, out string filename)
        {
            filename = "";
            if (!Http(r) || r.HttpMethod is not ("POST" or "PUT" or "PATCH")
                || !NetworkBatch166170Evidence.Path(r, out var path)) return false;
            var uploadPath = path.Equals("/upload", StringComparison.OrdinalIgnoreCase)
                || path.StartsWith("/upload/", StringComparison.OrdinalIgnoreCase)
                || path.StartsWith("/api/upload", StringComparison.OrdinalIgnoreCase);
            if (!NetworkBatch166170Evidence.Header(r, "Content-Type", out var type)) return false;
            var multipart = type.StartsWith("multipart/form-data;", StringComparison.OrdinalIgnoreCase);
            if (!multipart && !(uploadPath && type.StartsWith("application/octet-stream", StringComparison.OrdinalIgnoreCase)))
                return false;
            if (NetworkBatch166170Evidence.Header(r, "Content-Disposition", out var disposition))
            {
                var match = Filename.Match(disposition);
                if (match.Success) filename = match.Groups["f"].Value;
            }
            if (filename.Length == 0 && uploadPath && r.HttpMethod.Equals("PUT", StringComparison.OrdinalIgnoreCase))
                filename = path.Split('/').LastOrDefault() ?? "";
            if (filename.Length == 0 && uploadPath && NetworkBatch156165Evidence.UriOf(r, out var uri))
            {
                foreach (var pair in uri.Query.TrimStart('?').Split('&', StringSplitOptions.RemoveEmptyEntries))
                {
                    var parts = pair.Split('=', 2);
                    if (parts.Length == 2 && parts[0].Equals("filename", StringComparison.OrdinalIgnoreCase))
                    { filename = Uri.UnescapeDataString(parts[1]); break; }
                }
            }
            if (filename.Length is < 5 or > 180 || filename.Contains('/') || filename.Contains('\\')
                || filename.Contains("..", StringComparison.Ordinal)) return false;
            return new[] { ".php", ".phtml", ".phar", ".jsp", ".jspx", ".asp", ".aspx", ".ashx", ".cfm", ".war", ".jar" }
                .Any(ext => filename.EndsWith(ext, StringComparison.OrdinalIgnoreCase));
        }
        internal static bool Dns(TrafficRecord r, out string query)
        {
            query = "";
            if (r.Id == Guid.Empty || r.DnsIsResponse || !string.IsNullOrWhiteSpace(r.DnsAnswers)
                || string.IsNullOrWhiteSpace(r.DnsQname) || string.IsNullOrWhiteSpace(r.DnsQtype)
                || r.DnsQname!.Length > 253 || r.IsQuic || r.IsTcp == r.IsUdp
                || !new[] { "DNS", "UDP", "TCP" }.Contains(r.Protocol, StringComparer.OrdinalIgnoreCase)
                || !(r.ApplicationProtocol?.Equals("DNS", StringComparison.OrdinalIgnoreCase) == true
                    || r.ApplicationService?.Equals("DNS", StringComparison.OrdinalIgnoreCase) == true
                    || r.Protocol?.Equals("DNS", StringComparison.OrdinalIgnoreCase) == true)
                || r.ApplicationProtocol is not (null or "DNS")
                || r.ApplicationService is not (null or "DNS")
                || r.HttpMethod != null || r.HttpUri != null || r.HttpRequestHeaders != null
                || r.DestinationPort != 53 || !IPAddress.TryParse(r.Source, out var src)
                || !IPAddress.TryParse(r.Destination, out var dst)
                || src.Equals(dst) || src.AddressFamily != dst.AddressFamily
                || r.IpVersion == 4 && src.AddressFamily != System.Net.Sockets.AddressFamily.InterNetwork
                || r.IpVersion == 6 && src.AddressFamily != System.Net.Sockets.AddressFamily.InterNetworkV6)
                return false;
            var normalized = r.DnsQname.TrimEnd('.').ToLowerInvariant();
            if (normalized.Length is < 3 or > 253 || normalized.Contains("..", StringComparison.Ordinal)
                || normalized.Split('.').Any(label => label.Length is < 1 or > 63
                    || label[0] == '-' || label[^1] == '-'
                    || label.Any(c => !(char.IsAsciiLetterOrDigit(c) || c == '-'))))
                return false;
            query = normalized;
            return true;
        }
    }
}
