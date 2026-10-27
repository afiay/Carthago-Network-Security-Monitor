// SPDX-License-Identifier: MIT
using System;
using System.Globalization;
using System.Linq;
using System.Net;
using System.Text.RegularExpressions;
using Carthago.Models;
namespace Carthago.Engine.Rules.Expansion
{
    // R171-R175: attributed HTTP metadata only. Do not treat Info as body proof.
    internal static class NetworkBatch171175Evidence
    {
        internal static bool Http(TrafficRecord r) => NetworkBatch166170Evidence.Http(r);
        internal static bool Inbound(TrafficRecord r) => NetworkBatch166170Evidence.Inbound(r);

        internal static bool Soap(TrafficRecord r, out string action)
        {
            action = "";
            if (!Http(r) || !NetworkBatch166170Evidence.Header(r, "SOAPAction", out var raw)
                || !NetworkBatch166170Evidence.Header(r, "Content-Type", out var type)
                || !(type.StartsWith("text/xml", StringComparison.OrdinalIgnoreCase)
                    || type.StartsWith("application/soap+xml", StringComparison.OrdinalIgnoreCase)
                    || type.StartsWith("application/xml", StringComparison.OrdinalIgnoreCase)))
                return false;
            var value = raw.Trim().Trim('"', '\'');
            if (value.Length is < 6 or > 256
                || !Regex.IsMatch(value, @"(?:^|[/#])(?:executecommand|runshell|invokeruntime|processbuilder|jndilookup|uploadshell)$",
                    RegexOptions.IgnoreCase | RegexOptions.CultureInvariant))
                return false;
            action = value;
            return true;
        }

        internal static bool ScannerBrowser(TrafficRecord r)
        {
            if (!Http(r) || string.IsNullOrWhiteSpace(r.HttpUserAgent)
                || r.HttpUserAgent!.Length > 512) return false;
            if (NetworkBatch166170Evidence.Header(r, "User-Agent", out var observed)
                && !observed.Equals(r.HttpUserAgent, StringComparison.Ordinal))
                return false;
            var ua = r.HttpUserAgent;
            return Regex.IsMatch(ua, @"(?:^|[^a-z0-9])(?:sqlmap|nikto|nuclei|gobuster|dirbuster|ffuf|zgrab|masscan|nmap|wpscan|feroxbuster)(?:/|\s|;|\)|$)",
                    RegexOptions.IgnoreCase | RegexOptions.CultureInvariant)
                && Regex.IsMatch(ua, @"(?:Mozilla/5\.0|Chrome/[0-9]+|Firefox/[0-9]+|Edg/[0-9]+|Safari/[0-9]+)",
                    RegexOptions.IgnoreCase | RegexOptions.CultureInvariant);
        }

        internal static bool Cors(TrafficRecord r)
        {
            if (!Http(r) || !string.Equals(r.HttpMethod, "OPTIONS", StringComparison.OrdinalIgnoreCase)
                || !NetworkBatch166170Evidence.Path(r, out var path)) return false;
            var admin = path.Equals("/admin/api", StringComparison.OrdinalIgnoreCase)
                || path.StartsWith("/admin/api/", StringComparison.OrdinalIgnoreCase)
                || path.Equals("/api/admin", StringComparison.OrdinalIgnoreCase)
                || path.StartsWith("/api/admin/", StringComparison.OrdinalIgnoreCase)
                || path.Equals("/management/api", StringComparison.OrdinalIgnoreCase)
                || path.StartsWith("/management/api/", StringComparison.OrdinalIgnoreCase);
            if (!admin || !NetworkBatch166170Evidence.Header(r, "Access-Control-Request-Method", out var method)
                || !(new[] { "POST", "PUT", "PATCH", "DELETE" }
                    .Any(m => m.Equals(method, StringComparison.OrdinalIgnoreCase)))
                || !NetworkBatch166170Evidence.Header(r, "Access-Control-Request-Headers", out var names)
                || !names.Split(',').Any(x => new[] { "authorization", "cookie", "x-api-key",
                    "x-amz-security-token" }.Contains(x.Trim(), StringComparer.OrdinalIgnoreCase))
                || !NetworkBatch166170Evidence.Header(r, "Origin", out var origin)
                || !Uri.TryCreate(origin, UriKind.Absolute, out var uri)
                || (uri.Scheme != "https" && uri.Scheme != "http")
                || uri.UserInfo.Length != 0 || uri.Query.Length != 0 || uri.Fragment.Length != 0
                || !uri.AbsolutePath.Equals("/", StringComparison.Ordinal)
                || uri.Host.Equals(r.HttpHost, StringComparison.OrdinalIgnoreCase))
                return false;
            return true;
        }

        internal static bool DavHttp(TrafficRecord r)
        {
            if (r.Id == Guid.Empty || !r.IsTcp || r.IsUdp || r.IsQuic
                || r.DnsQname != null || r.DnsAnswers != null || r.DnsIsResponse
                || r.IcmpTypeCode.HasValue || r.TcpFlags.HasValue
                    && ((r.TcpFlags.Value & 0x07) != 0 || (r.TcpFlags.Value & 0x18) == 0)
                || !IPAddress.TryParse(r.Source, out var src)
                || !IPAddress.TryParse(r.Destination, out var dst)
                || src.Equals(dst) || src.AddressFamily != dst.AddressFamily
                || r.IpVersion == 4 && src.AddressFamily != System.Net.Sockets.AddressFamily.InterNetwork
                || r.IpVersion == 6 && src.AddressFamily != System.Net.Sockets.AddressFamily.InterNetworkV6
                || r.IpVersion is not (null or 4 or 6)
                || !new[] { "PROPFIND", "PROPPATCH", "MKCOL", "LOCK", "UNLOCK", "MOVE", "COPY", "SEARCH" }
                    .Any(x => x.Equals(r.HttpMethod, StringComparison.OrdinalIgnoreCase))
                || !new[] { "TCP", "HTTP", "HTTPS", "TLS" }
                    .Any(x => x.Equals(r.Protocol, StringComparison.OrdinalIgnoreCase))
                || !new[] { "HTTP", "HTTPS" }
                    .Any(x => x.Equals(r.ApplicationProtocol, StringComparison.OrdinalIgnoreCase)
                        || x.Equals(r.ApplicationService, StringComparison.OrdinalIgnoreCase))
                || r.ApplicationProtocol != null && !new[] { "HTTP", "HTTPS" }
                    .Any(x => x.Equals(r.ApplicationProtocol, StringComparison.OrdinalIgnoreCase))
                || r.ApplicationService != null && !new[] { "HTTP", "HTTPS" }
                    .Any(x => x.Equals(r.ApplicationService, StringComparison.OrdinalIgnoreCase))
                || r.Sni != null && !r.Sni.Equals(r.HttpHost, StringComparison.OrdinalIgnoreCase)
                || !NetworkBatch156165Evidence.Authority(r)
                || !NetworkBatch156165Evidence.UriOf(r, out _)
                || !NetworkBatch166170Evidence.Path(r, out _))
                return false;
            return true;
        }

        internal static bool DavAbuse(TrafficRecord r)
        {
            if (!DavHttp(r) || !NetworkBatch166170Evidence.Path(r, out var path))
                return false;
            if (path.Equals("/.well-known/caldav", StringComparison.OrdinalIgnoreCase)
                || path.Equals("/.well-known/carddav", StringComparison.OrdinalIgnoreCase))
                return false;
            var dav = path.StartsWith("/webdav", StringComparison.OrdinalIgnoreCase)
                || path.StartsWith("/dav/", StringComparison.OrdinalIgnoreCase)
                || path.StartsWith("/remote.php/dav", StringComparison.OrdinalIgnoreCase);
            var admin = path.StartsWith("/admin/", StringComparison.OrdinalIgnoreCase);
            var deep = NetworkBatch166170Evidence.Header(r, "Depth", out var depth)
                && depth.Equals("infinity", StringComparison.OrdinalIgnoreCase);
            return (dav && deep)
                || (admin && !r.HttpMethod!.Equals("PROPFIND", StringComparison.OrdinalIgnoreCase));
        }

        internal static bool Smuggling(TrafficRecord r, out string mode)
        {
            mode = "";
            if (!Http(r) || r.Alpn?.Equals("h2", StringComparison.OrdinalIgnoreCase) == true
                || r.ProtocolVersion?.Contains("HTTP/2", StringComparison.OrdinalIgnoreCase) == true
                || string.IsNullOrWhiteSpace(r.HttpRequestHeaders)
                || r.HttpRequestHeaders!.Length > 8192) return false;
            var lengths = new System.Collections.Generic.List<long>();
            var transfer = new System.Collections.Generic.List<string>();
            foreach (var line in r.HttpRequestHeaders.Split('\n'))
            {
                var colon = line.IndexOf(':');
                if (colon < 1) continue;
                var name = line[..colon].Trim();
                var value = line[(colon + 1)..].Trim();
                if (name.Equals("Content-Length", StringComparison.OrdinalIgnoreCase))
                {
                    if (!long.TryParse(value, NumberStyles.None, CultureInfo.InvariantCulture, out var size)
                        || size < 0) return false;
                    lengths.Add(size);
                }
                if (name.Equals("Transfer-Encoding", StringComparison.OrdinalIgnoreCase))
                    transfer.Add(value);
            }
            if (lengths.Count > 1 && lengths.Distinct().Count() > 1)
            { mode = "multiple-content-length"; return true; }
            if (lengths.Count > 0 && transfer.Any(x => x.Split(',')
                .Any(t => t.Trim().Equals("chunked", StringComparison.OrdinalIgnoreCase))))
            { mode = "cl-plus-te"; return true; }
            return false;
        }
    }
}
