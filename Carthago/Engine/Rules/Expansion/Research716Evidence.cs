// SPDX-License-Identifier: MIT
// SOURCE CANDIDATE — UNVERIFIED. Shared evidence hygiene/classification only; no rule convergence.
using System;
using System.Linq;
using System.Net;
using Carthago.Models;

namespace Carthago.Engine.Rules.Expansion
{
    internal static class Research716Evidence
    {
        internal static bool Process(TrafficRecord r, params string[] names)
            => Research676Evidence.Process(r, names);

        internal static bool HostIs(string? candidate, string root)
            => Research656Evidence.HostIs(candidate, root);

        internal static bool Udp18ToPrivateDiagnosticPort(TrafficRecord r)
        {
            if (r == null || r.Id == Guid.Empty || r.IpVersion != 4
                || r.IsTcp || !r.IsUdp || r.IsQuic
                || !string.Equals(r.Protocol, "UDP", StringComparison.OrdinalIgnoreCase)
                || r.SourcePort is null or <= 0 or > 65535
                || r.DestinationPort != 50000
                || r.L4Len != 18 || r.Length < 46
                || r.TcpFlags != null
                || r.HttpMethod != null || r.HttpUri != null || r.TlsVersion != null
                || r.Sni != null || r.DnsQname != null || r.DnsIsResponse
                || r.ApplicationProtocol != null)
                return false;

            if (!IPAddress.TryParse(r.Source, out var source) || source == null
                || !IPAddress.TryParse(r.Destination, out var destination) || destination == null
                || source.AddressFamily != System.Net.Sockets.AddressFamily.InterNetwork
                || destination.AddressFamily != System.Net.Sockets.AddressFamily.InterNetwork
                || source.Equals(destination)
                || !Research646Evidence.Private(destination))
                return false;

            var b = destination.GetAddressBytes();
            return b[3] is not (0 or 255);
        }

        internal static bool OutboundTls443(TrafficRecord r)
            => Research676Evidence.Tcp(r)
               && Research676Evidence.PrivateToPublic(r)
               && r.DestinationPort == 443
               && r.TlsVersion != null
               && !string.IsNullOrWhiteSpace(r.Sni)
               && r.L4Len is >= 32 and <= 8192
               && r.HttpMethod == null && r.HttpUri == null
               && r.DnsQname == null && !r.DnsIsResponse;

        internal static bool CodeRepositoryApi(string? host, string uri)
        {
            if (HostIs(host, "api.github.com"))
                return uri.StartsWith("/repos/", StringComparison.OrdinalIgnoreCase)
                    && !uri.StartsWith("/gists", StringComparison.OrdinalIgnoreCase);

            if (HostIs(host, "gitlab.com"))
                return uri.StartsWith("/api/v4/projects/", StringComparison.OrdinalIgnoreCase);

            return false;
        }

        internal static bool CloudStorageHost(string? host)
            => HostIs(host, "dropbox.com")
               || HostIs(host, "dropboxapi.com")
               || HostIs(host, "drive.google.com")
               || HostIs(host, "box.com")
               || HostIs(host, "onedrive.live.com")
               || HostIs(host, "1drv.ms");

        internal static bool SuspiciousDownloadExtension(string uri)
        {
            var path = uri.Split('?')[0];
            string[] extensions =
            {
                ".7z", ".asax", ".ashx", ".asmx", ".asp", ".aspx", ".bat",
                ".cgi", ".chm", ".cmd", ".dll", ".jsp", ".jspx", ".ps1",
                ".psm1", ".rar", ".scf", ".sct", ".vbe", ".vbs", ".war",
                ".wsf", ".wsh", ".xll", ".zip"
            };
            return extensions.Any(ext => path.EndsWith(ext, StringComparison.OrdinalIgnoreCase));
        }

        internal static bool BrowserLikeUserAgent(string? value)
        {
            if (string.IsNullOrWhiteSpace(value) || value.Length is < 16 or > 512
                || !value.Contains("Mozilla/5.0", StringComparison.OrdinalIgnoreCase))
                return false;

            return value.Contains("Chrome/", StringComparison.OrdinalIgnoreCase)
                || value.Contains("Firefox/", StringComparison.OrdinalIgnoreCase)
                || value.Contains("Edg/", StringComparison.OrdinalIgnoreCase)
                || value.Contains("Safari/", StringComparison.OrdinalIgnoreCase);
        }

        internal static bool PublicIpDiscoveryHost(string? host)
            => HostIs(host, "api.ipify.org")
               || HostIs(host, "ifconfig.me")
               || HostIs(host, "ipinfo.io")
               || HostIs(host, "icanhazip.com")
               || HostIs(host, "checkip.amazonaws.com")
               || HostIs(host, "ident.me");

        internal static bool HighEntropyDnsQuery(string query)
        {
            if (string.IsNullOrWhiteSpace(query) || query.Length > 253)
                return false;

            var labels = query.Split('.', StringSplitOptions.RemoveEmptyEntries);
            if (labels.Length < 2) return false;

            var first = labels[0];
            if (first.Length is < 28 or > 63
                || first.Count(char.IsDigit) < 4
                || first.Distinct().Count() < 14)
                return false;

            return !query.EndsWith(".microsoft.com", StringComparison.OrdinalIgnoreCase)
                && !query.EndsWith(".office.com", StringComparison.OrdinalIgnoreCase)
                && !query.EndsWith(".windows.net", StringComparison.OrdinalIgnoreCase)
                && !query.EndsWith(".google.com", StringComparison.OrdinalIgnoreCase);
        }
    }
}
