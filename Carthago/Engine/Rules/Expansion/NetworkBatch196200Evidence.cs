// SPDX-License-Identifier: MIT
using System;
using System.Linq;
using System.Net;
using Carthago.Models;

namespace Carthago.Engine.Rules.Expansion
{
    // Candidate typed-provenance checks. Packet Info is not a DNS response or
    // HTTP credential response; only parsed request/response fields qualify.
    internal static class NetworkBatch196200Evidence
    {
        private static bool DnsResponse(TrafficRecord r)
        {
            if (r.Id == Guid.Empty || !r.DnsIsResponse || r.IsTcp == r.IsUdp || r.IsQuic
                || r.SourcePort != 53 || r.DestinationPort == 53
                || string.IsNullOrWhiteSpace(r.DnsQname)
                || !string.IsNullOrWhiteSpace(r.HttpMethod)
                || !string.IsNullOrWhiteSpace(r.HttpUri)
                || !string.IsNullOrWhiteSpace(r.HttpRequestHeaders)
                || !new[] { "DNS", "TCP", "UDP" }.Contains(r.Protocol, StringComparer.OrdinalIgnoreCase)
                || r.ApplicationProtocol != null && !r.ApplicationProtocol.Equals("DNS", StringComparison.OrdinalIgnoreCase)
                || r.ApplicationService != null && !r.ApplicationService.Equals("DNS", StringComparison.OrdinalIgnoreCase)
                || !string.Equals(r.Protocol, "DNS", StringComparison.OrdinalIgnoreCase)
                    && !string.Equals(r.ApplicationProtocol, "DNS", StringComparison.OrdinalIgnoreCase)
                    && !string.Equals(r.ApplicationService, "DNS", StringComparison.OrdinalIgnoreCase)
                || !IPAddress.TryParse(r.Source, out var src) || !IPAddress.TryParse(r.Destination, out var dst)
                || src.Equals(dst) || src.AddressFamily != dst.AddressFamily
                || r.IpVersion is not (null or 4 or 6)
                || r.IpVersion == 4 && src.AddressFamily != System.Net.Sockets.AddressFamily.InterNetwork
                || r.IpVersion == 6 && src.AddressFamily != System.Net.Sockets.AddressFamily.InterNetworkV6)
                return false;
            return true;
        }

        internal static bool Nxdomain(TrafficRecord r)
            => DnsResponse(r) && string.IsNullOrWhiteSpace(r.DnsAnswers)
                && (r.DnsRcode?.Equals("NXDOMAIN", StringComparison.OrdinalIgnoreCase) == true
                    || r.DnsRcode == "3"
                    || r.DnsRcode?.Equals("Name Error", StringComparison.OrdinalIgnoreCase) == true);

        internal static bool PrivateAnswer(TrafficRecord r)
            => DnsResponse(r) && !string.IsNullOrWhiteSpace(r.DnsAnswers)
                && new[] { "A", "AAAA" }.Contains(r.DnsQtype, StringComparer.OrdinalIgnoreCase)
                && (string.IsNullOrWhiteSpace(r.DnsRcode)
                    || r.DnsRcode.Equals("NOERROR", StringComparison.OrdinalIgnoreCase)
                    || r.DnsRcode == "0")
                && r.DnsTtl is null or >= 0;

        private static bool HasQuery(Uri uri, string key)
        {
            foreach (var part in uri.Query.TrimStart('?').Split('&', StringSplitOptions.RemoveEmptyEntries))
            {
                var pieces = part.Split('=', 2);
                if (pieces.Length == 2 && pieces[0].Equals(key, StringComparison.OrdinalIgnoreCase)
                    && pieces[1].Length is > 0 and <= 256)
                    return true;
            }
            return false;
        }

        internal static bool MetadataRequest(TrafficRecord r, string provider)
        {
            // Metadata credentials are only attributable to the link-local IMDS
            // socket. An HTTP Host string or packet Info cannot establish it.
            if (!NetworkBatch166170Evidence.Http(r)
                || !NetworkBatch131135Evidence.CleartextHttpRequest(r)
                || r.Destination != "169.254.169.254"
                || !string.Equals(r.HttpMethod, "GET", StringComparison.OrdinalIgnoreCase)
                || !NetworkBatch166170Evidence.Header(r, "Host", out var host)
                || !host.Equals(r.HttpHost, StringComparison.OrdinalIgnoreCase)
                || !NetworkBatch156165Evidence.UriOf(r, out var uri))
                return false;

            var path = uri.AbsolutePath;
            switch (provider)
            {
                case "aws":
                    if (!(host.Equals("169.254.169.254", StringComparison.OrdinalIgnoreCase)
                        || host.Equals("instance-data.ec2.internal", StringComparison.OrdinalIgnoreCase)))
                        return false;
                    const string prefix = "/latest/meta-data/iam/security-credentials/";
                    return path.StartsWith(prefix, StringComparison.OrdinalIgnoreCase)
                        && path.Length > prefix.Length && path.Length <= prefix.Length + 128
                        && !path[prefix.Length..].Contains('/');
                case "gcp":
                    if (!(host.Equals("metadata.google.internal", StringComparison.OrdinalIgnoreCase)
                        || host.Equals("metadata.google", StringComparison.OrdinalIgnoreCase)
                        || host.Equals("169.254.169.254", StringComparison.OrdinalIgnoreCase))
                        || !NetworkBatch166170Evidence.Header(r, "Metadata-Flavor", out var flavor)
                        || !flavor.Equals("Google", StringComparison.OrdinalIgnoreCase))
                        return false;
                    const string start = "/computeMetadata/v1/instance/service-accounts/";
                    if (!path.StartsWith(start, StringComparison.OrdinalIgnoreCase)) return false;
                    var segments = path[start.Length..].Split('/');
                    return segments.Length == 2 && segments[0].Length is > 0 and <= 128
                        && (segments[1].Equals("token", StringComparison.OrdinalIgnoreCase)
                            || segments[1].Equals("identity", StringComparison.OrdinalIgnoreCase));
                case "azure":
                    return host.Equals("169.254.169.254", StringComparison.OrdinalIgnoreCase)
                        && path.Equals("/metadata/identity/oauth2/token", StringComparison.OrdinalIgnoreCase)
                        && NetworkBatch166170Evidence.Header(r, "Metadata", out var metadata)
                        && metadata.Equals("true", StringComparison.OrdinalIgnoreCase)
                        && HasQuery(uri, "api-version")
                        && (HasQuery(uri, "resource") || HasQuery(uri, "scope"));
                default: return false;
            }
        }
    }
}
