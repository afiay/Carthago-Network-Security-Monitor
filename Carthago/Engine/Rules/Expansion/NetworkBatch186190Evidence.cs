// SPDX-License-Identifier: MIT
using System;
using System.Linq;
using System.Net;
using Carthago.Models;

namespace Carthago.Engine.Rules.Expansion
{
    // Wire-observable DNS metadata only. No inference from packet Info text.
    // AD SRV names contain RFC-compatible underscore service labels, which
    // the ordinary hostname validator intentionally rejects.
    internal static class NetworkBatch186190Evidence
    {
        private static bool Transport(TrafficRecord r, bool response)
        {
            if (r.Id == Guid.Empty || r.IsQuic || r.IsTcp == r.IsUdp
                || r.DnsIsResponse != response || !string.IsNullOrWhiteSpace(r.HttpMethod)
                || !string.IsNullOrWhiteSpace(r.HttpUri) || !string.IsNullOrWhiteSpace(r.HttpRequestHeaders)
                || !new[] { "DNS", "TCP", "UDP" }.Contains(r.Protocol, StringComparer.OrdinalIgnoreCase)
                || r.ApplicationProtocol != null && !r.ApplicationProtocol.Equals("DNS", StringComparison.OrdinalIgnoreCase)
                || r.ApplicationService != null && !r.ApplicationService.Equals("DNS", StringComparison.OrdinalIgnoreCase)
                || r.Protocol != "DNS" && r.ApplicationProtocol != "DNS" && r.ApplicationService != "DNS"
                || !IPAddress.TryParse(r.Source, out var src) || !IPAddress.TryParse(r.Destination, out var dst)
                || src.Equals(dst) || src.AddressFamily != dst.AddressFamily
                || r.IpVersion == 4 && src.AddressFamily != System.Net.Sockets.AddressFamily.InterNetwork
                || r.IpVersion == 6 && src.AddressFamily != System.Net.Sockets.AddressFamily.InterNetworkV6
                || r.IpVersion is not (null or 4 or 6))
                return false;
            return response ? r.SourcePort == 53 && r.DestinationPort != 53
                            : r.DestinationPort == 53;
        }

        private static bool ValidLabels(string? name, bool serviceLabels, out string normalized)
        {
            normalized = (name ?? "").TrimEnd('.').ToLowerInvariant();
            if (normalized.Length is < 3 or > 253 || normalized.Contains("..", StringComparison.Ordinal))
                return false;
            var labels = normalized.Split('.');
            if (labels.Length < 2) return false;
            foreach (var label in labels)
            {
                if (label.Length is < 1 or > 63 || label[^1] == '-') return false;
                var service = serviceLabels && label[0] == '_';
                if (!service && label[0] == '-') return false;
                if (service && label.Length < 2) return false;
                if (label.Skip(service ? 1 : 0).Any(c => !(char.IsAsciiLetterOrDigit(c) || c == '-')))
                    return false;
            }
            return true;
        }

        internal static bool AdSrv(TrafficRecord r, out string query)
        {
            query = "";
            if (!Transport(r, response: false) || !string.IsNullOrWhiteSpace(r.DnsAnswers)
                || !string.Equals(r.DnsQtype, "SRV", StringComparison.OrdinalIgnoreCase)
                || !ValidLabels(r.DnsQname, serviceLabels: true, out query))
                return false;
            var labels = query.Split('.');
            if (labels.Length < 4 || !new[] { "_ldap", "_kerberos", "_gc", "_kpasswd" }.Contains(labels[0], StringComparer.OrdinalIgnoreCase)
                || !labels[1].Equals("_tcp", StringComparison.OrdinalIgnoreCase))
                return false;
            // Only AD service/site labels may contain underscores, not arbitrary host labels.
            return labels.Skip(2).All(label => !label.StartsWith("_", StringComparison.Ordinal)
                || label is "_sites" or "_msdcs");
        }

        internal static bool DnsResponse(TrafficRecord r, out string query)
        {
            query = "";
            return Transport(r, response: true)
                && r.DnsTtl is >= 0
                && (string.IsNullOrWhiteSpace(r.DnsRcode)
                    || r.DnsRcode.Equals("NOERROR", StringComparison.OrdinalIgnoreCase)
                    || r.DnsRcode == "0")
                && new[] { "A", "AAAA", "CNAME" }.Contains(r.DnsQtype, StringComparer.OrdinalIgnoreCase)
                && ValidLabels(r.DnsQname, serviceLabels: false, out query);
        }
    }
}
