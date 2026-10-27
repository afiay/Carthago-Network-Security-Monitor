// SPDX-License-Identifier: MIT
using System;
using System.Collections.Generic;
using System.Linq;
using System.Net;
using System.Net.Sockets;
using System.Text.RegularExpressions;
using Carthago.Models;

namespace Carthago.Engine.Rules
{
    // Evidence contracts for R101-R105; no packet Info or guessed upload direction.
    internal static class NetworkBatch101105Evidence
    {
        private static readonly Regex CnameToken = new(
            @"(?<![a-z0-9._-])(?:CNAME|(?:[a-z0-9_-]{1,63}\.)+[a-z0-9_-]{2,63})(?![a-z0-9._-])",
            RegexOptions.IgnoreCase | RegexOptions.CultureInvariant,
            TimeSpan.FromMilliseconds(50));

        internal static int CnameChainDepth(string? answers)
        {
            if (string.IsNullOrWhiteSpace(answers) || answers.Length > 4096) return 0;
            try
            {
                var tokens = CnameToken.Matches(answers).Select(m => m.Value.TrimEnd('.')).ToArray();
                if (tokens.Length is < 5 or > 128) return 0;
                var edges = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);
                var indegree = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
                for (var i = 1; i + 1 < tokens.Length; i++)
                {
                    if (!tokens[i].Equals("CNAME", StringComparison.OrdinalIgnoreCase)) continue;
                    var from = tokens[i - 1];
                    var to = tokens[i + 1];
                    if (from.Equals("CNAME", StringComparison.OrdinalIgnoreCase)
                        || to.Equals("CNAME", StringComparison.OrdinalIgnoreCase)
                        || from.Equals(to, StringComparison.OrdinalIgnoreCase)) return 0;
                    if (edges.TryGetValue(from, out var existing)
                        && !existing.Equals(to, StringComparison.OrdinalIgnoreCase)) return 0;
                    edges[from] = to;
                    indegree.Add(to);
                }
                if (edges.Count is < 2 or > 32) return 0;
                var roots = edges.Keys.Where(k => !indegree.Contains(k)).ToArray();
                if (roots.Length == 0) return 0;
                var maximum = 0;
                foreach (var root in roots)
                {
                    var seen = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
                    var node = root;
                    var depth = 0;
                    while (edges.TryGetValue(node, out var next))
                    {
                        if (!seen.Add(node) || depth >= 32) return 0;
                        depth++;
                        node = next;
                    }
                    maximum = Math.Max(maximum, depth);
                }
                return maximum;
            }
            catch (RegexMatchTimeoutException) { return 0; }
        }

        internal static bool CloudUpload(RuleEvaluationContext context)
        {
            var r = context.Record;
            if (r.Id == Guid.Empty || !NetworkBatch076080Evidence.ValidTime(context)
                || !r.IsTcp || r.IsUdp || r.IsQuic || r.IcmpTypeCode.HasValue
                || r.DnsQname != null || r.DnsIsResponse || r.DnsAnswers != null
                || !string.Equals(r.Protocol, "TCP", StringComparison.OrdinalIgnoreCase)
                || !string.Equals(r.ApplicationProtocol, "HTTP", StringComparison.OrdinalIgnoreCase)
                || !new[] { "POST", "PUT", "PATCH" }.Contains(r.HttpMethod, StringComparer.OrdinalIgnoreCase)
                || string.IsNullOrWhiteSpace(r.HttpUri) || r.HttpUri!.Length > 4096
                || r.HttpUri.IndexOfAny(new[] { '\r', '\n', '\0' }) >= 0
                || r.DestinationPort is not int port || port is < 1 or > 65535
                || !IPAddress.TryParse(r.Source, out var source)
                || !IPAddress.TryParse(r.Destination, out var destination)
                || source.Equals(destination)
                || source.AddressFamily != destination.AddressFamily
                || r.IpVersion == 4 && source.AddressFamily != AddressFamily.InterNetwork
                || r.IpVersion == 6 && source.AddressFamily != AddressFamily.InterNetworkV6
                || r.IpVersion is not (null or 4 or 6)
                || r.TcpFlags is ushort flags && ((flags & 0x07) != 0 || (flags & 0x18) == 0)
                || Math.Max(r.Length, r.L4Len ?? 0) <= 0)
                return false;

            var host = r.HttpHost ?? r.Sni;
            if (string.IsNullOrWhiteSpace(host) || host!.Length > 253
                || host.IndexOfAny(new[] { '\r', '\n', '\t', ' ', '\0' }) >= 0
                || r.HttpHost != null && r.Sni != null
                   && !r.HttpHost.Equals(r.Sni, StringComparison.OrdinalIgnoreCase))
                return false;

            // An HTTP Host header cannot contradict parser-attributed HttpHost.
            if (r.HttpRequestHeaders is { } headers)
            {
                if (headers.Length > 4096 || headers.IndexOf('\0') >= 0) return false;
                var hosts = Regex.Matches(headers,
                    @"(?:^|\r\n)Host:\s*([^\r\n]+)",
                    RegexOptions.IgnoreCase | RegexOptions.CultureInvariant,
                    TimeSpan.FromMilliseconds(50));
                if (hosts.Count > 1 || hosts.Count == 1
                    && !hosts[0].Groups[1].Value.Trim().Equals(host, StringComparison.OrdinalIgnoreCase))
                    return false;
            }
            return true;
        }

        internal static bool UploadMetadata(TrafficRecord record)
        {
            // Never interpret free-form Info as an HTTP parser observation.
            var uri = record.HttpUri ?? string.Empty;
            var headers = record.HttpRequestHeaders ?? string.Empty;
            return uri.Contains("/upload", StringComparison.OrdinalIgnoreCase)
                || uri.Contains("createUploadSession", StringComparison.OrdinalIgnoreCase)
                || headers.Contains("Content-Disposition:", StringComparison.OrdinalIgnoreCase)
                || headers.Contains("Content-Range:", StringComparison.OrdinalIgnoreCase)
                || headers.Contains("X-Goog-Upload", StringComparison.OrdinalIgnoreCase)
                || headers.Contains("X-Ms-Blob-Type:", StringComparison.OrdinalIgnoreCase);
        }
    }
}
