// SPDX-License-Identifier: MIT
// CANDIDATE — UNVERIFIED. Parsed request shape is not authenticated identity.
using System;
using Carthago.Models;

namespace Carthago.Engine.Rules.Expansion
{
    internal static class DevOpsHttpEvidence
    {
        internal static bool HasParsedRequest(TrafficRecord record)
            => record.IsTcp && !record.IsUdp
                && string.Equals(record.ApplicationProtocol, "HTTP", StringComparison.OrdinalIgnoreCase)
                && !string.IsNullOrWhiteSpace(record.HttpMethod)
                && !string.IsNullOrWhiteSpace(record.HttpUri);

        internal static string? OriginPath(string? target)
        {
            if (string.IsNullOrEmpty(target) || target.Length > 4096
                || !target.StartsWith("/", StringComparison.Ordinal)
                || target.StartsWith("//", StringComparison.Ordinal)
                || target.IndexOf((char)92) >= 0 || target.IndexOf('#') >= 0)
                return null;
            foreach (var ch in target)
                if (char.IsControl(ch)) return null;
            var query = target.IndexOf('?');
            var path = query < 0 ? target : target[..query];
            if (path.Contains("//", StringComparison.Ordinal)
                || path.Contains("/../", StringComparison.Ordinal)
                || path.EndsWith("/..", StringComparison.Ordinal)
                || path.Contains("/./", StringComparison.Ordinal)
                || path.Contains('%'))
                return null;
            return path.TrimEnd('/');
        }

        // Host comes from the client HTTP request, not a server identity proof.
        internal static bool HostMatches(TrafficRecord record, string domain, bool subdomains = false)
        {
            if (string.IsNullOrWhiteSpace(record.HttpHost)) return false;
            var host = record.HttpHost.Trim().TrimEnd('.');
            var colon = host.LastIndexOf(':');
            if (colon >= 0)
            {
                if (!int.TryParse(host[(colon + 1)..], out var port) || port is < 1 or > 65535)
                    return false;
                host = host[..colon];
            }
            return string.Equals(host, domain, StringComparison.OrdinalIgnoreCase)
                || (subdomains && host.EndsWith("." + domain, StringComparison.OrdinalIgnoreCase));
        }
    }
}
