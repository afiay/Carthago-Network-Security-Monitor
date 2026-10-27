// SPDX-License-Identifier: MIT
using System;
using System.Collections.Generic;
using System.Linq;
using System.Net;
using Carthago.Models;

namespace Carthago.Engine.Rules.Expansion
{
    // R153-R155: typed network requests, bounded parser summaries, and
    // path-only correlation. Do not infer HTTP verbs/bodies from packet Info.
    internal static class NetworkBatch151155Evidence
    {
        private static bool Same(string? a, string b)
            => string.Equals(a, b, StringComparison.OrdinalIgnoreCase);

        internal static bool HttpRequest(TrafficRecord r)
        {
            if (NetworkBatch131135Evidence.HttpRequest(r)) return true;
            // Preserve historical HEAD/OPTIONS behavior under the same basic
            // typed HTTP, transport, endpoint and authority constraints.
            if (!Same(r.HttpMethod, "HEAD") && !Same(r.HttpMethod, "OPTIONS"))
                return false;
            if (r.Id == Guid.Empty || !r.IsTcp || r.IsUdp || r.IsQuic
                || r.IcmpTypeCode.HasValue || r.TcpFlags.HasValue &&
                    ((r.TcpFlags.Value & 0x07) != 0 || (r.TcpFlags.Value & 0x18) == 0)
                || r.DnsQname != null || r.DnsAnswers != null || r.DnsIsResponse
                || !IPAddress.TryParse(r.Source, out var src)
                || !IPAddress.TryParse(r.Destination, out var dst)
                || src.Equals(dst) || src.AddressFamily != dst.AddressFamily
                || r.IpVersion is not (null or 4 or 6)
                || r.IpVersion == 4 && src.AddressFamily != System.Net.Sockets.AddressFamily.InterNetwork
                || r.IpVersion == 6 && src.AddressFamily != System.Net.Sockets.AddressFamily.InterNetworkV6
                || string.IsNullOrWhiteSpace(r.HttpHost) || r.HttpHost!.Length > 255
                || string.IsNullOrWhiteSpace(r.HttpUri) || r.HttpUri!.Length > 2048
                || !(Same(r.Protocol, "TCP") || Same(r.Protocol, "HTTP")
                    || Same(r.Protocol, "HTTPS") || Same(r.Protocol, "TLS"))
                || !(Same(r.ApplicationProtocol, "HTTP") || Same(r.ApplicationProtocol, "HTTPS")
                    || Same(r.ApplicationService, "HTTP") || Same(r.ApplicationService, "HTTPS"))
                || r.ApplicationProtocol != null && !Same(r.ApplicationProtocol, "HTTP")
                    && !Same(r.ApplicationProtocol, "HTTPS")
                || r.ApplicationService != null && !Same(r.ApplicationService, "HTTP")
                    && !Same(r.ApplicationService, "HTTPS")
                || r.Sni != null && !Same(r.Sni, r.HttpHost))
                return false;
            return !Uri.TryCreate(r.HttpUri, UriKind.Absolute, out var absolute)
                || Same(absolute.Host, r.HttpHost!);
        }

        private static Uri? UriFor(TrafficRecord r)
        {
            var raw = r.HttpUri;
            if (string.IsNullOrWhiteSpace(raw) || raw.Length > 2048)
                return null;
            if (Uri.TryCreate(raw, UriKind.Absolute, out var result))
                return result;
            return Uri.TryCreate("https://placeholder" +
                (raw.StartsWith("/", StringComparison.Ordinal) ? "" : "/") + raw,
                UriKind.Absolute, out result) ? result : null;
        }

        internal static bool GraphqlPath(TrafficRecord r)
        {
            var uri = UriFor(r);
            if (uri == null) return false;
            var path = uri.AbsolutePath.TrimEnd('/');
            return path.Equals("/graphql", StringComparison.OrdinalIgnoreCase)
                || path.EndsWith("/graphql", StringComparison.OrdinalIgnoreCase)
                || path.EndsWith("/graphql/api", StringComparison.OrdinalIgnoreCase);
        }

        internal static bool IntrospectionQuery(TrafficRecord r)
        {
            var uri = UriFor(r);
            if (uri == null || uri.Query.Length is < 5 or > 2048)
                return false;
            // GraphQL GET queries are the only inspectable query payload in
            // the current typed record. Info, paths and arbitrary headers
            // are not reliable body evidence.
            try
            {
                foreach (var segment in uri.Query.TrimStart('?').Split('&',
                    StringSplitOptions.RemoveEmptyEntries))
                {
                    var parts = segment.Split('=', 2);
                    if (parts.Length != 2) continue;
                    var name = Uri.UnescapeDataString(parts[0]).Trim();
                    if (!Same(name, "query") && !Same(name, "operationName"))
                        continue;
                    var value = Uri.UnescapeDataString(parts[1]);
                    if (value.Length > 1024) continue;
                    if (value.Contains("__schema", StringComparison.Ordinal)
                        || value.Contains("__type", StringComparison.Ordinal)
                        || value.Equals("IntrospectionQuery", StringComparison.OrdinalIgnoreCase))
                        return true;
                }
            }
            catch (UriFormatException) { return false; }
            return false;
        }

        internal static bool GraphqlBatchSummary(TrafficRecord r)
        {
            var headers = r.HttpRequestHeaders;
            if (!string.IsNullOrWhiteSpace(headers) && headers.Length <= 8192)
            {
                foreach (var line in headers.Split('\n'))
                {
                    var index = line.IndexOf(':');
                    if (index < 0 || !Same(line[..index].Trim(), "X-Graphql-Batch"))
                        continue;
                    var value = line[(index + 1)..].Trim();
                    if (Same(value, "1") || Same(value, "true")) return true;
                }
            }
            var info = r.Info;
            if (string.IsNullOrWhiteSpace(info) || info.Length > 1024)
                return false;
            // Explicit batch label plus array syntax; generic operationName
            // alone is not evidence for more than one operation.
            return info.Contains("graphql batch", StringComparison.OrdinalIgnoreCase)
                && info.Contains("[{", StringComparison.Ordinal);
        }

        internal static bool ApiResourcePath(TrafficRecord r, out string path)
        {
            path = string.Empty;
            var uri = UriFor(r);
            if (uri == null) return false;
            var candidate = uri.AbsolutePath.ToLowerInvariant().TrimEnd('/');
            if (candidate.Length is < 6 or > 512
                || candidate.Contains("//", StringComparison.Ordinal)
                || candidate.Contains("/../", StringComparison.Ordinal)
                || candidate.Contains("/./", StringComparison.Ordinal))
                return false;
            if (!candidate.StartsWith("/api/", StringComparison.Ordinal)
                && !candidate.StartsWith("/v1/", StringComparison.Ordinal)
                && !candidate.StartsWith("/v2/", StringComparison.Ordinal)
                && !candidate.StartsWith("/v3/", StringComparison.Ordinal)
                && !candidate.StartsWith("/rest/", StringComparison.Ordinal)
                && !candidate.StartsWith("/admin/api/", StringComparison.Ordinal))
                return false;
            // Ignore high-variance query values. Distinct resource paths,
            // not pagination tokens, drive enumeration detection.
            path = candidate;
            return true;
        }
    }

    // Per-rule bounded source+target resource set and packet ID cache.
    internal sealed class NetworkBatch151155DistinctWindow
    {
        private sealed class Slot
        {
            internal readonly Dictionary<Guid, DateTime> PacketIds = new();
            internal readonly Dictionary<string, DateTime> Paths = new(StringComparer.OrdinalIgnoreCase);
            internal DateTime Latest = DateTime.MinValue;
        }
        private readonly object _gate = new();
        private readonly Dictionary<string, Slot> _slots = new(StringComparer.OrdinalIgnoreCase);

        internal bool Observe(string key, Guid id, string path, DateTime at, TimeSpan window, out int distinct)
        {
            lock (_gate)
            {
                foreach (var k in _slots.Where(item => at - item.Value.Latest > window)
                    .Select(item => item.Key).ToArray()) _slots.Remove(k);
                if (!_slots.TryGetValue(key, out var slot))
                {
                    if (_slots.Count >= 1024)
                        _slots.Remove(_slots.OrderBy(item => item.Value.Latest).First().Key);
                    _slots[key] = slot = new Slot();
                }
                foreach (var k in slot.PacketIds.Where(item => at - item.Value > window)
                    .Select(item => item.Key).ToArray()) slot.PacketIds.Remove(k);
                foreach (var k in slot.Paths.Where(item => at - item.Value > window)
                    .Select(item => item.Key).ToArray()) slot.Paths.Remove(k);
                distinct = slot.Paths.Count;
                if (at < slot.Latest || slot.PacketIds.ContainsKey(id))
                    return false;
                slot.Latest = at;
                if (slot.PacketIds.Count >= 256)
                    slot.PacketIds.Remove(slot.PacketIds.OrderBy(item => item.Value).First().Key);
                slot.PacketIds[id] = at;
                if (slot.Paths.Count >= 256 && !slot.Paths.ContainsKey(path))
                    slot.Paths.Remove(slot.Paths.OrderBy(item => item.Value).First().Key);
                slot.Paths[path] = at;
                distinct = slot.Paths.Count;
                return true;
            }
        }
    }
}
