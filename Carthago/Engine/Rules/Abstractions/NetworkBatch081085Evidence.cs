// SPDX-License-Identifier: MIT
using System;
using System.Collections.Generic;
using System.Linq;
using System.Net;
using System.Net.Sockets;
using System.Text.RegularExpressions;
using Carthago.Engine.Rules.AssetInventory;
using Carthago.Models;

namespace Carthago.Engine.Rules
{
    // Typed evidence only: never interpret Info prose as a parsed security protocol.
    // These service labels require independently validated capture-adapter provenance.
    internal static class NetworkBatch081085Evidence
    {
        internal static bool KerberosAsRep(RuleEvaluationContext c, out string kdc, out string client)
        {
            kdc = client = "";
            var r = c.Record;
            if (!NetworkBatch076080Evidence.ValidTime(c) || r.Id == Guid.Empty
                || r.IpVersion is not (null or 4)
                || !AssetNetworkEvidence.Private(r.Source, out kdc)
                || !AssetNetworkEvidence.Private(r.Destination, out client) || kdc == client
                || r.SourcePort != 88 || r.DestinationPort is not int dp || dp is < 1 or > 65535
                || dp == 88 || r.IsQuic || r.IcmpTypeCode.HasValue || r.DnsIsResponse
                || r.DnsQname != null || r.HttpMethod != null) return false;
            if (string.Equals(r.Protocol, "UDP", StringComparison.OrdinalIgnoreCase))
                return r.IsUdp && !r.IsTcp && !r.TcpFlags.HasValue;
            return string.Equals(r.Protocol, "TCP", StringComparison.OrdinalIgnoreCase)
                && r.IsTcp && !r.IsUdp
                && (!r.TcpFlags.HasValue ||
                    ((r.TcpFlags.Value & 0x07) == 0 && (r.TcpFlags.Value & 0x18) != 0));
        }

        internal static bool Ntlm(RuleEvaluationContext c, out string source, out string target)
        {
            source = target = "";
            var r = c.Record;
            if (!NetworkBatch076080Evidence.ValidTime(c) || r.Id == Guid.Empty
                || r.IpVersion is not (null or 4)
                || !AssetNetworkEvidence.Private(r.Source, out source)
                || !AssetNetworkEvidence.Private(r.Destination, out target) || source == target
                || r.DestinationPort is not (80 or 135 or 139 or 445 or 5985 or 5986)
                || r.SourcePort is not int sp || sp is < 1 or > 65535
                || !string.Equals(r.Protocol, "TCP", StringComparison.OrdinalIgnoreCase)
                || !r.IsTcp || r.IsUdp || r.IsQuic || r.IcmpTypeCode.HasValue
                || r.DnsIsResponse || r.DnsQname != null) return false;
            if (r.TcpFlags is ushort flags && ((flags & 0x07) != 0 || (flags & 0x18) == 0))
                return false;
            return true;
        }

        internal static bool NameServiceConflict(RuleEvaluationContext c, out string responder, out string peer, out string service)
        {
            responder = peer = service = "";
            var r = c.Record;
            if (!NetworkBatch076080Evidence.ValidTime(c) || r.Id == Guid.Empty
                || r.IpVersion is not (null or 4)
                || !AssetNetworkEvidence.Private(r.Source, out responder)
                || !IPAddress.TryParse(r.Destination, out var dst)
                || dst.AddressFamily != AddressFamily.InterNetwork
                || r.SourcePort is not (5355 or 137)
                || r.DestinationPort is not int dp || dp is < 1 or > 65535
                || !string.Equals(r.Protocol, "UDP", StringComparison.OrdinalIgnoreCase)
                || !r.IsUdp || r.IsTcp || r.IsQuic || r.TcpFlags.HasValue
                || r.IcmpTypeCode.HasValue || !r.DnsIsResponse
                || string.IsNullOrWhiteSpace(r.DnsQname) || r.DnsQname!.Length > 253
                || string.IsNullOrWhiteSpace(r.DnsAnswers) || r.HttpMethod != null
                || r.HttpUri != null || r.HttpRequestHeaders != null) return false;
            service = r.SourcePort == 5355 ? "LLMNR" : "NBNS";
            if (!NetworkBatch076080Evidence.Classification(r, service, "CONFLICTING_RESPONSE")) return false;
            var broadcast = dst.ToString() == "255.255.255.255"
                || (service == "LLMNR" && dst.ToString() == "224.0.0.252");
            if (!broadcast && !AssetNetworkEvidence.Private(r.Destination, out _)) return false;
            peer = dst.ToString();
            return responder != peer;
        }

        internal static bool HttpRequest(RuleEvaluationContext c)
        {
            var r = c.Record;
            if (!NetworkBatch076080Evidence.ValidTime(c) || r.Id == Guid.Empty
                || r.IsUdp || r.IsQuic || r.IcmpTypeCode.HasValue || r.DnsIsResponse
                || r.DnsQname != null || r.TcpFlags is ushort flags &&
                    ((flags & 0x07) != 0 || (flags & 0x18) == 0)
                || !(string.Equals(r.Protocol, "TCP", StringComparison.OrdinalIgnoreCase) && r.IsTcp
                     || string.Equals(r.Protocol, "HTTP", StringComparison.OrdinalIgnoreCase) && !r.IsUdp)
                || r.SourcePort is not int sp || sp is < 1 or > 65535
                || r.DestinationPort is not int dp || dp is < 1 or > 65535
                || r.Length <= 0 || !IPAddress.TryParse(r.Source, out var src)
                || !IPAddress.TryParse(r.Destination, out var dst) || src.Equals(dst)
                || string.IsNullOrWhiteSpace(r.HttpHost) || r.HttpHost!.Length > 253
                || r.HttpHost.IndexOfAny(new[] { '\r', '\n', '\t', ' ' }) >= 0
                || string.IsNullOrWhiteSpace(r.HttpUri) || r.HttpUri!.Length > 4096
                || r.HttpUri.IndexOfAny(new[] { '\r', '\n' }) >= 0
                || !new[] { "GET", "POST", "PUT", "PATCH", "DELETE", "HEAD", "OPTIONS" }
                    .Contains(r.HttpMethod, StringComparer.OrdinalIgnoreCase)) return false;
            if (!r.HttpUri.StartsWith("/", StringComparison.Ordinal))
            {
                if (!Uri.TryCreate(r.HttpUri, UriKind.Absolute, out var uri)
                    || !string.Equals(uri.Host, r.HttpHost, StringComparison.OrdinalIgnoreCase))
                    return false;
            }
            if (r.HttpRequestHeaders == null) return true;
            var h = r.HttpRequestHeaders;
            if (h.Length > 4096 || !h.EndsWith("\r\n\r\n", StringComparison.Ordinal)) return false;
            var lines = h.Split(new[] { "\r\n" }, StringSplitOptions.None);
            var hosts = 0;
            foreach (var line in lines)
            {
                if (line.Length == 0) continue;
                if (line.IndexOfAny(new[] { '\r', '\n' }) >= 0) return false;
                var colon = line.IndexOf(':');
                if (colon <= 0 || line[0] == ' ' || line[0] == '\t') return false;
                if (!string.Equals(line.Substring(0, colon), "Host", StringComparison.OrdinalIgnoreCase)) continue;
                hosts++;
                if (!string.Equals(line.Substring(colon + 1).Trim(), r.HttpHost, StringComparison.OrdinalIgnoreCase))
                    return false;
            }
            return hosts == 1;
        }

        internal static IEnumerable<string> HttpFields(TrafficRecord r)
        {
            if (!string.IsNullOrEmpty(r.HttpUri)) yield return r.HttpUri;
            if (!string.IsNullOrEmpty(r.HttpUserAgent)) yield return r.HttpUserAgent;
            if (!string.IsNullOrEmpty(r.HttpRequestHeaders)) yield return r.HttpRequestHeaders;
        }

        // Bounded, at most two percent-decode passes. No raw content is retained or logged.
        internal static string Normalize(string raw)
        {
            var value = raw.Length > 4096 ? raw.Substring(0, 4096) : raw;
            for (var i = 0; i < 2; i++)
            {
                string decoded;
                try { decoded = Uri.UnescapeDataString(value.Replace("+", " ")); }
                catch (UriFormatException) { break; }
                if (decoded == value) break;
                value = decoded.Length > 4096 ? decoded.Substring(0, 4096) : decoded;
            }
            return value;
        }

        internal static bool Jndi(string raw)
        {
            var s = Normalize(raw);
            try
            {
                return Regex.IsMatch(s, @"\$\{(?:\$\{(?:lower:j|upper:J)\}|j)ndi\s*:\s*(?:ldap|ldaps|rmi|dns|iiop)://",
                    RegexOptions.IgnoreCase | RegexOptions.CultureInvariant, TimeSpan.FromMilliseconds(50));
            }
            catch (RegexMatchTimeoutException) { return false; }
        }

        internal static bool SqlInjection(string raw)
        {
            var s = Normalize(raw);
            // A SQL keyword or ordinary equality is never enough by itself.
            const RegexOptions options = RegexOptions.IgnoreCase | RegexOptions.CultureInvariant;
            var timeout = TimeSpan.FromMilliseconds(50);
            try
            {
            return Regex.IsMatch(s, "['\"]\\s*(?:or|and)\\s+(?:1\\s*=\\s*1|2\\s*=\\s*2)\\s*(?:--|#|/\\*)",
                    options, timeout)
                || (s.Contains("?", StringComparison.Ordinal)
                    && s.Contains("'", StringComparison.Ordinal)
                    && Regex.IsMatch(s, @"\bunion\s+(?:all\s+)?select\s+.{1,80}\s+from\s+[a-z_][\w]*",
                        options, timeout))
                || Regex.IsMatch(s, @"[';]\s*(?:waitfor\s+delay\s*'\d{2}:\d{2}:\d{2}'|select\s+sleep\s*\(\s*\d+\s*\))\s*(?:--|#|/\*)",
                    options, timeout);
            }
            catch (RegexMatchTimeoutException) { return false; }
        }

        internal static RuleEvaluationResult Match(RuleDescriptor descriptor, RuleEvaluationContext c, string summary)
            => RuleEvaluationResult.Match(descriptor.RuleId,
                NetworkBatch071075Evidence.Alert(descriptor, c, summary));
    }

    // Single-record payload alerts are deduplicated by record identity; the memory is
    // bounded and never stores URLs, principals, credentials or payloads.
    internal sealed class NetworkBatch081085Dedup
    {
        private readonly Dictionary<Guid, DateTime> _seen = new();
        private readonly object _gate = new();
        internal bool First(Guid id, DateTime timestamp)
        {
            lock (_gate)
            {
                foreach (var stale in _seen.Where(x => timestamp - x.Value > TimeSpan.FromMinutes(10))
                    .Select(x => x.Key).ToArray()) _seen.Remove(stale);
                if (_seen.ContainsKey(id)) return false;
                if (_seen.Count >= 4096)
                    _seen.Remove(_seen.OrderBy(x => x.Value).First().Key);
                _seen[id] = timestamp;
                return true;
            }
        }
    }
}
