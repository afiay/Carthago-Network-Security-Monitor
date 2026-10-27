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
    // R096-R100 consume parser-attributed DNS fields, not packet Info, HTTP,
    // an arbitrary hostname or the mere presence of port 53.
    internal static class NetworkBatch096100Evidence
    {
        private static readonly HashSet<string> QueryTypes = new(
            new[] { "A", "AAAA", "TXT", "NULL", "CNAME", "MX", "NS", "SRV", "PTR", "SOA" },
            StringComparer.OrdinalIgnoreCase);

        internal static bool Dns(RuleEvaluationContext context, bool response = false, bool singleLabel = false)
        {
            var r = context.Record;
            if (!NetworkBatch076080Evidence.ValidTime(context) || r.Id == Guid.Empty
                || r.DnsIsResponse != response || string.IsNullOrWhiteSpace(r.DnsQname)
                || r.DnsQname!.Length > 253 || !QueryTypes.Contains(r.DnsQtype ?? "")
                || r.HttpMethod != null || r.HttpUri != null || r.HttpRequestHeaders != null
                || r.IsQuic || r.IcmpTypeCode.HasValue
                || response && r.DnsRcode != null
                    && !string.Equals(r.DnsRcode, "NOERROR", StringComparison.OrdinalIgnoreCase)
                || !IPAddress.TryParse(r.Source, out var src)
                || !IPAddress.TryParse(r.Destination, out var dst)
                || src.Equals(dst) || src.AddressFamily != dst.AddressFamily
                || r.IpVersion is not (null or 4 or 6)
                || r.IpVersion == 4 && src.AddressFamily != AddressFamily.InterNetwork
                || r.IpVersion == 6 && src.AddressFamily != AddressFamily.InterNetworkV6
                || r.SourcePort != 53 && r.DestinationPort != 53
                || r.ApplicationProtocol != null
                    && !string.Equals(r.ApplicationProtocol, "DNS", StringComparison.OrdinalIgnoreCase)
                || !(string.Equals(r.ApplicationProtocol, "DNS", StringComparison.OrdinalIgnoreCase)
                    || string.Equals(r.Protocol, "DNS", StringComparison.OrdinalIgnoreCase)))
                return false;

            var udp = r.IsUdp && !r.IsTcp && !r.TcpFlags.HasValue
                && (string.Equals(r.Protocol, "UDP", StringComparison.OrdinalIgnoreCase)
                    || string.Equals(r.Protocol, "DNS", StringComparison.OrdinalIgnoreCase));
            var tcp = r.IsTcp && !r.IsUdp
                && (string.Equals(r.Protocol, "TCP", StringComparison.OrdinalIgnoreCase)
                    || string.Equals(r.Protocol, "DNS", StringComparison.OrdinalIgnoreCase))
                && (!r.TcpFlags.HasValue
                    || (r.TcpFlags.Value & 0x07) == 0 && (r.TcpFlags.Value & 0x18) != 0);
            if (!udp && !tcp) return false;

            var name = r.DnsQname.Trim().TrimEnd('.');
            if (name.Length == 0 || (!singleLabel && name.IndexOf('.') < 0))
                return false;
            foreach (var label in name.Split('.'))
            {
                if (label.Length is < 1 or > 63 || label[0] == '-' || label[^1] == '-'
                    || label.Any(ch => !char.IsAsciiLetterOrDigit(ch) && ch != '-' && ch != '_'))
                    return false;
            }
            return true;
        }

        // A DNS answer field is not a free-text evidence channel. Only exact
        // address tokens of the declared A/AAAA family count. Documentation
        // ranges remain parseable to support deterministic offline fixtures;
        // this is not proof of globally routed fast-flux infrastructure.
        internal static int AddressAnswerCount(string? answers, string? qtype)
        {
            if (string.IsNullOrWhiteSpace(answers) || answers.Length > 2048
                || !(string.Equals(qtype, "A", StringComparison.OrdinalIgnoreCase)
                    || string.Equals(qtype, "AAAA", StringComparison.OrdinalIgnoreCase)))
                return 0;

            var family = string.Equals(qtype, "A", StringComparison.OrdinalIgnoreCase)
                ? AddressFamily.InterNetwork : AddressFamily.InterNetworkV6;
            var tokens = Regex.Split(answers, @"[\s,;|]+");
            if (tokens.Length > 128) return 0;
            var unique = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
            foreach (var raw in tokens)
            {
                if (raw.Length == 0 || raw.Equals("A", StringComparison.OrdinalIgnoreCase)
                    || raw.Equals("AAAA", StringComparison.OrdinalIgnoreCase)
                    || raw.Equals("IN", StringComparison.OrdinalIgnoreCase)) continue;
                var token = raw.StartsWith("A=", StringComparison.OrdinalIgnoreCase)
                    ? raw[2..] : raw.StartsWith("AAAA=", StringComparison.OrdinalIgnoreCase)
                    ? raw[5..] : raw;
                if (!IPAddress.TryParse(token, out var address) || address.AddressFamily != family)
                    continue;
                if (family == AddressFamily.InterNetwork
                    && !Regex.IsMatch(token, @"^\d{1,3}(?:\.\d{1,3}){3}$", RegexOptions.CultureInvariant))
                    continue;
                unique.Add(address.ToString());
            }
            return unique.Count;
        }

        internal static bool PrivateClient(string? address)
        {
            if (!IPAddress.TryParse(address, out var ip)) return false;
            var b = ip.GetAddressBytes();
            if (ip.AddressFamily == AddressFamily.InterNetwork)
                return b[0] == 10 || b[0] == 172 && b[1] is >= 16 and <= 31
                    || b[0] == 192 && b[1] == 168;
            return ip.AddressFamily == AddressFamily.InterNetworkV6 && (b[0] & 0xfe) == 0xfc;
        }

        // Conservative global-unicast filter for a destination resolver.
        // In particular, RFC1918, CGNAT, TEST-NET, loopback, link-local,
        // multicast, benchmark and documentation destinations are not public.
        internal static bool PublicResolver(string? address)
        {
            if (!IPAddress.TryParse(address, out var ip)) return false;
            var b = ip.GetAddressBytes();
            if (ip.AddressFamily == AddressFamily.InterNetwork)
            {
                if (b[0] is 0 or 10 or 127 or 169 || b[0] >= 224
                    || b[0] == 100 && b[1] is >= 64 and <= 127
                    || b[0] == 172 && b[1] is >= 16 and <= 31
                    || b[0] == 192 && (b[1] == 168 || b[1] == 0 || b[1] == 2)
                    || b[0] == 198 && (b[1] is 18 or 19 || b[1] == 51 && b[2] == 100)
                    || b[0] == 203 && b[1] == 0 && b[2] == 113)
                    return false;
                return true;
            }
            if (ip.AddressFamily != AddressFamily.InterNetworkV6
                || (b[0] & 0xe0) != 0x20 || ip.IsIPv6Multicast
                || ip.IsIPv6LinkLocal || ip.IsIPv6SiteLocal
                || b[0] == 0x20 && b[1] == 0x01 && b[2] == 0x0d && b[3] == 0xb8)
                return false;
            return true;
        }
    }
}
