// SPDX-License-Identifier: MIT
using System;
using System.Collections.Generic;
using System.Linq;
using System.Net;
using System.Net.Sockets;
using Carthago.Engine.Rules.AssetInventory;
using Carthago.Models;

namespace Carthago.Engine.Rules
{
    // Typed evidence only. Raw packet Info, MAC and application text are never copied into alerts.
    internal static class NetworkBatch071075Evidence
    {
        internal static bool Tcp(RuleEvaluationContext c, int port, out string source, out string destination)
        {
            source = destination = "";
            var r = c.Record;
            if (r.IpVersion.HasValue && r.IpVersion != 4
                || !AssetNetworkEvidence.Private(r.Source, out source)
                || !AssetNetworkEvidence.Private(r.Destination, out destination) || source == destination
                || !string.Equals(r.Protocol, "TCP", StringComparison.OrdinalIgnoreCase)
                || r.IsUdp || r.IsQuic || r.IcmpTypeCode.HasValue
                || r.DnsIsResponse || r.DnsQname != null || r.HttpMethod != null
                || r.DestinationPort != port || r.SourcePort is not int sp || sp is < 1 or > 65535
                || r.TcpFlags is not ushort flags || (flags & 0x1f) != 0x02) return false;
            return true;
        }
        internal static bool Multicast(TrafficRecord r, out string source, out string service)
        {
            source = service = "";
            if (r.IpVersion != 6 || !string.Equals(r.Protocol, "UDP", StringComparison.OrdinalIgnoreCase)
                || r.IsTcp || r.IsQuic || r.IcmpTypeCode.HasValue || r.TcpFlags.HasValue
                || r.SourcePort is not int sp || sp is < 1 or > 65535
                || !IPAddress.TryParse(r.Source, out var src)
                || src.AddressFamily != AddressFamily.InterNetworkV6
                || src.IsIPv6Multicast || src.Equals(IPAddress.IPv6Any) || src.Equals(IPAddress.IPv6Loopback)
                || !IPAddress.TryParse(r.Destination, out var dst) || !dst.IsIPv6Multicast) return false;
            service = (dst.ToString(), r.DestinationPort) switch
            {
                ("ff02::fb", 5353) => "mDNS",
                ("ff02::1:3", 5355) => "LLMNR",
                ("ff02::c", 1900) => "SSDP",
                _ => ""
            };
            source = src.ToString();
            return service.Length > 0;
        }
        internal static bool Ipv6Policy(TrafficRecord r, out string flow)
        {
            flow = "";
            if (r.IpVersion != 6 || !string.Equals(r.NetworkType?.Trim(), "IPv4Only", StringComparison.OrdinalIgnoreCase)
                || !IPAddress.TryParse(r.Source, out var src) || !IPAddress.TryParse(r.Destination, out var dst)
                || src.AddressFamily != AddressFamily.InterNetworkV6 || dst.AddressFamily != AddressFamily.InterNetworkV6
                || src.IsIPv4MappedToIPv6 || dst.IsIPv4MappedToIPv6 || src.IsIPv6Multicast || dst.IsIPv6Multicast
                || src.IsIPv6LinkLocal || dst.IsIPv6LinkLocal || src.Equals(IPAddress.IPv6Any)
                || dst.Equals(IPAddress.IPv6Any) || src.Equals(IPAddress.IPv6Loopback)
                || dst.Equals(IPAddress.IPv6Loopback) || src.Equals(dst)
                || r.SourcePort is not int sp || sp is < 1 or > 65535
                || r.DestinationPort is not int dp || dp is < 1 or > 65535
                || r.IcmpTypeCode.HasValue || r.DnsIsResponse || r.DnsQname != null) return false;
            if (string.Equals(r.Protocol, "TCP", StringComparison.OrdinalIgnoreCase))
            { if (r.IsUdp || r.IsQuic) return false; }
            else if (string.Equals(r.Protocol, "UDP", StringComparison.OrdinalIgnoreCase))
            { if (r.IsTcp || r.TcpFlags.HasValue) return false; }
            else return false;
            flow = src + ">" + dst;
            return true;
        }
        internal static DetectionEvent Alert(RuleDescriptor d, RuleEvaluationContext c, string message)
        {
            var e = AssetNetworkEvidence.Alert(d, c, message);
            e.Evidence = "Corroborated typed endpoint, transport and temporal evidence; authorization not inferred; raw payload excluded.";
            return e;
        }
    }
    // Per-rule-instance, bounded, thread-safe window. Distinct destinations or distinct observation times.
    internal sealed class NetworkBatch071075Window
    {
        private sealed class Entry
        {
            internal DateTime Last;
            internal readonly Dictionary<string, DateTime> Seen = new(StringComparer.Ordinal);
            internal bool Reported;
        }
        private readonly Dictionary<string, Entry> _entries = new(StringComparer.Ordinal);
        private readonly object _gate = new();
        internal bool Observe(string key, string value, DateTime now, int threshold, TimeSpan window)
        {
            lock (_gate)
            {
                if (!_entries.TryGetValue(key, out var entry))
                {
                    if (_entries.Count >= 2048)
                        _entries.Remove(_entries.OrderBy(x => x.Value.Last).First().Key);
                    _entries[key] = entry = new Entry();
                }
                if (now <= entry.Last) return false;
                entry.Last = now;
                foreach (var stale in entry.Seen.Where(x => now - x.Value > window).Select(x => x.Key).ToArray())
                    entry.Seen.Remove(stale);
                if (entry.Seen.Count < threshold) entry.Reported = false;
                if (entry.Seen.Count >= 4096 && !entry.Seen.ContainsKey(value))
                    entry.Seen.Remove(entry.Seen.OrderBy(x => x.Value).First().Key);
                entry.Seen[value] = now;
                if (entry.Seen.Count < threshold || entry.Reported) return false;
                entry.Reported = true;
                return true;
            }
        }
    }
}
