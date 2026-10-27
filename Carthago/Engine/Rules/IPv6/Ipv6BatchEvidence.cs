// SPDX-License-Identifier: MIT
using System;
using System.Collections.Generic;
using System.Globalization;
using System.Linq;
using System.Net;
using System.Net.Sockets;
using Carthago.Engine.Rules;
using Carthago.Engine.Rules.AssetInventory;
using Carthago.Models;

namespace Carthago.Engine.Rules.IPv6
{
    // No textual packet descriptions are accepted as proof of ICMPv6 types,
    // neighbor targets or tunnel protocols. The current capture model has no
    // structured ND target; consequently multicast NS is intentionally excluded.
    internal static class Ipv6BatchEvidence
    {
        internal static bool Address(string? text, out IPAddress address)
        {
            address = IPAddress.IPv6Any;
            if (!IPAddress.TryParse(text, out var parsed)) return false;
            address = parsed;
            return address.AddressFamily == AddressFamily.InterNetworkV6
                && !address.IsIPv4MappedToIPv6 && !address.IsIPv6Multicast
                && !address.Equals(IPAddress.IPv6Any);
        }
        internal static bool Neighbor(TrafficRecord r, int type)
            => r.IpVersion == 6 && string.Equals(r.Protocol, "ICMPv6", StringComparison.OrdinalIgnoreCase)
                && r.IcmpTypeCode == (ushort)(type << 8)
                && string.Equals(r.TTL?.Trim(), "255", StringComparison.Ordinal)
                && !r.SourcePort.HasValue && !r.DestinationPort.HasValue
                && !r.IsTcp && !r.IsUdp;

        internal static bool Mac(string? text, out string mac)
        {
            mac = "";
            var parts = text?.Split(new[] { ':', '-' }, StringSplitOptions.None);
            if (parts?.Length != 6 || parts.Any(p => p.Length != 2)) return false;
            var bytes = new byte[6];
            for (var i = 0; i < bytes.Length; i++)
                if (!byte.TryParse(parts[i], NumberStyles.HexNumber,
                    CultureInfo.InvariantCulture, out bytes[i])) return false;
            if ((bytes[0] & 1) != 0 || bytes.All(b => b == 0)) return false;
            mac = string.Join(":", bytes.Select(b => b.ToString("X2", CultureInfo.InvariantCulture)));
            return true;
        }

        internal static bool RouterAdvertisement(TrafficRecord r, out string router, out string mac)
        {
            router = mac = "";
            if (!Neighbor(r, 134) || !Address(r.Source, out var src) || !src.IsIPv6LinkLocal
                || !IPAddress.TryParse(r.Destination, out var dst)
                || !dst.Equals(IPAddress.Parse("ff02::1")) || !Mac(r.MacSource, out mac))
                return false;
            router = src.ToString();
            return true;
        }

        internal static bool NeighborSolicitation(TrafficRecord r, out string source, out string target)
        {
            source = target = "";
            if (!Neighbor(r, 135) || !Address(r.Source, out var src)
                || !Address(r.Destination, out var dst) || src.Equals(dst)
                || dst.IsIPv6LinkLocal)
                return false;
            // Unicast NS only: the multicast destination is NOT the ND target.
            source = src.ToString();
            target = dst.ToString();
            return true;
        }

        internal static bool NeighborAdvertisement(TrafficRecord r, out string address, out string mac)
        {
            address = mac = "";
            if (!Neighbor(r, 136) || !Address(r.Source, out var src)
                || !Mac(r.MacSource, out mac) || !IPAddress.TryParse(r.Destination, out var dst)
                || dst.AddressFamily != AddressFamily.InterNetworkV6)
                return false;
            // The current record lacks a parsed NA target. Require the
            // capture-path target annotation to agree with the packet source.
            // This is corroboration, not independent structured target proof.
            var expected = "target=" + src;
            if (!string.Equals(r.Info?.Trim(), expected, StringComparison.OrdinalIgnoreCase))
                return false;
            address = src.ToString();
            return true;
        }

        internal static bool Transition(TrafficRecord r, out string kind, out string flow)
        {
            kind = flow = "";
            if (r.IpVersion == 4 && string.Equals(r.Protocol, "UDP", StringComparison.OrdinalIgnoreCase)
                && string.Equals(r.ApplicationProtocol, "Teredo", StringComparison.OrdinalIgnoreCase)
                && (r.SourcePort == 3544 || r.DestinationPort == 3544)
                && AssetNetworkEvidence.Public(r.Source, out var src4)
                && AssetNetworkEvidence.Public(r.Destination, out var dst4))
            {
                kind = "Teredo"; flow = src4 + ">" + dst4;
                return true;
            }
            if (r.IpVersion != 6 || !Address(r.Source, out var src)
                || !Address(r.Destination, out var dst)
                || !(string.Equals(r.Protocol, "TCP", StringComparison.OrdinalIgnoreCase)
                    || string.Equals(r.Protocol, "UDP", StringComparison.OrdinalIgnoreCase)
                    || string.Equals(r.Protocol, "ICMPv6", StringComparison.OrdinalIgnoreCase)))
                return false;
            var a = src.GetAddressBytes();
            var b = dst.GetAddressBytes();
            if (string.Equals(r.ApplicationProtocol, "6to4", StringComparison.OrdinalIgnoreCase)
                && (a[0] == 0x20 && a[1] == 0x02 || b[0] == 0x20 && b[1] == 0x02))
                kind = "6to4";
            else if (string.Equals(r.ApplicationProtocol, "ISATAP", StringComparison.OrdinalIgnoreCase)
                && (IsIsatap(a) || IsIsatap(b)))
                kind = "ISATAP";
            else if (string.Equals(r.ApplicationProtocol, "Teredo", StringComparison.OrdinalIgnoreCase)
                && (a[0] == 0x20 && a[1] == 0x01 && a[2] == 0 && a[3] == 0
                    || b[0] == 0x20 && b[1] == 0x01 && b[2] == 0 && b[3] == 0))
                kind = "Teredo";
            if (kind.Length == 0) return false;
            flow = src + ">" + dst;
            return true;
        }
        private static bool IsIsatap(byte[] a)
            => (a[8] == 0 || a[8] == 2) && a[9] == 0 && a[10] == 0x5e && a[11] == 0xfe;

        internal static DetectionEvent Alert(RuleDescriptor d, RuleEvaluationContext c, string message)
        {
            var e = AssetNetworkEvidence.Alert(d, c, message);
            e.Evidence = "Structured packet type, endpoint and temporal corroboration; no raw packet text or MAC retained.";
            return e;
        }
    }

    internal sealed class Ipv6DistinctWindow
    {
        private sealed class Entry
        {
            internal DateTime Last;
            internal readonly Dictionary<string, DateTime> Targets = new(StringComparer.Ordinal);
            internal bool Reported;
        }
        private readonly Dictionary<string, Entry> _entries = new(StringComparer.Ordinal);
        private readonly object _gate = new();
        internal bool Observe(string source, string target, DateTime now, int threshold, TimeSpan window)
        {
            lock (_gate)
            {
                if (!_entries.TryGetValue(source, out var entry))
                {
                    if (_entries.Count >= 1024)
                        _entries.Remove(_entries.OrderBy(p => p.Value.Last).First().Key);
                    _entries[source] = entry = new Entry();
                }
                if (now <= entry.Last) return false;
                entry.Last = now;
                foreach (var stale in entry.Targets.Where(p => now - p.Value > window)
                    .Select(p => p.Key).ToArray()) entry.Targets.Remove(stale);
                if (entry.Targets.Count < threshold) entry.Reported = false;
                if (entry.Targets.Count >= 256 && !entry.Targets.ContainsKey(target))
                    entry.Targets.Remove(entry.Targets.OrderBy(p => p.Value).First().Key);
                entry.Targets[target] = now;
                if (entry.Targets.Count < threshold || entry.Reported) return false;
                entry.Reported = true;
                return true;
            }
        }
    }

    internal sealed class Ipv6SequenceState
    {
        private sealed class Entry
        {
            internal DateTime First;
            internal DateTime Last;
            internal bool Reported;
        }
        private readonly Dictionary<string, Entry> _entries = new(StringComparer.Ordinal);
        private readonly object _gate = new();
        internal bool Observe(string key, DateTime now)
        {
            lock (_gate)
            {
                if (!_entries.TryGetValue(key, out var entry))
                {
                    if (_entries.Count >= 2048)
                        _entries.Remove(_entries.OrderBy(p => p.Value.Last).First().Key);
                    _entries[key] = new Entry { First = now, Last = now };
                    return false;
                }
                if (now <= entry.Last) return false;
                if (now - entry.Last > TimeSpan.FromMinutes(10)
                    || !entry.Reported && now - entry.First > TimeSpan.FromMinutes(2))
                {
                    entry.First = entry.Last = now;
                    entry.Reported = false;
                    return false;
                }
                entry.Last = now;
                if (entry.Reported) return false;
                entry.Reported = true;
                return true;
            }
        }
    }
}
