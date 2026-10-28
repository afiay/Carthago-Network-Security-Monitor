// SPDX-License-Identifier: MIT
using System;
using System.Collections.Generic;
using System.Globalization;
using System.Linq;
using System.Net;
using Carthago.Models;

namespace Carthago.Engine.Rules.Expansion
{
    // Candidate-only typed evidence. Packet Info, generic port numbers and arbitrary
    // process substrings never establish protocol or Tor/VPN guard attribution.
    internal static class NetworkBatch261265Evidence
    {
        private static bool Private(string? value)
        {
            if (!IPAddress.TryParse(value, out var ip)) return false;
            var b = ip.GetAddressBytes();
            return b.Length == 4 && (b[0] == 10 || b[0] == 172 && b[1] >= 16 && b[1] <= 31
                || b[0] == 192 && b[1] == 168)
                || b.Length == 16 && (b[0] & 0xfe) == 0xfc;
        }
        internal static bool ValidFlow(TrafficRecord r)
            => r.Id != Guid.Empty && IPAddress.TryParse(r.Source, out var src)
                && IPAddress.TryParse(r.Destination, out var dst)
                && src.AddressFamily == dst.AddressFamily && !src.Equals(dst);
        private static bool ExternalTcp(TrafficRecord r)
            => ValidFlow(r) && Private(r.Source) && !Private(r.Destination)
                && IPAddress.TryParse(r.Destination, out var dst)
                && !IPAddress.IsLoopback(dst) && !dst.IsIPv6LinkLocal && !dst.IsIPv6Multicast
                && r.IsTcp && !r.IsUdp && !r.IsQuic
                && string.Equals(r.Protocol, "TCP", StringComparison.OrdinalIgnoreCase)
                && r.SourcePort is > 0 and <= 65535 && r.DestinationPort is > 0 and <= 65535
                && r.IcmpTypeCode == null;
        internal static bool Ttl(TrafficRecord r, out int ttl)
        {
            ttl = 0;
            return ValidFlow(r) && (r.IpVersion == 4 || r.IpVersion == 6)
                && int.TryParse(r.TTL, NumberStyles.None, CultureInfo.InvariantCulture, out ttl)
                && ttl is >= 1 and <= 255 && r.HttpMethod == null
                && r.IcmpTypeCode == null && r.TlsVersion == null;
        }
        internal static bool TinyFragment(TrafficRecord r)
            => ValidFlow(r) && r.IpVersion == 4
                && r.IpFragmentOffset is > 0 and <= 8191 && r.IpMoreFragments == true
                && r.IpFragmentPayloadLength is > 0 and <= 24
                && r.HttpMethod == null && r.TlsVersion == null && r.DnsQname == null
                && r.ApplicationProtocol == null && r.IcmpTypeCode == null
                && r.TcpFlags == null && !r.IsTcp && !r.IsUdp;
        private static string BaseName(string? value)
        {
            if (string.IsNullOrWhiteSpace(value) || value.Length > 260) return "";
            return value.Trim().Replace('\\', '/').Split('/').Last().ToLowerInvariant();
        }
        internal static bool ProxyProcessEgress(TrafficRecord r, out string process)
        {
            process = BaseName(r.ProcessName);
            return ExternalTcp(r) && new[] { "ngrok.exe", "cloudflared.exe", "frpc.exe",
                "chisel.exe", "ligolo.exe", "sshuttle", "socat.exe", "mitmproxy.exe" }.Contains(process)
                && r.HttpMethod == null && r.DnsQname == null && r.IcmpTypeCode == null;
        }
        internal static bool TorProcessEgress(TrafficRecord r, out string process)
        {
            process = BaseName(r.ProcessName);
            return ExternalTcp(r) && (process == "tor.exe" || process == "arti.exe" || process == "tor")
                && r.HttpMethod == null && r.DnsQname == null && r.IcmpTypeCode == null;
        }
        private static readonly (string Domain, string Label)[] Providers = {
            ("nordvpn.com", "nordvpn"), ("protonvpn.com", "protonvpn"),
            ("mullvad.net", "mullvad"), ("expressvpn.com", "expressvpn"),
            ("surfshark.com", "surfshark"), ("windscribe.com", "windscribe")
        };
        internal static bool ProviderTls(TrafficRecord r, out string provider)
        {
            provider = "";
            if (!ExternalTcp(r) || string.IsNullOrWhiteSpace(r.TlsVersion)
                || r.HttpMethod != null || r.DnsQname != null || r.ApplicationProtocol == "HTTP"
                || string.IsNullOrWhiteSpace(r.Sni)) return false;
            var host = r.Sni!.Trim().TrimEnd('.').ToLowerInvariant();
            if (host.Length > 253 || host.Any(c => !(char.IsAsciiLetterOrDigit(c) || c is '.' or '-')))
                return false;
            foreach (var entry in Providers)
                if (host == entry.Domain || host.EndsWith("." + entry.Domain, StringComparison.Ordinal))
                {
                    provider = entry.Label;
                    return true;
                }
            return false;
        }
        internal sealed class TtlWindow
        {
            private sealed class Slot
            {
                internal readonly Queue<(Guid Id, DateTime At, int Ttl)> Items = new();
                internal readonly HashSet<Guid> Seen = new();
                internal DateTime Latest = DateTime.MinValue;
            }
            private readonly object _gate = new();
            private readonly Dictionary<string, Slot> _slots = new(StringComparer.OrdinalIgnoreCase);
            internal int Observe(TrafficRecord r, DateTime at, string key, int ttl)
            {
                lock (_gate)
                {
                    if (!_slots.TryGetValue(key, out var slot))
                    {
                        if (_slots.Count >= 512)
                        {
                            foreach (var stale in _slots.Where(x => at - x.Value.Latest > TimeSpan.FromMinutes(15))
                                .Select(x => x.Key).ToArray()) _slots.Remove(stale);
                            if (_slots.Count >= 512) return 0;
                        }
                        _slots.Add(key, slot = new Slot());
                    }
                    if (at < slot.Latest || slot.Seen.Contains(r.Id)) return 0;
                    while (slot.Items.Count > 0 && at - slot.Items.Peek().At > TimeSpan.FromMinutes(15))
                    {
                        var old = slot.Items.Dequeue(); slot.Seen.Remove(old.Id);
                    }
                    if (slot.Items.Count >= 256) return 0;
                    slot.Items.Enqueue((r.Id, at, ttl)); slot.Seen.Add(r.Id); slot.Latest = at;
                    if (slot.Items.Count < 3) return 0;
                    return slot.Items.Max(x => x.Ttl) - slot.Items.Min(x => x.Ttl) >= 16
                        ? slot.Items.Count : 0;
                }
            }
        }
    }
}
