// SPDX-License-Identifier: MIT
using System;
using System.Collections.Generic;
using System.Net;
using Carthago.Models;

namespace Carthago.Engine.Rules.Expansion
{
    // Conservative typed contracts. Info and port-derived ApplicationService
    // are never sufficient evidence of an OT/MQTT operation.
    internal static class NetworkBatch226230Evidence
    {
        private static bool Flow(TrafficRecord r, bool tcp)
            => r.Id != Guid.Empty && r.IsTcp == tcp && r.IsUdp != tcp
               && !r.IsQuic && r.HttpMethod == null && r.DnsQname == null
               && r.TlsVersion == null
               && string.Equals(r.Protocol, tcp ? "TCP" : "UDP", StringComparison.OrdinalIgnoreCase)
               && IPAddress.TryParse(r.Source, out _) && IPAddress.TryParse(r.Destination, out _);

        private static bool Port(TrafficRecord r, int port)
            => r.SourcePort == port || r.DestinationPort == port;

        internal static bool CipDiscovery(TrafficRecord r)
            => (Flow(r, true) || Flow(r, false)) && Port(r, 44818)
               && string.Equals(r.ApplicationProtocol, "ethernetip.listidentity", StringComparison.OrdinalIgnoreCase);

        // DCP is Ethernet layer 2, NOT UDP/34964 (Profinet RT). The current
        // PacketHandler only produces IP records; this is a future L2 adapter
        // contract, not a claim of live DCP visibility.
        internal static bool ProfinetDcp(TrafficRecord r)
            => r.Id != Guid.Empty && !r.IsTcp && !r.IsUdp && !r.IsQuic
               && r.HttpMethod == null && r.DnsQname == null
               && r.SourcePort == null && r.DestinationPort == null
               && string.Equals(r.Protocol, "PROFINET-DCP", StringComparison.OrdinalIgnoreCase)
               && string.Equals(r.ApplicationProtocol, "profinet.dcp.identify", StringComparison.OrdinalIgnoreCase)
               && ValidMac(r.MacSource) && ValidMac(r.MacDestination);

        private static bool ValidMac(string? value)
        {
            if (string.IsNullOrWhiteSpace(value)) return false;
            var parts = value.Split(':');
            if (parts.Length != 6) return false;
            foreach (var part in parts)
                if (part.Length != 2 || !byte.TryParse(part, System.Globalization.NumberStyles.HexNumber,
                    System.Globalization.CultureInfo.InvariantCulture, out _)) return false;
            return true;
        }

        internal static bool OpcUaEgress(TrafficRecord r)
            => Flow(r, true) && Port(r, 4840)
               && string.Equals(r.ApplicationProtocol, "opcua", StringComparison.OrdinalIgnoreCase)
               && Private(r.Source) && Public(r.Destination);

        private static bool Private(string? value)
        {
            if (!IPAddress.TryParse(value, out var ip)) return false;
            var b = ip.GetAddressBytes();
            if (b.Length == 4)
                return b[0] == 10 || b[0] == 172 && b[1] is >= 16 and <= 31
                    || b[0] == 192 && b[1] == 168;
            return b.Length == 16 && (b[0] & 0xfe) == 0xfc;
        }

        internal static bool Public(string? value)
        {
            if (!IPAddress.TryParse(value, out var ip) || IPAddress.IsLoopback(ip)
                || ip.IsIPv6Multicast || ip.IsIPv6LinkLocal) return false;
            var b = ip.GetAddressBytes();
            if (b.Length == 16) return (b[0] & 0xfe) != 0xfc;
            return b[0] is > 0 and < 224 && b[0] != 10 && b[0] != 127
                && !(b[0] == 172 && b[1] is >= 16 and <= 31)
                && !(b[0] == 192 && b[1] == 168)
                && !(b[0] == 169 && b[1] == 254)
                && !(b[0] == 100 && b[1] is >= 64 and <= 127);
        }

        internal static bool RetainedPublish(TrafficRecord r)
            => Flow(r, true) && Port(r, 1883)
               && string.Equals(r.ApplicationProtocol, "mqtt.publish", StringComparison.OrdinalIgnoreCase)
               && r.MqttRetain == true && r.MqttPublishTopicObserved;

        internal static bool LastWill(TrafficRecord r)
            => Flow(r, true) && Port(r, 1883)
               && string.Equals(r.ApplicationProtocol, "mqtt.connect", StringComparison.OrdinalIgnoreCase)
               && r.MqttWillTopicObserved;

        // Instance-owned, bounded, duplicate-resistant and monotonic event
        // windows. Saturation fails closed rather than inflating counts.
        internal sealed class Window
        {
            private sealed class Bucket
            {
                internal readonly Dictionary<Guid, DateTime> Packets = new();
                internal readonly Dictionary<string, DateTime> Targets = new(StringComparer.OrdinalIgnoreCase);
                internal DateTime Latest;
            }

            private readonly object _gate = new();
            private readonly Dictionary<string, Bucket> _buckets = new(StringComparer.OrdinalIgnoreCase);
            internal int Observe(string? source, string? target, Guid id, DateTime now, TimeSpan window, bool distinctTargets)
            {
                if (string.IsNullOrWhiteSpace(source) || string.IsNullOrWhiteSpace(target)
                    || id == Guid.Empty) return 0;
                lock (_gate)
                {
                    if (!_buckets.TryGetValue(source, out var bucket))
                    {
                        if (_buckets.Count >= 4096)
                        {
                            var stale = new List<string>();
                            foreach (var entry in _buckets)
                                if (now - entry.Value.Latest > window) stale.Add(entry.Key);
                            foreach (var key in stale) _buckets.Remove(key);
                            if (_buckets.Count >= 4096) return 0;
                        }
                        bucket = new Bucket { Latest = now };
                        _buckets.Add(source, bucket);
                    }
                    if (now < bucket.Latest || bucket.Packets.ContainsKey(id)) return 0;
                    var expired = new List<Guid>();
                    foreach (var entry in bucket.Packets)
                        if (now - entry.Value > window) expired.Add(entry.Key);
                    foreach (var old in expired) bucket.Packets.Remove(old);
                    var oldTargets = new List<string>();
                    foreach (var entry in bucket.Targets)
                        if (now - entry.Value > window) oldTargets.Add(entry.Key);
                    foreach (var old in oldTargets) bucket.Targets.Remove(old);
                    if (bucket.Packets.Count >= 512 || bucket.Targets.Count >= 512) return 0;
                    bucket.Packets.Add(id, now);
                    bucket.Targets[target] = now;
                    bucket.Latest = now;
                    return distinctTargets ? bucket.Targets.Count : bucket.Packets.Count;
                }
            }
        }
    }
}
