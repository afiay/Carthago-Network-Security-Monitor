// SPDX-License-Identifier: MIT
using System;
using System.Net;
using System.Net.Sockets;
using Carthago.Models;
using Carthago.Services;

namespace Carthago.Engine.Rules.Expansion
{
    // Only corroborate independently sourced classifications for the SAME
    // observed source IP. This is a typed contract; it does not create a feed
    // hit, trigger a reputation lookup, or attest to attack success.
    internal static class NetworkBatch271275Evidence
    {
        internal static bool HasSourceOverlap(TrafficRecord r, MatchInfo? hit,
            DateTimeOffset snapshotBuiltAt, DateTime observedUtc)
        {
            if (hit == null || observedUtc.Kind != DateTimeKind.Utc
                || r.Id == Guid.Empty || r.IpVersion != 4
                || !IPAddress.TryParse(r.Source, out var source)
                || !IPAddress.TryParse(r.Destination, out var destination)
                || source.AddressFamily != AddressFamily.InterNetwork
                || destination.AddressFamily != AddressFamily.InterNetwork
                || !IsRoutableSource(source) || !IsPrivateDestination(destination)
                || !r.IsTcp || r.IsUdp || r.IsQuic
                || !string.Equals(r.Protocol, "TCP", StringComparison.OrdinalIgnoreCase)
                || r.SourcePort is not (> 0 and <= 65535)
                || r.DestinationPort is not (> 0 and <= 65535)
                || r.IcmpTypeCode != null || r.DnsQname != null || r.DnsIsResponse
                || r.ReputationIsMalicious != true
                || r.ReputationScore is not (>= 75 and <= 100)
                || r.ReputationReports is not (>= 2)
                || r.ReputationLastSeen is not DateTime lastSeen
                || lastSeen.Kind != DateTimeKind.Utc
                || lastSeen > observedUtc
                || observedUtc - lastSeen > TimeSpan.FromDays(30)
                || hit.Kind != IndicatorKind.IPv4
                || !IPAddress.TryParse(hit.Value, out var feedAddress)
                || !source.Equals(feedAddress)
                || hit.Confidence < 75 || hit.Sources == null || hit.Sources.Length == 0
                || snapshotBuiltAt == default)
                return false;

            var age = new DateTimeOffset(observedUtc) - snapshotBuiltAt;
            return age >= TimeSpan.Zero && age <= TimeSpan.FromHours(48);
        }

        private static bool IsPrivateDestination(IPAddress ip)
        {
            var b = ip.GetAddressBytes();
            return b[0] == 10 || (b[0] == 172 && b[1] >= 16 && b[1] <= 31)
                || (b[0] == 192 && b[1] == 168);
        }

        private static bool IsRoutableSource(IPAddress ip)
        {
            var b = ip.GetAddressBytes();
            if (b[0] == 0 || b[0] == 10 || b[0] == 127 || b[0] >= 224
                || b[0] == 169 && b[1] == 254
                || b[0] == 172 && b[1] >= 16 && b[1] <= 31
                || b[0] == 192 && b[1] == 168
                || b[0] == 100 && b[1] >= 64 && b[1] <= 127
                || b[0] == 192 && b[1] == 0 && b[2] == 2
                || b[0] == 198 && b[1] == 51 && b[2] == 100
                || b[0] == 203 && b[1] == 0 && b[2] == 113)
                return false;
            return true;
        }
    }
}
