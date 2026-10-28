// SPDX-License-Identifier: MIT
using System;
using Carthago.Engine.Rules;
using Carthago.Models;

namespace Carthago.Tests;
internal static class NetworkBatch261265Context
{
    internal static readonly DateTime Origin = new(2026, 10, 28, 14, 0, 0, DateTimeKind.Utc);
    internal static RuleEvaluationContext At(TrafficRecord r, double seconds = 0)
        => new(r, Sensitivity.Balanced, Origin.AddSeconds(seconds));
    internal static TrafficRecord Sample(int rule)
    {
        var r = new TrafficRecord {
            Id = Guid.NewGuid(), Source = "10.61.0.10", Destination = "198.51.100.61",
            IpVersion = 4, SourcePort = 50000, DestinationPort = 443,
            Protocol = "TCP", IsTcp = true, TTL = "64", Info = ""
        };
        if (rule == 262) {
            r.IsTcp = false; r.Protocol = "IPv4"; r.SourcePort = null; r.DestinationPort = null;
            r.TTL = "64"; r.IpFragmentOffset = 1; r.IpMoreFragments = true;
            r.IpFragmentPayloadLength = 16;
        }
        if (rule == 263) r.ProcessName = "ngrok.exe";
        if (rule == 264) r.ProcessName = "tor.exe";
        if (rule == 265) { r.Sni = "api.nordvpn.com"; r.TlsVersion = "TLS1.3"; }
        return r;
    }
}
