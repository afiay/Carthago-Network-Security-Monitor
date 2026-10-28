// SPDX-License-Identifier: MIT
using System;
using System.Threading;
using Carthago.Engine.Rules;
using Carthago.Models;
using Carthago.Services;

namespace Carthago.Tests;
internal static class NetworkBatch221225Context
{
    private static int _source = 20;
    internal static readonly DateTime Origin = new(2026, 10, 28, 5, 30, 0, DateTimeKind.Utc);
    internal static RuleEvaluationContext At(TrafficRecord r, int seconds = 0)
        => new(r, Sensitivity.Balanced, Origin.AddSeconds(seconds));
    internal static TrafficRecord Flow(int rule)
    {
        var r = new TrafficRecord
        {
            Id = Guid.NewGuid(),
            Source = "10." + rule + ".0." + Interlocked.Increment(ref _source),
            Destination = rule <= 223 ? "198.51.100.223" : "10." + (rule + 1) + ".0.20",
            IpVersion = 4, SourcePort = 51000,
            DestinationPort = rule == 221 || rule == 222 ? 443 : rule == 225 ? 102 : 20000,
            Protocol = "TCP", IsTcp = true, IsUdp = false,
            Length = 1024, L4Len = 512, Info = "",
            ProcessName = rule == 221 ? "anydesk.exe" : rule == 222 ? "tailscale.exe" : null,
            Sni = rule == 221 ? "relay.anydesk.com" : rule == 222 ? "controlplane.tailscale.com" : null,
            ApplicationProtocol = rule == 223 || rule == 224 ? "DNP3" : rule == 225 ? "S7comm" : null,
            ApplicationService = rule == 223 || rule == 224 ? "DNP3" : rule == 225 ? "S7comm" : null
        };
        return r;
    }
}
