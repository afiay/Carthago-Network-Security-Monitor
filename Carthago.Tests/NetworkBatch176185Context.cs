// SPDX-License-Identifier: MIT
using System;
using Carthago.Engine.Rules;
using Carthago.Models;
using Carthago.Services;
namespace Carthago.Tests;
internal static class NetworkBatch176185Context
{
    internal static readonly DateTime Origin = new(2026, 10, 28, 1, 0, 0, DateTimeKind.Utc);
    internal static RuleEvaluationContext At(TrafficRecord r, int seconds = 0)
        => new(r, Sensitivity.Balanced, Origin.AddSeconds(seconds));
    internal static TrafficRecord Http(string path = "/upload", string method = "POST")
        => NetworkBatch166175Context.Http(path, method);
    internal static TrafficRecord Dns(string name, string type = "A")
        => new() { Id = Guid.NewGuid(), Source = "10.176.0.10", Destination = "8.8.8.8",
            IpVersion = 4, SourcePort = 53000, DestinationPort = 53,
            Protocol = "DNS", ApplicationProtocol = "DNS", IsUdp = true,
            DnsQname = name, DnsQtype = type, Length = 84, L4Len = 56 };
}
