// SPDX-License-Identifier: MIT
using System;
using Carthago.Engine.Rules;
using Carthago.Models;
using Carthago.Services;

namespace Carthago.Tests;
internal static class NetworkBatch186195Context
{
    internal static readonly DateTime Origin = new(2026, 10, 28, 2, 0, 0, DateTimeKind.Utc);
    internal static RuleEvaluationContext At(TrafficRecord r, int seconds = 0)
        => new(r, Sensitivity.Balanced, Origin.AddSeconds(seconds));
    internal static TrafficRecord Query(string name, string type = "A")
        => new() { Id = Guid.NewGuid(), Source = "10.186.0.10", Destination = "8.8.8.8",
            IpVersion = 4, SourcePort = 53000, DestinationPort = 53,
            Protocol = "DNS", ApplicationProtocol = "DNS", IsUdp = true,
            DnsQname = name, DnsQtype = type, Length = 84, L4Len = 56 };
    internal static TrafficRecord Response(string name, int ttl = 0)
        => new() { Id = Guid.NewGuid(), Source = "8.8.8.8", Destination = "10.186.0.10",
            IpVersion = 4, SourcePort = 53, DestinationPort = 53000,
            Protocol = "DNS", ApplicationProtocol = "DNS", IsUdp = true,
            DnsQname = name, DnsQtype = "A", DnsIsResponse = true, DnsTtl = ttl, DnsRcode = "NOERROR" };
}
