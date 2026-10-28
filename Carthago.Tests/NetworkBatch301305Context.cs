// SPDX-License-Identifier: MIT
using System;
using Carthago.Engine.Rules;
using Carthago.Models;
namespace Carthago.Tests;
internal static class NetworkBatch301305Context
{
    internal static readonly DateTime Origin = new(2026, 10, 28, 22, 0, 0, DateTimeKind.Utc);
    internal static RuleEvaluationContext At(TrafficRecord r, double seconds = 0)
        => new(r, Sensitivity.Balanced, Origin.AddSeconds(seconds));
    internal static TrafficRecord Sample() => new()
    {
        Id = Guid.NewGuid(), Source = "185.220.100.254", Destination = "10.61.0.10",
        IpVersion = 4, Protocol = "TCP", IsTcp = true, SourcePort = 51000, DestinationPort = 80,
        ApplicationProtocol = "HTTP", HttpMethod = "GET", HttpHost = "example.net", HttpUri = "/", Info = ""
    };
}
