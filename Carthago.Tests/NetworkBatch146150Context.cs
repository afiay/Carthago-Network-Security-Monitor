// SPDX-License-Identifier: MIT
using System;
using Carthago.Engine.Rules;
using Carthago.Models;
using Carthago.Services;

namespace Carthago.Tests;

internal static class NetworkBatch146150Context
{
    private static readonly DateTime Origin = new(2026, 10, 27, 13, 0, 0, DateTimeKind.Utc);
    internal static RuleEvaluationContext At(TrafficRecord r, int seconds = 0)
        => new(r, Sensitivity.Balanced, Origin.AddSeconds(seconds));

    internal static TrafficRecord Tls(string sni = "stage.example.test")
        => new()
        {
            Source = "10.146.0.10", Destination = "198.51.100.146",
            IpVersion = 4, SourcePort = 51460, DestinationPort = 443,
            Protocol = "TLS", ApplicationProtocol = "TLS",
            ApplicationService = "HTTPS", IsTcp = true,
            Sni = sni, TlsVersion = "TLS 1.2",
            Ja4 = "ja4-client-146", ProcessName = "service-agent.exe",
            Length = 1024, L4Len = 1024, Info = "normal tls session"
        };
}
