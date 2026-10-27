// SPDX-License-Identifier: MIT
using System;
using Carthago.Engine.Rules;
using Carthago.Models;
using Carthago.Services;

namespace Carthago.Tests;

internal static class NetworkBatch151155Context
{
    internal static readonly DateTime Origin = new(2026, 10, 27, 14, 0, 0, DateTimeKind.Utc);
    internal static RuleEvaluationContext At(TrafficRecord record, int seconds = 0)
        => new(record, Sensitivity.Balanced, Origin.AddSeconds(seconds));

    internal static TrafficRecord Tls()
        => new()
        {
            Source = "10.151.0.10", Destination = "198.51.100.151",
            IpVersion = 4, SourcePort = 51510, DestinationPort = 9443,
            Protocol = "TLS", ApplicationProtocol = "TLS", ApplicationService = "HTTPS",
            IsTcp = true, Sni = "api.example.test", TlsVersion = "TLS 1.3",
            Alpn = "h2", Ja4 = "ja4-151-client", ProcessName = "backend-agent.exe",
            WhoisASN = "AS100", Length = 1024, L4Len = 1024
        };

    internal static TrafficRecord Http(string uri = "/graphql", string method = "GET")
        => new()
        {
            Source = "203.0.113.153", Destination = "10.153.0.20",
            IpVersion = 4, SourcePort = 51530, DestinationPort = 443,
            Protocol = "HTTPS", ApplicationProtocol = "HTTPS", ApplicationService = "HTTPS",
            IsTcp = true, HttpHost = "api.internal.local", HttpUri = uri,
            HttpMethod = method, HttpRequestHeaders = "Host: api.internal.local",
            HttpUserAgent = "curl/8.7", Length = 2048, L4Len = 2048
        };
}
