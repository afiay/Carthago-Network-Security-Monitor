// SPDX-License-Identifier: MIT
using System;
using Carthago.Engine.Rules;
using Carthago.Models;
using Carthago.Services;

namespace Carthago.Tests;

internal static class NetworkBatch136140Context
{
    private static readonly DateTime Origin = new(2026, 10, 27, 12, 0, 0, DateTimeKind.Utc);
    internal static RuleEvaluationContext At(TrafficRecord record, int seconds = 0)
        => new(record, Sensitivity.Balanced, Origin.AddSeconds(seconds));

    internal static TrafficRecord Http(string path = "/dashboard", string method = "GET", bool cleartext = true)
    {
        var protocol = cleartext ? "HTTP" : "HTTPS";
        return new TrafficRecord
        {
            Source = "10.136.0.10", Destination = "198.51.100.136", IpVersion = 4,
            SourcePort = 51360, DestinationPort = cleartext ? 80 : 443,
            Protocol = protocol, ApplicationProtocol = protocol, ApplicationService = protocol,
            IsTcp = true, HttpHost = "portal.example.test", HttpUri = path,
            HttpMethod = method, HttpRequestHeaders = "Host: portal.example.test",
            Sni = cleartext ? null : "portal.example.test", Info = method + " request"
        };
    }

    internal static TrafficRecord Cookie(string path = "/dashboard")
    {
        var r = Http(path);
        r.HttpRequestHeaders += "\r\nCookie: JSESSIONID=abc123def456ghi789";
        return r;
    }

    internal static TrafficRecord Recovery(string path = "/password-reset")
    {
        var r = Http(path, "POST", false);
        r.Info = "reset password submit username=alice@example.test";
        return r;
    }

    internal static TrafficRecord Tls(string issuer = "CN=stage.example.test",
        string subject = "CN=stage.example.test", string version = "TLS 1.2")
        => new()
        {
            Source = "10.138.0.10", Destination = "198.51.100.138",
            IpVersion = 4, SourcePort = 51380, DestinationPort = 443,
            Protocol = "TLS", ApplicationProtocol = "TLS", ApplicationService = "HTTPS",
            IsTcp = true, Sni = "edge.example.test", TlsVersion = version,
            CertIssuer = issuer, CertSubject = subject, Info = "TLS handshake"
        };
}
