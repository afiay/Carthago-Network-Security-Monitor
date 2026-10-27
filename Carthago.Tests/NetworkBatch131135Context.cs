// SPDX-License-Identifier: MIT
using System;
using Carthago.Engine.Rules;
using Carthago.Models;
using Carthago.Services;

namespace Carthago.Tests;

internal static class NetworkBatch131135Context
{
    private static readonly DateTime Origin = new(2026, 10, 27, 12, 0, 0, DateTimeKind.Utc);

    internal static RuleEvaluationContext At(TrafficRecord record, int seconds = 0)
        => new(record, Sensitivity.Balanced, Origin.AddSeconds(seconds));

    internal static TrafficRecord Web(string path = "/api/auth/token", bool cleartext = false,
        string host = "auth.example.test")
    {
        var protocol = cleartext ? "HTTP" : "HTTPS";
        return new TrafficRecord
        {
            Source = "198.51.100.131", Destination = "10.131.0.20",
            IpVersion = 4, SourcePort = 53131, DestinationPort = cleartext ? 80 : 443,
            Protocol = protocol, ApplicationProtocol = protocol, ApplicationService = protocol,
            IsTcp = true, HttpMethod = "GET", HttpHost = host, HttpUri = path,
            HttpRequestHeaders = "Host: " + host,
            Sni = cleartext ? null : host, Info = "GET request"
        };
    }

    internal static TrafficRecord Failed()
    {
        var r = Web();
        r.HttpRequestHeaders += "\r\nAuthorization: Bearer eyJhbGciOiJIUzI1NiJ9.payload.signature";
        r.Info = "401 unauthorized authentication failed";
        return r;
    }

    internal static TrafficRecord Login(string identity = "alice@example.com", string country = "US")
    {
        var r = Web("/signin");
        r.HttpMethod = "POST";
        r.Info = "username=" + identity + " login successful";
        r.SrcCountryIso2 = country;
        return r;
    }

    internal static TrafficRecord Basic(string path = "/api")
    {
        var r = Web(path, true);
        r.HttpRequestHeaders += "\r\nAuthorization: Basic QWxhZGRpbjpPcGVuU2VzYW1l";
        return r;
    }

    internal static TrafficRecord Bearer(string path = "/v1/profile")
    {
        var r = Web(path, true);
        r.HttpRequestHeaders += "\r\nAuthorization: Bearer eyJhbGciOiJIUzI1NiJ9.payload.signature";
        return r;
    }
}
