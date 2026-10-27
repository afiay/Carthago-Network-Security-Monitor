// SPDX-License-Identifier: MIT
using System;
using Carthago.Engine.Rules;
using Carthago.Models;
using Carthago.Services;
namespace Carthago.Tests;
internal static class NetworkBatch126130Context
{
    private static readonly DateTime Origin = DateTime.UtcNow.AddMinutes(-20);
    internal static RuleEvaluationContext At(TrafficRecord r, int seconds = 0)
        => new(r, Sensitivity.Balanced, Origin.AddSeconds(seconds));
    internal static TrafficRecord Ssh(string identity = "alice") => new()
    {
        Source = "198.51.100.126", Destination = "10.126.1.20",
        IpVersion = 4, Protocol = "TCP", ApplicationProtocol = "SSH",
        ApplicationService = "SSH", IsTcp = true, SourcePort = 53000,
        DestinationPort = 22, Info = "Failed password for user=" + identity
    };
    internal static TrafficRecord Web(string path = "/admin", string host = "portal.example.test") => new()
    {
        Source = "198.51.100.127", Destination = "10.127.1.20",
        IpVersion = 4, Protocol = "HTTPS", ApplicationProtocol = "HTTPS",
        ApplicationService = "HTTPS", IsTcp = true, SourcePort = 53000,
        DestinationPort = 443, HttpMethod = "GET", HttpUri = path,
        HttpHost = host, Sni = host
    };
    internal static TrafficRecord Callback()
        => Web("/signin-oidc?id_token=eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxIn0.signature");
    internal static TrafficRecord Login(string identity = "alice", bool failed = true)
    {
        var r = Web("/login");
        r.HttpMethod = "POST";
        r.Info = (failed ? "login failed " : "login submitted ") + "user=" + identity;
        return r;
    }
}
