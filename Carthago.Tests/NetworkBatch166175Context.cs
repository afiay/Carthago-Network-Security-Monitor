// SPDX-License-Identifier: MIT
using System;
using Carthago.Engine.Rules;
using Carthago.Models;
using Carthago.Services;
namespace Carthago.Tests;
internal static class NetworkBatch166175Context
{
    internal static readonly DateTime Origin = new(2026, 10, 28, 0, 0, 0, DateTimeKind.Utc);
    internal static RuleEvaluationContext At(TrafficRecord r, int seconds = 0)
        => new(r, Sensitivity.Balanced, Origin.AddSeconds(seconds));
    internal static TrafficRecord Http(string path, string method = "GET")
        => new()
        {
            Id = Guid.NewGuid(), Source = "203.0.113.166", Destination = "10.166.0.20",
            IpVersion = 4, SourcePort = 51000, DestinationPort = 443,
            Protocol = "HTTPS", ApplicationProtocol = "HTTPS", ApplicationService = "HTTPS",
            IsTcp = true, HttpHost = "web.internal.local", HttpUri = path,
            HttpMethod = method, HttpRequestHeaders = "Host: web.internal.local",
            HttpUserAgent = "curl/8.7", Length = 2048, L4Len = 2048
        };
    internal static TrafficRecord Fail(string source = "203.0.113.166")
    {
        var r = Http("/admin/login", "POST");
        r.Source = source;
        r.Info = "login failed: invalid password";
        return r;
    }
    internal static TrafficRecord Xml(string path = "/soap/order")
    {
        var r = Http(path, "POST");
        r.HttpRequestHeaders += "\r\nContent-Type: text/xml";
        return r;
    }
    internal static string XxePath()
        => "/soap/order?xml=" + Uri.EscapeDataString(
            "<!DOCTYPE foo [<!ENTITY xxe SYSTEM \"file:///etc/passwd\">]>");
}
