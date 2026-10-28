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
    internal static TrafficRecord DohGet(string host = "resolver.example.net", string? path = null)
    {
        var r = NetworkBatch166175Context.Http(path ?? "/dns-query?dns=" + WireDnsQuestion());
        r.Source = "10.186.0.10"; r.Destination = "9.9.9.9";
        r.HttpHost = host; r.HttpRequestHeaders = "Host: " + host + "\r\nAccept: application/dns-message";
        return r;
    }
    private static string WireDnsQuestion()
    {
        var message = new byte[] { 0x12, 0x34, 0x01, 0x00, 0x00, 0x01, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x07, (byte)'e', (byte)'x', (byte)'a', (byte)'m',
            (byte)'p', (byte)'l', (byte)'e', 0x03, (byte)'o', (byte)'r', (byte)'g',
            0x00, 0x00, 0x01, 0x00, 0x01 };
        return Convert.ToBase64String(message).TrimEnd('=').Replace('+', '-').Replace('/', '_');
    }
    internal static TrafficRecord Dot(string host = "resolver.example.net")
        => new() { Id = Guid.NewGuid(), Source = "10.186.0.10", Destination = "9.9.9.9",
            IpVersion = 4, SourcePort = 55000, DestinationPort = 853,
            Protocol = "TCP", ApplicationProtocol = "TLS", ApplicationService = "TLS",
            IsTcp = true, Sni = host, TlsVersion = "TLS1.3", Length = 512, L4Len = 400 };

}
