// SPDX-License-Identifier: MIT
using System;
using System.Threading.Tasks;
using Carthago.Engine.Rules;
using Carthago.Engine.Rules.Expansion;
using Carthago.Models;
using Xunit;

namespace Carthago.Tests;

internal static class NetworkBatch276280Context
{
    internal static readonly DateTime Origin = new(2026, 10, 28, 16, 0, 0, DateTimeKind.Utc);
    internal static RuleEvaluationContext At(TrafficRecord r, double seconds = 0)
        => new(r, Sensitivity.Balanced, Origin.AddSeconds(seconds));
    internal static TrafficRecord Sample() => new()
    {
        Id = Guid.NewGuid(), Source = "10.61.0.10", Destination = "185.220.100.254",
        IpVersion = 4, Protocol = "TCP", IsTcp = true, SourcePort = 51000,
        DestinationPort = 443, ApplicationProtocol = "HTTPS", HttpMethod = "POST",
        HttpHost = "login.microsoftonline.com", HttpUri = "/oauth2/v2.0/authorize",
        Sni = "login.microsoftonline.com", Info = ""
    };
    internal static TrafficRecord Copy(TrafficRecord r) => new()
    {
        Id = Guid.NewGuid(), Source = r.Source, Destination = r.Destination,
        IpVersion = r.IpVersion, Protocol = r.Protocol, IsTcp = r.IsTcp,
        IsUdp = r.IsUdp, IsQuic = r.IsQuic, SourcePort = r.SourcePort,
        DestinationPort = r.DestinationPort, ApplicationProtocol = r.ApplicationProtocol,
        HttpMethod = r.HttpMethod, HttpHost = r.HttpHost, HttpUri = r.HttpUri,
        HttpUserAgent = r.HttpUserAgent, HttpRequestHeaders = r.HttpRequestHeaders,
        Sni = r.Sni, TlsVersion = r.TlsVersion, Info = r.Info, ProcessName = r.ProcessName,
        ProcessId = r.ProcessId, SrcCountry = r.SrcCountry, DstCountry = r.DstCountry,
        SrcLat = r.SrcLat, SrcLon = r.SrcLon, DstLat = r.DstLat, DstLon = r.DstLon
    };
}
