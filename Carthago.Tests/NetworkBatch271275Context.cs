// SPDX-License-Identifier: MIT
using System;
using System.Threading.Tasks;
using Carthago.Engine.Rules;
using Carthago.Engine.Rules.Expansion;
using Carthago.Models;
using Carthago.Services;
using Xunit;

namespace Carthago.Tests;

internal static class NetworkBatch271275Context
{
    internal static readonly DateTime Origin = new(2026, 10, 28, 15, 0, 0, DateTimeKind.Utc);
    internal static RuleEvaluationContext At(TrafficRecord r, double seconds = 0)
        => new(r, Sensitivity.Balanced, Origin.AddSeconds(seconds));
    internal static TrafficRecord Sample() => new()
    {
        Id = Guid.NewGuid(), Source = "185.220.100.254", Destination = "10.61.0.10",
        IpVersion = 4, Protocol = "TCP", IsTcp = true, SourcePort = 55000,
        DestinationPort = 443, ReputationIsMalicious = true, ReputationScore = 95,
        ReputationReports = 12, ReputationLastSeen = Origin.AddDays(-1), Info = ""
    };
    internal static MatchInfo Feed(string value = "185.220.100.254")
        => new(IndicatorKind.IPv4, value, 85, new[] { "independent-feed" }, Array.Empty<string>());
    internal static bool Overlap(TrafficRecord r, MatchInfo? hit = null,
        DateTimeOffset? built = null, double seconds = 0)
        => NetworkBatch271275Evidence.HasSourceOverlap(r, hit ?? Feed(),
            built ?? new DateTimeOffset(Origin.AddMinutes(-1)), Origin.AddSeconds(seconds));
    internal static TrafficRecord Copy(TrafficRecord r) => new()
    {
        Id = Guid.NewGuid(), Source = r.Source, Destination = r.Destination,
        IpVersion = r.IpVersion, Protocol = r.Protocol, IsTcp = r.IsTcp, IsUdp = r.IsUdp,
        IsQuic = r.IsQuic, SourcePort = r.SourcePort, DestinationPort = r.DestinationPort,
        ReputationIsMalicious = r.ReputationIsMalicious, ReputationScore = r.ReputationScore,
        ReputationReports = r.ReputationReports, ReputationLastSeen = r.ReputationLastSeen,
        Info = r.Info, HttpMethod = r.HttpMethod, HttpHost = r.HttpHost,
        HttpUri = r.HttpUri, ApplicationProtocol = r.ApplicationProtocol,
        Sni = r.Sni, TlsVersion = r.TlsVersion, ProcessName = r.ProcessName,
        ProcessId = r.ProcessId, DnsQname = r.DnsQname, DnsIsResponse = r.DnsIsResponse,
        SrcCountry = r.SrcCountry, DstCountry = r.DstCountry,
        SrcLat = r.SrcLat, SrcLon = r.SrcLon, DstLat = r.DstLat, DstLon = r.DstLon,
        IcmpTypeCode = r.IcmpTypeCode
    };
    internal static TrafficRecord DeviceCodeRequest()
    {
        var r = Sample();
        r.Source = "10.61.0.10"; r.Destination = "185.220.100.254";
        r.Protocol = "HTTPS"; r.ApplicationProtocol = "HTTPS";
        r.HttpMethod = "POST"; r.HttpHost = "login.microsoftonline.com";
        r.HttpUri = "/oauth2/v2.0/devicecode?client_id=app&device_code=code&user_code=secret";
        r.Sni = "login.microsoftonline.com";
        return r;
    }
}
