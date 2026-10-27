// SPDX-License-Identifier: MIT
using System;
using System.Threading.Tasks;
using Carthago.Engine.Rules;
using Carthago.Engine.Rules.Existing;
using Carthago.Models;
using Carthago.Services;
using Xunit;
namespace Carthago.Tests;

[Collection("Legacy rules R011-R015 isolated")]
public sealed class R032AdvancedAccuracyBatchTests : IDisposable
{
    private readonly R032_SuspiciousEmptyHttpUserAgentRule _rule = new();
    private static readonly DateTime T0 = new(2026, 10, 27, 5, 0, 0, DateTimeKind.Utc);
    public R032AdvancedAccuracyBatchTests() => RuleEngine.ResetRuntimeStateForReplay();
    public void Dispose() => RuleEngine.ResetRuntimeStateForReplay();
    private async Task<RuleEvaluationResult> See(TrafficRecord r, int sec = 0)
        => await _rule.EvaluateAsync(new RuleEvaluationContext(r, Sensitivity.Balanced, T0.AddSeconds(sec)));

    private static TrafficRecord Http(string? ua = "curl/8.1", string src = "10.32.0.2", string dst = "8.8.8.8")
        => new() { Source = src, Destination = dst, Protocol = "HTTP", DestinationPort = 80,
            HttpMethod = "GET", HttpUri = "/health", HttpUserAgent = ua, Length = 110 };
    [Fact] public async Task Observed_Automation_UserAgent_Is_Attributed_Without_Exposing_Header()
    {
        var r = Http("curl/8.1 SECRET-HEADER");
        var e = Assert.Single((await See(r)).Events);
        Assert.Equal("R032", e.RuleId); Assert.Equal(SeverityLevel.Medium, e.Severity);
        Assert.DoesNotContain("SECRET-HEADER", e.Description);
    }
    [Fact] public async Task Explicit_Empty_UserAgent_Uses_Low_Severity()
    {
        var e = Assert.Single((await See(Http(null))).Events);
        Assert.Equal(SeverityLevel.Low, e.Severity);
        Assert.Contains("empty", e.Description);
    }
    [Fact] public async Task Browser_Agent_And_NonHttp_Metadata_Are_Benign()
    {
        Assert.False((await See(Http("Mozilla/5.0 Safari/605"))).Matched);
        var tcp = Http(); tcp.Protocol = "TCP"; tcp.ApplicationService = null;
        Assert.False((await See(tcp)).Matched);
        var dns = Http(); dns.Protocol = "DNS";
        Assert.False((await See(dns)).Matched);
    }
    [Fact] public async Task Missing_Method_And_Response_Like_Record_Are_Not_Requests()
    {
        var r = Http(); r.HttpMethod = null;
        Assert.False((await See(r)).Matched);
        r.HttpMethod = "HTTP/1.1 200 OK";
        Assert.False((await See(r)).Matched);
    }
    [Fact] public async Task Contradictory_Service_And_Invalid_Evidence_Are_Rejected()
    {
        var r = Http(); r.ApplicationService = "DNS";
        Assert.False((await See(r)).Matched);
        r = Http(); r.Source = "bad";
        Assert.False((await See(r)).Matched);
        r = Http(); r.Length = 0;
        Assert.False((await See(r)).Matched);
        r = Http(); r.IsQuic = true;
        Assert.False((await See(r)).Matched);
    }
    [Fact] public async Task Structured_Tcp_Http_And_Per_Destination_Cooldown()
    {
        var tcp = Http(); tcp.Protocol = "TCP"; tcp.ApplicationService = "HTTP";
        Assert.Equal("R032", Assert.Single((await See(tcp)).Events).RuleId);
        Assert.True((await See(tcp, 1)).Suppressed);
        Assert.Equal("9.9.9.9", Assert.Single((await See(Http(dst: "9.9.9.9"), 1)).Events).DestinationIp);
    }
}
