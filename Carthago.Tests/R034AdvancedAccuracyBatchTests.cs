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
public sealed class R034AdvancedAccuracyBatchTests : IDisposable
{
    private readonly R034_DnsOverHttpsHeuristicRule _rule = new();
    private static readonly DateTime T0 = new(2026, 10, 27, 5, 0, 0, DateTimeKind.Utc);
    public R034AdvancedAccuracyBatchTests() => RuleEngine.ResetRuntimeStateForReplay();
    public void Dispose() => RuleEngine.ResetRuntimeStateForReplay();
    private async Task<RuleEvaluationResult> See(TrafficRecord r, int sec = 0)
        => await _rule.EvaluateAsync(new RuleEvaluationContext(r, Sensitivity.Balanced, T0.AddSeconds(sec)));

    private static TrafficRecord Doh(string method = "GET", string uri = "/dns-query?dns=AbCdEfGh1234", string dst = "8.8.8.8")
        => new() { Source = "10.34.0.2", Destination = dst, Protocol = "HTTP",
            DestinationPort = 443, HttpMethod = method, HttpUri = uri, Length = 220 };
    [Fact] public async Task Structured_Get_Doh_Query_Is_Detected_Without_Query_Leak()
    {
        var r = Doh(); r.HttpUri = "/dns-query?dns=SECRETBASE64TOKEN";
        var e = Assert.Single((await See(r)).Events);
        Assert.Equal("R034", e.RuleId);
        Assert.DoesNotContain("SECRETBASE64TOKEN", e.Description);
    }
    [Fact] public async Task Post_Requires_Explicit_Dns_Message_Content_Type()
    {
        var r = Doh("POST", "/dns-query"); r.HttpRequestHeaders = "Content-Type: application/dns-message\r\n";
        Assert.True((await See(r)).Matched);
        RuleEngine.ResetRuntimeStateForReplay();
        r.HttpRequestHeaders = "Content-Type: application/json\r\n";
        Assert.False((await See(r)).Matched);
    }
    [Fact] public async Task Uri_Substring_And_Header_Prose_Are_Not_Enough()
    {
        var r = Doh(uri: "/not-dns-query?dns=AbCdEfGh1234");
        Assert.False((await See(r)).Matched);
        r = Doh(uri: "/health"); r.Info = "GET /dns-query?dns=AbCdEfGh1234 HTTP/1.1";
        Assert.False((await See(r)).Matched);
    }
    [Fact] public async Task Missing_Method_And_Malformed_Encoded_Query_Are_Excluded()
    {
        var r = Doh(); r.HttpMethod = null;
        Assert.False((await See(r)).Matched);
        r = Doh(uri: "/dns-query?dns=x");
        Assert.False((await See(r)).Matched);
        r = Doh(uri: "/dns-query");
        Assert.False((await See(r)).Matched);
    }
    [Fact] public async Task Wrong_Transport_Quic_And_Contradictory_Service_Are_Excluded()
    {
        var r = Doh(); r.Protocol = "DNS";
        Assert.False((await See(r)).Matched);
        r = Doh(); r.IsQuic = true;
        Assert.False((await See(r)).Matched);
        r = Doh(); r.ApplicationService = "SMTP";
        Assert.False((await See(r)).Matched);
        r = Doh(); r.DestinationPort = 80;
        Assert.False((await See(r)).Matched);
    }
    [Fact] public async Task Invalid_Endpoints_And_Cooldown_Are_Handled()
    {
        var r = Doh(); r.Source = "bad";
        Assert.False((await See(r)).Matched);
        r = Doh(); r.Length = 0;
        Assert.False((await See(r)).Matched);
        Assert.True((await See(Doh())).Matched);
        Assert.True((await See(Doh(), 1)).Suppressed);
        Assert.Equal("9.9.9.9", Assert.Single((await See(Doh(dst: "9.9.9.9"), 1)).Events).DestinationIp);
    }
}
