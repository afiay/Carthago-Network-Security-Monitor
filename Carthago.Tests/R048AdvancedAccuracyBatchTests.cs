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
public sealed class R048AdvancedAccuracyBatchTests : IDisposable
{
    private readonly R048_AlternateDohPatternsRule _rule = new();
    private static readonly DateTime T0 = new(2026, 10, 27, 8, 0, 0, DateTimeKind.Utc);
    public R048AdvancedAccuracyBatchTests() => RuleEngine.ResetRuntimeStateForReplay();
    public void Dispose() => RuleEngine.ResetRuntimeStateForReplay();
    private async Task<RuleEvaluationResult> See(TrafficRecord r, int sec = 0)
        => await _rule.EvaluateAsync(new RuleEvaluationContext(r, Sensitivity.Balanced, T0.AddSeconds(sec)));
    private static TrafficRecord Doh(string uri = "/dns-query?dns=QWJjZEVmR2gxMjM0")
        => new() { Source = "10.48.0.2", Destination = "8.8.8.8", Protocol = "HTTP",
            DestinationPort = 443, HttpMethod = "GET", HttpHost = "dns.google",
            HttpUri = uri, Length = 250 };

    [Fact] public async Task Structured_Get_Dns_Query_Matches_Without_Query_Leak()
    {
        var e = Assert.Single((await See(Doh())).Events);
        Assert.Equal("R048", e.RuleId);
        Assert.DoesNotContain("QWJjZEVmR2gxMjM0", e.Description);
        Assert.DoesNotContain("dns.google", e.Description);
    }
    [Fact] public async Task Json_Accept_And_Alternate_Resolve_Path_Match()
    {
        var r = Doh("/resolve?name=example.org"); r.HttpRequestHeaders = "Accept: application/dns-json\r\n";
        Assert.True((await See(r)).Matched);
    }
    [Fact] public async Task Json_Post_To_Dns_Query_Requires_Content_Type()
    {
        var r = Doh("/dns-query"); r.HttpMethod = "POST";
        r.HttpRequestHeaders = "Content-Type: application/dns-json\r\n";
        Assert.True((await See(r)).Matched);
        RuleEngine.ResetRuntimeStateForReplay();
        r.HttpRequestHeaders = "Content-Type: application/json\r\n";
        Assert.False((await See(r)).Matched);
    }
    [Fact] public async Task Provider_Substring_And_Contradictory_Host_Are_Excluded()
    {
        var r = Doh(); r.HttpHost = "dns.google.attacker.example";
        Assert.False((await See(r)).Matched);
        r = Doh(); r.HttpRequestHeaders = "Host: other.example.net\r\n";
        Assert.False((await See(r)).Matched);
        r = Doh(); r.HttpRequestHeaders = "Host: dns.google\r\nHost: dns.google\r\n";
        Assert.False((await See(r)).Matched);
    }
    [Fact] public async Task Info_Prose_And_Unrelated_Uri_Are_Not_Doh_Evidence()
    {
        var r = Doh("/health"); r.Info = "GET /dns-query?dns=QWJjZEVmR2gxMjM0 HTTP/1.1";
        Assert.False((await See(r)).Matched);
        r = Doh("/not-dns-query?dns=QWJjZEVmR2gxMjM0");
        Assert.False((await See(r)).Matched);
    }
    [Fact] public async Task Wrong_Method_Transport_And_Port_Are_Excluded()
    {
        var r = Doh(); r.HttpMethod = null; Assert.False((await See(r)).Matched);
        r = Doh(); r.Protocol = "DNS"; Assert.False((await See(r)).Matched);
        r = Doh(); r.DestinationPort = 80; Assert.False((await See(r)).Matched);
        r = Doh(); r.ApplicationService = "SMTP"; Assert.False((await See(r)).Matched);
    }
    [Fact] public async Task Duplicate_OutOfOrder_And_Cooldown_Are_Handled()
    {
        Assert.True((await See(Doh())).Matched);
        Assert.False((await See(Doh())).Matched);
        Assert.False((await See(Doh(), -1)).Matched);
        Assert.True((await See(Doh(), 1)).Suppressed);
    }
}