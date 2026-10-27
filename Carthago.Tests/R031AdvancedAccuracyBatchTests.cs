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
public sealed class R031AdvancedAccuracyBatchTests : IDisposable
{
    private readonly R031_DnsTxtSpikeRule _rule = new();
    private static readonly DateTime T0 = new(2026, 10, 27, 5, 0, 0, DateTimeKind.Utc);
    public R031AdvancedAccuracyBatchTests() => RuleEngine.ResetRuntimeStateForReplay();
    public void Dispose() => RuleEngine.ResetRuntimeStateForReplay();
    private async Task<RuleEvaluationResult> See(TrafficRecord r, int sec = 0)
        => await _rule.EvaluateAsync(new RuleEvaluationContext(r, Sensitivity.Balanced, T0.AddSeconds(sec)));

    private static TrafficRecord Txt(string src = "10.31.0.2", string dst = "8.8.8.8")
        => new() { Source = src, Destination = dst, Protocol = "DNS", DestinationPort = 53,
            DnsQtype = "TXT", DnsQname = "example.org", Length = 90 };
    [Fact] public async Task Fifteen_Observed_Txt_Queries_Reach_Existing_Threshold()
    {
        for (int i = 0; i < 14; i++) Assert.False((await See(Txt(), i)).Matched);
        var e = Assert.Single((await See(Txt(), 14)).Events);
        Assert.Equal("R031", e.RuleId); Assert.Equal(15, e.Count);
        Assert.Equal(60, e.WindowSeconds); Assert.Equal("10.31.0.2", e.SourceIp);
    }
    [Fact] public async Task Dns_Responses_NonTxt_And_Contradictory_Service_Do_Not_Prime()
    {
        for (int i = 0; i < 15; i++)
        {
            var response = Txt(); response.DnsIsResponse = true;
            Assert.False((await See(response, i)).Matched);
            var a = Txt(); a.DnsQtype = "A";
            Assert.False((await See(a, i)).Matched);
            var wrong = Txt(); wrong.ApplicationService = "HTTP";
            Assert.False((await See(wrong, i)).Matched);
        }
        Assert.False((await See(Txt(), 16)).Matched);
    }
    [Fact] public async Task Different_Resolvers_And_Clients_Do_Not_Accumulate_Together()
    {
        for (int i = 0; i < 14; i++)
        {
            Assert.False((await See(Txt(), i)).Matched);
            Assert.False((await See(Txt(dst: "9.9.9.9"), i)).Matched);
            Assert.False((await See(Txt(src: "10.31.0.3"), i)).Matched);
        }
        Assert.Equal(15, Assert.Single((await See(Txt(), 14)).Events).Count);
    }
    [Fact] public async Task Invalid_Endpoints_Empty_Query_And_Wrong_Port_Are_Excluded()
    {
        var a = Txt(); a.Source = "bad";
        var b = Txt(); b.Destination = "bad";
        var c = Txt(); c.DnsQname = null;
        var d = Txt(); d.Length = 0;
        var e = Txt(); e.DestinationPort = 853;
        var f = Txt(); f.IsQuic = true;
        foreach (var r in new[] { a, b, c, d, e, f }) Assert.False((await See(r)).Matched);
    }
    [Fact] public async Task Duplicate_Timestamps_And_Expired_Window_Cannot_Inflate()
    {
        for (int i = 0; i < 30; i++) Assert.False((await See(Txt(), 0)).Matched);
        for (int i = 1; i < 14; i++) Assert.False((await See(Txt(), i)).Matched);
        Assert.Equal(15, Assert.Single((await See(Txt(), 14)).Events).Count);
        RuleEngine.ResetRuntimeStateForReplay();
        for (int i = 0; i < 14; i++) Assert.False((await See(Txt(), i)).Matched);
        Assert.False((await See(Txt(), 120)).Matched);
    }
    [Fact] public async Task Suppressed_Burst_Clears_And_Query_Name_Is_Not_Exposed()
    {
        var q = Txt(); q.DnsQname = "secret.customer.example.org";
        for (int i = 0; i < 14; i++) await See(q, i);
        var e = Assert.Single((await See(q, 14)).Events);
        Assert.DoesNotContain("secret.customer", e.Description);
        for (int i = 15; i < 29; i++) Assert.False((await See(q, i)).Matched);
        Assert.True((await See(q, 29)).Suppressed);
        Assert.False((await See(q, 30)).Matched);
    }
}
