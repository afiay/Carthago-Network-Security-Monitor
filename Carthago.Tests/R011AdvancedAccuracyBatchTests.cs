// SPDX-License-Identifier: MIT
using System;
using System.Threading.Tasks;
using Carthago.Engine.Rules;
using Carthago.Engine.Rules.Existing;
using Carthago.Models;
using Carthago.Services;
using Xunit;

namespace Carthago.Tests;

/// <summary>R011: per-client DHCP request evidence and temporal isolation.</summary>
[Collection("Legacy rules R011-R015 isolated")]
public sealed class R011AdvancedAccuracyBatchTests : IDisposable
{
    private readonly R011_DhcpAbuseRule _rule = new();
    private static readonly DateTime T0 = new(2026, 10, 27, 3, 0, 0, DateTimeKind.Utc);
    public R011AdvancedAccuracyBatchTests() => RuleEngine.ResetRuntimeStateForReplay();
    public void Dispose() => RuleEngine.ResetRuntimeStateForReplay();

    private static TrafficRecord Request(string? mac = "02:11:22:33:44:55", string? source = "0.0.0.0")
        => new() { Source = source, Destination = "255.255.255.255", Protocol = "UDP",
            SourcePort = 68, DestinationPort = 67, MacSource = mac, Length = 300,
            ApplicationService = "DHCP" };

    private async Task<RuleEvaluationResult> See(TrafficRecord r, int second)
        => await _rule.EvaluateAsync(new RuleEvaluationContext(r, Sensitivity.Balanced, T0.AddSeconds(second)));

    [Fact]
    public async Task Twenty_Client_Requests_Produce_One_Attributed_Rate_Candidate()
    {
        for (int i = 0; i < 19; i++)
            Assert.False((await See(Request(), i)).Matched);
        var evt = Assert.Single((await See(Request(), 19)).Events);
        Assert.Equal("R011", evt.RuleId);
        Assert.Equal(20, evt.Count);
        Assert.Equal(60, evt.WindowSeconds);
        Assert.Equal(SeverityLevel.High, evt.Severity);
        Assert.DoesNotContain("02:11:22:33:44:55", evt.Description);
    }

    [Fact]
    public async Task Server_Replies_And_Text_Only_Dhcp_Labels_Do_Not_Inflate_Client_Rate()
    {
        for (int i = 0; i < 40; i++)
        {
            var response = Request();
            response.SourcePort = 67;
            response.DestinationPort = 68;
            Assert.False((await See(response, i)).Matched);
            var labelOnly = Request();
            labelOnly.Protocol = "TCP";
            Assert.False((await See(labelOnly, i)).Matched);
        }
        for (int i = 0; i < 19; i++)
            Assert.False((await See(Request(), i)).Matched);
        Assert.Equal(20, Assert.Single((await See(Request(), 19)).Events).Count);
    }

    [Fact]
    public async Task Distinct_Clients_Cannot_Combine_To_Cross_Threshold()
    {
        for (int i = 0; i < 19; i++)
        {
            Assert.False((await See(Request("02:11:22:33:44:55"), i)).Matched);
            Assert.False((await See(Request("06:11:22:33:44:55"), i)).Matched);
        }
        Assert.Equal(20, Assert.Single((await See(Request("02:11:22:33:44:55"), 19)).Events).Count);
        Assert.Equal(20, Assert.Single((await See(Request("06:11:22:33:44:55"), 19)).Events).Count);
    }

    [Fact]
    public async Task Zero_Source_Ip_With_Valid_Link_Mac_Remains_Attributable()
    {
        for (int i = 0; i < 19; i++)
            Assert.False((await See(Request(), i)).Matched);
        var evt = Assert.Single((await See(Request(), 19)).Events);
        Assert.Equal("0.0.0.0", evt.SourceIp);
        Assert.Contains("client-request rate", evt.Description);
    }

    [Fact]
    public async Task Missing_Or_Malformed_Identity_Cannot_Prime_Broadcast_Requests()
    {
        foreach (string? mac in new[] { null, "", "zz:11:22:33:44:55", "01:11:22:33:44:55" })
            for (int i = 0; i < 25; i++)
                Assert.False((await See(Request(mac), i)).Matched);
        for (int i = 0; i < 19; i++)
            Assert.False((await See(Request(), i)).Matched);
        Assert.Equal(20, Assert.Single((await See(Request(), 19)).Events).Count);
    }

    [Fact]
    public async Task Private_Renewal_Ip_Is_An_Identity_Fallback_Without_Mac()
    {
        for (int i = 0; i < 19; i++)
            Assert.False((await See(Request(null, "10.11.0.7"), i)).Matched);
        var evt = Assert.Single((await See(Request(null, "10.11.0.7"), 19)).Events);
        Assert.Equal("10.11.0.7", evt.SourceIp);
    }

    [Fact]
    public async Task Future_And_Expired_Requests_Do_Not_Complete_Current_Window()
    {
        Assert.False((await See(Request(), 1000)).Matched);
        for (int i = 0; i < 19; i++)
            Assert.False((await See(Request(), i)).Matched);
        Assert.Equal(20, Assert.Single((await See(Request(), 19)).Events).Count);

        RuleEngine.ResetRuntimeStateForReplay();
        for (int i = 0; i < 19; i++)
            Assert.False((await See(Request(), i)).Matched);
        Assert.False((await See(Request(), 100)).Matched);
        for (int i = 1; i < 19; i++)
            Assert.False((await See(Request(), 100 + i)).Matched);
        Assert.Equal(20, Assert.Single((await See(Request(), 119)).Events).Count);
    }

    [Fact]
    public async Task Cooldown_Does_Not_Allow_Unbounded_State_Or_Cross_Client_Suppression()
    {
        for (int i = 0; i < 20; i++)
            await See(Request(), i);
        for (int i = 0; i < 19; i++)
            Assert.False((await See(Request(), 30 + i)).Matched);
        var repeat = await See(Request(), 49);
        Assert.True(repeat.Suppressed);
        Assert.Empty(repeat.Events);
        for (int i = 0; i < 19; i++)
            Assert.False((await See(Request("06:11:22:33:44:55"), 30 + i)).Matched);
        Assert.Equal(20, Assert.Single((await See(Request("06:11:22:33:44:55"), 49)).Events).Count);
    }
}
