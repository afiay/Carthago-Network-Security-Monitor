// SPDX-License-Identifier: MIT
using System;
using System.Threading.Tasks;
using Carthago.Engine.Rules;
using Carthago.Engine.Rules.Existing;
using Carthago.Models;
using Carthago.Services;
using Xunit;

namespace Carthago.Tests;

/// <summary>R006: bounded DNS query-volume evidence and content attribution.</summary>
[Collection("Legacy rules R006-R010 isolated")]
public sealed class R006AdvancedAccuracyBatchTests : IDisposable
{
    private readonly R006_DnsAnomaliesRule _rule = new();
    private static readonly DateTime T0 = new(2026, 10, 27, 1, 0, 0, DateTimeKind.Utc);
    public R006AdvancedAccuracyBatchTests() => RuleEngine.ResetRuntimeStateForReplay();
    public void Dispose() => RuleEngine.ResetRuntimeStateForReplay();

    private static TrafficRecord Query(string source = "10.206.0.1",
        string? qname = "www.example.invalid", string? destination = "1.1.1.1")
        => new() { Source = source, Destination = destination, Protocol = "DNS",
            DestinationPort = 53, DnsQname = qname, DnsQtype = "A",
            DnsIsResponse = false, Length = 90 };

    private async Task<RuleEvaluationResult> See(TrafficRecord record, int second)
        => await _rule.EvaluateAsync(new RuleEvaluationContext(
            record, Sensitivity.Balanced, T0.AddSeconds(second)));

    [Fact]
    public async Task Twenty_Configured_Valid_Queries_Produce_One_Medium_Volume_Candidate()
    {
        for (int i = 0; i < 19; i++)
            Assert.False((await See(Query(qname: $"www{i}.example.invalid"), i)).Matched);
        var hit = await See(Query(), 19);
        Assert.True(hit.Matched);
        var evt = Assert.Single(hit.Events);
        Assert.Equal("R006", evt.RuleId);
        Assert.Equal(20, evt.Count);
        Assert.Equal(SeverityLevel.Medium, evt.Severity);
        Assert.Equal("10.206.0.1", evt.SourceIp);
        Assert.Equal("1.1.1.1", evt.DestinationIp);
    }

    [Fact]
    public async Task High_Entropy_Query_At_Threshold_Is_High_Severity_Without_Leaking_Qname()
    {
        for (int i = 0; i < 19; i++)
            Assert.False((await See(Query(), i)).Matched);
        string label = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789";
        var hit = await See(Query(qname: label + ".exfil.invalid"), 19);
        var evt = Assert.Single(hit.Events);
        Assert.Equal(SeverityLevel.High, evt.Severity);
        Assert.Equal(20, evt.Count);
        Assert.DoesNotContain(label, evt.Description, StringComparison.Ordinal);
    }

    [Fact]
    public async Task Forty_Dns_Responses_Cannot_Inflate_Request_Counts()
    {
        for (int i = 0; i < 40; i++)
        {
            var response = Query();
            response.DnsIsResponse = true;
            Assert.False((await See(response, i)).Matched);
        }
        for (int i = 0; i < 19; i++)
            Assert.False((await See(Query(), 50 + i)).Matched);
        Assert.Equal(20, Assert.Single((await See(Query(), 69)).Events).Count);
    }

    [Fact]
    public async Task Missing_Or_Invalid_Query_Evidence_And_Port_Only_Noise_Do_Not_Prime_State()
    {
        var missing = Query(qname: null);
        var malformed = Query(qname: "bad label.example.invalid");
        var emptyDestination = Query(destination: null);
        var wrongTransport = Query();
        wrongTransport.Protocol = "TCP";
        var portNoise = Query();
        portNoise.Protocol = "UDP";
        portNoise.DnsQname = null;
        var badPort = Query();
        badPort.DestinationPort = 65536;
        foreach (var record in new[] { missing, malformed, emptyDestination, wrongTransport, portNoise, badPort })
            Assert.False((await See(record, 0)).Matched);
        for (int i = 0; i < 19; i++)
            Assert.False((await See(Query(), i + 1)).Matched);
        Assert.Equal(20, Assert.Single((await See(Query(), 20)).Events).Count);
    }

    [Fact]
    public async Task Future_Dated_Query_Does_Not_Complete_A_Current_Window()
    {
        Assert.False((await See(Query(), 1000)).Matched);
        for (int i = 0; i < 19; i++)
            Assert.False((await See(Query(), i)).Matched);
        Assert.Equal(20, Assert.Single((await See(Query(), 19)).Events).Count);
    }

    [Fact]
    public async Task Different_Sources_Do_Not_Combine_Dns_Volume()
    {
        for (int i = 0; i < 19; i++)
        {
            Assert.False((await See(Query(source: "10.206.0.11"), i)).Matched);
            Assert.False((await See(Query(source: "10.206.0.12"), i)).Matched);
        }
        var first = await See(Query(source: "10.206.0.11"), 19);
        Assert.Equal("10.206.0.11", Assert.Single(first.Events).SourceIp);
        var second = await See(Query(source: "10.206.0.12"), 19);
        Assert.Equal("10.206.0.12", Assert.Single(second.Events).SourceIp);
    }

    [Fact]
    public async Task Expired_Queries_Do_Not_Complete_A_New_Burst()
    {
        for (int i = 0; i < 19; i++)
            Assert.False((await See(Query(), i)).Matched);
        Assert.False((await See(Query(), 100)).Matched);
        for (int i = 1; i < 19; i++)
            Assert.False((await See(Query(), 100 + i)).Matched);
        Assert.Equal(20, Assert.Single((await See(Query(), 119)).Events).Count);
    }
}
