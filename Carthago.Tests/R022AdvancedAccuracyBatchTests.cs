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
public sealed class R022AdvancedAccuracyBatchTests : IDisposable
{
    private readonly R022_DnsNxdomainSpikeRule _rule = new();
    private static readonly DateTime T0 = new(2026, 10, 27, 0, 0, 0, DateTimeKind.Utc);
    public R022AdvancedAccuracyBatchTests() => RuleEngine.ResetRuntimeStateForReplay();
    public void Dispose() => RuleEngine.ResetRuntimeStateForReplay();
    private async Task<RuleEvaluationResult> See(TrafficRecord record, int second = 0)
        => await _rule.EvaluateAsync(new RuleEvaluationContext(record, Sensitivity.Balanced, T0.AddSeconds(second)));

    private static TrafficRecord Response(string client = "10.22.0.2", string resolver = "8.8.8.8", string rcode = "NXDOMAIN")
        => new() { Protocol = "DNS", Source = resolver, Destination = client,
            SourcePort = 53, DestinationPort = 53000, Length = 96, DnsIsResponse = true,
            DnsRcode = rcode, DnsQname = "absent.example", Info = "DNS response NXDOMAIN" };


    [Fact] public async Task Thirty_Observed_Negative_Responses_Attribute_The_Client()
    {
        for (int i = 0; i < 29; i++) Assert.False((await See(Response(), i)).Matched);
        var evt = Assert.Single((await See(Response(), 29)).Events);
        Assert.Equal("R022", evt.RuleId);
        Assert.Equal("10.22.0.2", evt.SourceIp);
        Assert.Equal("8.8.8.8", evt.DestinationIp);
        Assert.Equal(30, evt.Count);
    }
    [Fact] public async Task Queries_And_Successful_Responses_Do_Not_Count_As_Nxdomain()
    {
        for (int i = 0; i < 29; i++) await See(Response(), i);
        var query = Response(); query.DnsIsResponse = false;
        Assert.False((await See(query, 29)).Matched);
        Assert.False((await See(Response(rcode: "NOERROR"), 30)).Matched);
        Assert.True((await See(Response(), 31)).Matched);
    }
    [Fact] public async Task Structured_Rcode_Overrides_Contradictory_Free_Text()
    {
        var record = Response(rcode: "NOERROR");
        for (int i = 0; i < 40; i++) Assert.False((await See(record, i)).Matched);
        Assert.False((await See(Response(rcode: "SERVFAIL"), 40)).Matched);
    }
    [Fact] public async Task Separate_Clients_And_Resolvers_Are_Not_Coalesced()
    {
        for (int i = 0; i < 29; i++)
        {
            await See(Response(client: "10.22.0.2"), i);
            await See(Response(client: "10.22.0.3"), i);
        }
        Assert.Equal("10.22.0.3", Assert.Single((await See(Response(client: "10.22.0.3"), 29)).Events).SourceIp);
    }
    [Fact] public async Task Duplicate_Capture_Timestamp_Does_Not_Create_Thirty_Responses()
    {
        for (int i = 0; i < 50; i++) Assert.False((await See(Response(), 0)).Matched);
        for (int i = 1; i < 29; i++) Assert.False((await See(Response(), i)).Matched);
        Assert.True((await See(Response(), 29)).Matched);
    }
    [Fact] public async Task Malformed_Endpoints_And_Absent_Dns_Responses_Do_Not_Prime()
    {
        var invalid = Response(); invalid.Destination = "not-an-ip";
        var empty = Response(); empty.Length = 0;
        var unrelated = Response(); unrelated.Protocol = "TCP";
        foreach (var r in new[] { invalid, empty, unrelated })
            Assert.False((await See(r)).Matched);
        for (int i = 0; i < 29; i++) Assert.False((await See(Response(), i)).Matched);
        Assert.True((await See(Response(), 29)).Matched);
    }

}
