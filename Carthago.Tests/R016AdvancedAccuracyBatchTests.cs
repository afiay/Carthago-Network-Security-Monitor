// SPDX-License-Identifier: MIT
using System;
using System.Threading.Tasks;
using Carthago.Engine.Rules;
using Carthago.Engine.Rules.Existing;
using Carthago.Models;
using Carthago.Services;
using Xunit;

namespace Carthago.Tests;

/// <summary>R016: destination reputation provenance, freshness and contradiction controls.</summary>
[Collection("Legacy rules R011-R015 isolated")]
public sealed class R016AdvancedAccuracyBatchTests : IDisposable
{
    private readonly R016_ReputationAbuseIpdbRule _rule = new();
    private static readonly DateTime T0 = new(2026, 10, 27, 3, 0, 0, DateTimeKind.Utc);
    public R016AdvancedAccuracyBatchTests() => RuleEngine.ResetRuntimeStateForReplay();
    public void Dispose() => RuleEngine.ResetRuntimeStateForReplay();

    private static TrafficRecord Flow(int? score = 85, string source = "10.16.0.2",
        string destination = "8.8.8.8")
        => new() { Source = source, Destination = destination, Protocol = "TCP",
            DestinationPort = 443, Length = 120, ReputationScore = score,
            ReputationIsMalicious = true, ReputationReports = 8,
            ReputationLastSeen = T0.AddDays(-1) };

    private async Task<RuleEvaluationResult> See(TrafficRecord record, int second = 0)
        => await _rule.EvaluateAsync(new RuleEvaluationContext(record, Sensitivity.Balanced, T0.AddSeconds(second)));

    [Fact]
    public async Task Corroborated_Public_Destination_Score_Produces_Attributed_High_Event()
    {
        var evt = Assert.Single((await See(Flow())).Events);
        Assert.Equal("R016", evt.RuleId);
        Assert.Equal("8.8.8.8", evt.DestinationIp);
        Assert.Equal(85, evt.Count);
        Assert.Equal(SeverityLevel.High, evt.Severity);
        Assert.DoesNotContain("10.16.0.2", evt.Description);
    }

    [Fact]
    public async Task Critical_Severity_Uses_Existing_Ninety_Point_Boundary()
    {
        var evt = Assert.Single((await See(Flow(90))).Events);
        Assert.Equal(SeverityLevel.Critical, evt.Severity);
        Assert.Equal(90, evt.Count);
    }

    [Fact]
    public async Task Score_Only_Legacy_Enrichment_Remains_A_Review_Candidate()
    {
        var record = Flow(75);
        record.ReputationIsMalicious = null;
        record.ReputationReports = null;
        record.ReputationLastSeen = null;
        Assert.Equal(75, Assert.Single((await See(record)).Events).Count);
    }

    [Fact]
    public async Task Missing_Below_Floor_And_Out_Of_Range_Scores_Are_Rejected()
    {
        foreach (int? score in new int?[] { null, -1, 0, 74, 101, 999 })
            Assert.False((await See(Flow(score))).Matched);
    }

    [Fact]
    public async Task Contradictory_Benign_Classification_Or_Zero_Reports_Cannot_Trigger()
    {
        var benign = Flow(); benign.ReputationIsMalicious = false;
        var noReports = Flow(); noReports.ReputationReports = 0;
        var negativeReports = Flow(); negativeReports.ReputationReports = -3;
        foreach (var record in new[] { benign, noReports, negativeReports })
            Assert.False((await See(record)).Matched);
    }

    [Fact]
    public async Task Future_And_Stale_Enrichment_Cannot_Override_Observation_Time()
    {
        var future = Flow(); future.ReputationLastSeen = T0.AddHours(1);
        var stale = Flow(); stale.ReputationLastSeen = T0.AddDays(-31);
        Assert.False((await See(future)).Matched);
        Assert.False((await See(stale)).Matched);
    }

    [Fact]
    public async Task Malformed_Private_Loopback_And_Documentation_Endpoints_Are_Excluded()
    {
        foreach (var destination in new[] { "not-an-ip", "10.0.0.9", "127.0.0.1", "192.0.2.9", "198.51.100.2" })
            Assert.False((await See(Flow(destination: destination))).Matched);
        Assert.False((await See(Flow(source: "not-an-ip"))).Matched);
    }

    [Fact]
    public async Task Cooldown_Is_Per_Source_Destination_And_Preserves_Distinct_Evidence()
    {
        Assert.True((await See(Flow())).Matched);
        var duplicate = await See(Flow(), 1);
        Assert.True(duplicate.Suppressed);
        Assert.Empty(duplicate.Events);
        Assert.Equal("9.9.9.9", Assert.Single((await See(Flow(destination: "9.9.9.9"), 1)).Events).DestinationIp);
    }
}
