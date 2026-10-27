// SPDX-License-Identifier: MIT
using System;
using System.Threading;
using System.Threading.Tasks;
using Carthago.Engine.Rules.Health;
using Xunit;

namespace Carthago.Tests;

public sealed class R055AdvancedAccuracyBatchTests
{
    private readonly R055_ThreatFeedStaleRule _rule = new();
    private static readonly DateTime T0 = HealthBatch051055Context.T0;
    private static DateTime Feed(int hoursAgo) => T0.AddHours(-hoursAgo);

    [Fact] public async Task More_Than_24_Hours_Without_Feed_Update_Alerts()
    {
        var evt = Assert.Single((await _rule.EvaluateAsync(
            HealthBatch051055Context.At(feed: Feed(25)))).Events);
        Assert.Equal("R055", evt.RuleId);
        Assert.Equal("carthago-engine", evt.SourceIp);
        Assert.Contains("Threat feed stale", evt.Summary);
    }
    [Fact] public async Task Exactly_24_Hours_Is_Not_Stale()
    {
        Assert.False((await _rule.EvaluateAsync(
            HealthBatch051055Context.At(feed: Feed(24)))).Matched);
    }
    [Fact] public async Task Missing_Feed_Timestamp_Cannot_Establish_Staleness()
    {
        Assert.False((await _rule.EvaluateAsync(HealthBatch051055Context.At())).Matched);
    }
    [Fact] public async Task Future_And_Unspecified_Feed_Timestamps_Are_Excluded()
    {
        Assert.False((await _rule.EvaluateAsync(HealthBatch051055Context.At(
            feed: T0.AddHours(2)))).Matched);
        Assert.False((await _rule.EvaluateAsync(HealthBatch051055Context.At(
            feed: DateTime.SpecifyKind(Feed(25), DateTimeKind.Unspecified)))).Matched);
    }
    [Fact] public async Task Same_Stale_Feed_Does_Not_Alert_On_Every_Packet()
    {
        Assert.True((await _rule.EvaluateAsync(HealthBatch051055Context.At(
            feed: Feed(25)))).Matched);
        Assert.False((await _rule.EvaluateAsync(HealthBatch051055Context.At(
            1, feed: Feed(25)))).Matched);
        Assert.False((await _rule.EvaluateAsync(HealthBatch051055Context.At(
            2, feed: Feed(25)))).Matched);
    }
    [Fact] public async Task Fresh_Feed_Update_Rearms_The_Next_Stale_Episode()
    {
        Assert.True((await _rule.EvaluateAsync(HealthBatch051055Context.At(
            feed: Feed(25)))).Matched);
        Assert.False((await _rule.EvaluateAsync(HealthBatch051055Context.At(
            1, feed: T0))).Matched);
        Assert.True((await _rule.EvaluateAsync(HealthBatch051055Context.At(
            25 * 3600, feed: T0))).Matched);
    }
    [Fact] public async Task Out_Of_Order_Observations_Do_Not_Repeat_Alerts()
    {
        Assert.True((await _rule.EvaluateAsync(HealthBatch051055Context.At(
            2, feed: Feed(25)))).Matched);
        Assert.False((await _rule.EvaluateAsync(HealthBatch051055Context.At(
            1, feed: Feed(26)))).Matched);
    }
    [Fact] public async Task Missing_Feed_After_Alert_Does_Not_Rearm_Same_Incident()
    {
        Assert.True((await _rule.EvaluateAsync(HealthBatch051055Context.At(
            feed: Feed(25)))).Matched);
        Assert.False((await _rule.EvaluateAsync(HealthBatch051055Context.At(1))).Matched);
        Assert.False((await _rule.EvaluateAsync(HealthBatch051055Context.At(
            2, feed: Feed(25)))).Matched);
    }
    [Fact] public async Task Stale_Future_And_Unspecified_Health_Snapshots_Are_Rejected()
    {
        Assert.False((await _rule.EvaluateAsync(HealthBatch051055Context.At(
            feed: Feed(25), observedAt: T0.AddMinutes(-2)))).Matched);
        Assert.False((await _rule.EvaluateAsync(HealthBatch051055Context.At(
            feed: Feed(25), observedAt: T0.AddSeconds(1)))).Matched);
        Assert.False((await _rule.EvaluateAsync(HealthBatch051055Context.At(
            feed: Feed(25), observedAt: DateTime.SpecifyKind(T0, DateTimeKind.Unspecified)))).Matched);
    }
    [Fact] public async Task Cancellation_Prevents_Staleness_Alert()
    {
        using var cts = new CancellationTokenSource(); cts.Cancel();
        await Assert.ThrowsAnyAsync<OperationCanceledException>(async () =>
        { await _rule.EvaluateAsync(HealthBatch051055Context.At(feed: Feed(25)), cts.Token); });
    }
}
