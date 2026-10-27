// SPDX-License-Identifier: MIT
using System;
using System.Threading;
using System.Threading.Tasks;
using Carthago.Engine.Rules.Health;
using Xunit;

namespace Carthago.Tests;

public sealed class R051AdvancedAccuracyBatchTests
{
    private readonly R051_PacketCaptureDropSurgeRule _rule = new();

    [Fact] public async Task Observed_Drop_Delta_Produces_Attributable_Health_Alert()
    {
        var evt = Assert.Single((await _rule.EvaluateAsync(HealthBatch051055Context.At(drops: 4))).Events);
        Assert.Equal("R051", evt.RuleId);
        Assert.Equal("carthago-engine", evt.SourceIp);
        Assert.Contains("4 packets", evt.Summary);
    }
    [Fact] public async Task Zero_And_Negative_Deltas_Do_Not_Alert()
    {
        Assert.False((await _rule.EvaluateAsync(HealthBatch051055Context.At(drops: 0))).Matched);
        Assert.False((await _rule.EvaluateAsync(HealthBatch051055Context.At(1, drops: -2))).Matched);
    }
    [Fact] public async Task Duplicate_Snapshot_Cannot_Replay_An_Alert()
    {
        var c = HealthBatch051055Context.At(drops: 2);
        Assert.True((await _rule.EvaluateAsync(c)).Matched);
        Assert.False((await _rule.EvaluateAsync(c)).Matched);
    }
    [Fact] public async Task Distinct_Fresh_Drop_Intervals_Both_Alert()
    {
        Assert.True((await _rule.EvaluateAsync(HealthBatch051055Context.At(drops: 1))).Matched);
        Assert.True((await _rule.EvaluateAsync(HealthBatch051055Context.At(1, drops: 3))).Matched);
    }
    [Fact] public async Task Older_Snapshot_After_Newer_One_Is_Ignored()
    {
        Assert.True((await _rule.EvaluateAsync(HealthBatch051055Context.At(2, drops: 1))).Matched);
        Assert.False((await _rule.EvaluateAsync(HealthBatch051055Context.At(1, drops: 5))).Matched);
    }
    [Fact] public async Task Zero_Drop_Interval_Rearms_For_Later_New_Drops()
    {
        Assert.True((await _rule.EvaluateAsync(HealthBatch051055Context.At(drops: 1))).Matched);
        Assert.False((await _rule.EvaluateAsync(HealthBatch051055Context.At(1))).Matched);
        Assert.True((await _rule.EvaluateAsync(HealthBatch051055Context.At(2, drops: 1))).Matched);
    }
    [Fact] public async Task Stale_And_Future_Snapshots_Are_Not_Evidence()
    {
        Assert.False((await _rule.EvaluateAsync(HealthBatch051055Context.At(drops: 3,
            observedAt: HealthBatch051055Context.T0.AddMinutes(-2)))).Matched);
        Assert.False((await _rule.EvaluateAsync(HealthBatch051055Context.At(drops: 3,
            observedAt: HealthBatch051055Context.T0.AddMinutes(1)))).Matched);
    }
    [Fact] public async Task Unspecified_Snapshot_Clock_Is_Not_Trusted()
    {
        Assert.False((await _rule.EvaluateAsync(HealthBatch051055Context.At(drops: 1,
            observedAt: DateTime.SpecifyKind(HealthBatch051055Context.T0, DateTimeKind.Unspecified)))).Matched);
    }
    [Fact] public async Task Cancellation_Stops_Evaluation()
    {
        using var cts = new CancellationTokenSource(); cts.Cancel();
        await Assert.ThrowsAnyAsync<OperationCanceledException>(async () =>
        { await _rule.EvaluateAsync(HealthBatch051055Context.At(drops: 1), cts.Token); });
    }
}
