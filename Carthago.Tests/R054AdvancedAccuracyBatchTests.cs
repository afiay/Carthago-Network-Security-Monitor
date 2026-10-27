// SPDX-License-Identifier: MIT
using System;
using System.Threading;
using System.Threading.Tasks;
using Carthago.Engine.Rules.Health;
using Xunit;

namespace Carthago.Tests;

public sealed class R054AdvancedAccuracyBatchTests
{
    private readonly R054_RuleConfigReloadFailureRule _rule = new();

    [Fact] public async Task New_Operational_Failure_Emits_Attributable_Alert()
    {
        var evt = Assert.Single((await _rule.EvaluateAsync(HealthBatch051055Context.At(reload: 1))).Events);
        Assert.Equal("R054", evt.RuleId);
        Assert.Equal("carthago-engine", evt.SourceIp);
        Assert.Equal("health", evt.Protocol);
        Assert.Contains("Count=1", evt.Summary);
    }
    [Fact] public async Task Zero_And_Negative_Counters_Cannot_Claim_Failure()
    {
        Assert.False((await _rule.EvaluateAsync(HealthBatch051055Context.At(reload: 0))).Matched);
        Assert.False((await _rule.EvaluateAsync(HealthBatch051055Context.At(1, reload: -1))).Matched);
    }
    [Fact] public async Task Unchanged_Cumulative_Counter_Is_Not_A_New_Incident()
    {
        Assert.True((await _rule.EvaluateAsync(HealthBatch051055Context.At(reload: 2))).Matched);
        Assert.False((await _rule.EvaluateAsync(HealthBatch051055Context.At(1, reload: 2))).Matched);
        Assert.False((await _rule.EvaluateAsync(HealthBatch051055Context.At(2, reload: 2))).Matched);
    }
    [Fact] public async Task Counter_Increase_Produces_One_New_Incident()
    {
        Assert.True((await _rule.EvaluateAsync(HealthBatch051055Context.At(reload: 1))).Matched);
        Assert.True((await _rule.EvaluateAsync(HealthBatch051055Context.At(1, reload: 2))).Matched);
        Assert.False((await _rule.EvaluateAsync(HealthBatch051055Context.At(2, reload: 2))).Matched);
    }
    [Fact] public async Task Counter_Reset_Does_Not_Manufacture_An_Incident()
    {
        Assert.True((await _rule.EvaluateAsync(HealthBatch051055Context.At(reload: 5))).Matched);
        Assert.False((await _rule.EvaluateAsync(HealthBatch051055Context.At(1, reload: 0))).Matched);
        Assert.True((await _rule.EvaluateAsync(HealthBatch051055Context.At(2, reload: 1))).Matched);
    }
    [Fact] public async Task Decreasing_Positive_Counter_Is_Treated_As_New_Baseline()
    {
        Assert.True((await _rule.EvaluateAsync(HealthBatch051055Context.At(reload: 8))).Matched);
        Assert.False((await _rule.EvaluateAsync(HealthBatch051055Context.At(1, reload: 3))).Matched);
        Assert.True((await _rule.EvaluateAsync(HealthBatch051055Context.At(2, reload: 4))).Matched);
    }
    [Fact] public async Task Out_Of_Order_And_Duplicate_Snapshots_Are_Ignored()
    {
        Assert.True((await _rule.EvaluateAsync(HealthBatch051055Context.At(2, reload: 1))).Matched);
        Assert.False((await _rule.EvaluateAsync(HealthBatch051055Context.At(1, reload: 2))).Matched);
        Assert.False((await _rule.EvaluateAsync(HealthBatch051055Context.At(2, reload: 2))).Matched);
        Assert.True((await _rule.EvaluateAsync(HealthBatch051055Context.At(3, reload: 2))).Matched);
    }
    [Fact] public async Task Stale_Future_And_Unspecified_Snapshot_Clocks_Are_Excluded()
    {
        Assert.False((await _rule.EvaluateAsync(HealthBatch051055Context.At(reload: 1, observedAt: HealthBatch051055Context.T0.AddMinutes(-2)))).Matched);
        Assert.False((await _rule.EvaluateAsync(HealthBatch051055Context.At(reload: 1, observedAt: HealthBatch051055Context.T0.AddSeconds(1)))).Matched);
        Assert.False((await _rule.EvaluateAsync(HealthBatch051055Context.At(reload: 1, observedAt: DateTime.SpecifyKind(HealthBatch051055Context.T0, DateTimeKind.Unspecified)))).Matched);
    }
    [Fact] public async Task Cancellation_Prevents_Alert_Creation()
    {
        using var cts = new CancellationTokenSource(); cts.Cancel();
        await Assert.ThrowsAnyAsync<OperationCanceledException>(async () =>
        { await _rule.EvaluateAsync(HealthBatch051055Context.At(reload: 1), cts.Token); });
    }
}
