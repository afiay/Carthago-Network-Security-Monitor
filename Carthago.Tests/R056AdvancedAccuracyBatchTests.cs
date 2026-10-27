// SPDX-License-Identifier: MIT
using System;
using System.Threading;
using System.Threading.Tasks;
using Carthago.Engine.Rules;
using Carthago.Engine.Rules.Health;
using Carthago.Models;
using Carthago.Services;
using Xunit;

namespace Carthago.Tests;

public sealed class R056AdvancedAccuracyBatchTests
{
    private readonly R056_TimeSkewClockJumpRule _rule = new();
    private static readonly DateTime T0 = new(2026, 10, 27, 10, 0, 0, DateTimeKind.Utc);

    private static RuleEvaluationContext At(int seconds, double skewSeconds,
        DateTime? observedAt = null)
    {
        var now = T0.AddSeconds(seconds);
        var health = new RuleEngineHealthSnapshot(observedAt ?? now, null, 0,
            0, 0, 0, 0, null, TimeSpan.FromSeconds(skewSeconds));
        return new RuleEvaluationContext(new TrafficRecord(), Sensitivity.Balanced, now, health);
    }

    [Fact] public async Task Fresh_Positive_Clock_Jump_Matches_Without_Leaking_Offset()
    {
        var evt = Assert.Single((await _rule.EvaluateAsync(At(0, 61))).Events);
        Assert.Equal("R056", evt.RuleId);
        Assert.Equal("carthago-engine", evt.SourceIp);
        Assert.DoesNotContain("61s", evt.Description);
    }

    [Fact] public async Task Existing_Inclusive_Sixty_Second_Threshold_Is_Preserved()
    {
        Assert.True((await _rule.EvaluateAsync(At(0, 60))).Matched);
    }

    [Fact] public async Task Just_Below_Threshold_Is_Benign()
    {
        Assert.False((await _rule.EvaluateAsync(At(0, 59.999))).Matched);
        Assert.False((await _rule.EvaluateAsync(At(1, -59))).Matched);
    }

    [Fact] public async Task Repeated_And_Duplicate_Health_Snapshots_Do_Not_Spam()
    {
        Assert.True((await _rule.EvaluateAsync(At(0, 65))).Matched);
        Assert.False((await _rule.EvaluateAsync(At(0, 65))).Matched);
        Assert.False((await _rule.EvaluateAsync(At(1, 80))).Matched);
    }

    [Fact] public async Task Recovery_Rearms_A_New_Clock_Jump_Episode()
    {
        Assert.True((await _rule.EvaluateAsync(At(0, 80))).Matched);
        Assert.False((await _rule.EvaluateAsync(At(1, 10))).Matched);
        Assert.True((await _rule.EvaluateAsync(At(2, 80))).Matched);
    }

    [Fact] public async Task Sign_Reversal_Is_A_New_Corroborated_Clock_Episode()
    {
        Assert.True((await _rule.EvaluateAsync(At(0, 80))).Matched);
        Assert.True((await _rule.EvaluateAsync(At(1, -80))).Matched);
        Assert.False((await _rule.EvaluateAsync(At(2, -90))).Matched);
    }

    [Fact] public async Task Stale_Future_And_Unspecified_Snapshot_Times_Are_Rejected()
    {
        Assert.False((await _rule.EvaluateAsync(At(0, 80, T0.AddMinutes(-2)))).Matched);
        Assert.False((await _rule.EvaluateAsync(At(0, 80, T0.AddSeconds(1)))).Matched);
        Assert.False((await _rule.EvaluateAsync(At(0, 80,
            DateTime.SpecifyKind(T0, DateTimeKind.Unspecified)))).Matched);
    }

    [Fact] public async Task Out_Of_Order_Snapshot_Does_Not_Rearm()
    {
        Assert.True((await _rule.EvaluateAsync(At(2, 80))).Matched);
        Assert.False((await _rule.EvaluateAsync(At(1, 10))).Matched);
        Assert.False((await _rule.EvaluateAsync(At(3, 90))).Matched);
    }

    [Fact] public async Task Cancellation_Prevents_Health_Alert()
    {
        using var cts = new CancellationTokenSource(); cts.Cancel();
        await Assert.ThrowsAnyAsync<OperationCanceledException>(async () =>
            await _rule.EvaluateAsync(At(0, 80), cts.Token));
    }
}
