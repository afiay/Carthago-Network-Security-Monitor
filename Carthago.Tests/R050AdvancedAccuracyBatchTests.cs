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

public sealed class R050AdvancedAccuracyBatchTests
{
    private readonly R050_RuleExecutionGapRule _rule = new();
    private static readonly DateTime T0 = new(2026, 10, 27, 8, 0, 0, DateTimeKind.Utc);
    private static RuleEvaluationContext Context(DateTime? last, long count = 3)
    {
        var health = new RuleEngineHealthSnapshot(T0, last, count, 0, 0, 0, 0, null, TimeSpan.Zero);
        return new RuleEvaluationContext(new TrafficRecord(), Sensitivity.Balanced, T0, health);
    }

    [Fact] public async Task Corroborated_Eleven_Second_Gap_Matches()
    {
        var e = Assert.Single((await _rule.EvaluateAsync(Context(T0.AddSeconds(-11)))).Events);
        Assert.Equal("R050", e.RuleId);
        Assert.Equal("carthago-engine", e.SourceIp);
    }
    [Fact] public async Task Exactly_Ten_Seconds_Is_Not_An_Execution_Gap()
    {
        Assert.False((await _rule.EvaluateAsync(Context(T0.AddSeconds(-10)))).Matched);
    }
    [Fact] public async Task Fresh_Evaluation_Is_Not_An_Execution_Gap()
    {
        Assert.False((await _rule.EvaluateAsync(Context(T0.AddSeconds(-1)))).Matched);
    }
    [Fact] public async Task Missing_Health_Timestamp_Cannot_Establish_Gap()
    {
        Assert.False((await _rule.EvaluateAsync(Context(null))).Matched);
    }
    [Fact] public async Task Future_Health_Timestamp_Cannot_Establish_Gap()
    {
        Assert.False((await _rule.EvaluateAsync(Context(T0.AddMinutes(5)))).Matched);
    }
    [Fact] public async Task Contradictory_Zero_Evaluation_Count_Cannot_Establish_Gap()
    {
        Assert.False((await _rule.EvaluateAsync(Context(T0.AddMinutes(-5), 0))).Matched);
    }
    [Fact] public async Task Unspecified_Timestamp_Kind_Is_Not_Trusted_Health_Evidence()
    {
        var unknown = DateTime.SpecifyKind(T0.AddMinutes(-5), DateTimeKind.Unspecified);
        Assert.False((await _rule.EvaluateAsync(Context(unknown))).Matched);
    }
    [Fact] public async Task Cancellation_Is_Respected()
    {
        using var cts = new CancellationTokenSource();
        cts.Cancel();
        await Assert.ThrowsAnyAsync<OperationCanceledException>(
            async () => await _rule.EvaluateAsync(Context(T0.AddMinutes(-5)), cts.Token));
    }
}