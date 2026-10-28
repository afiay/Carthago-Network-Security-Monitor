// SPDX-License-Identifier: MIT
using System;
using System.Threading.Tasks;
using Carthago.Engine.Rules;
using Carthago.Engine.Rules.Expansion;
using Carthago.Models;
using Xunit;

namespace Carthago.Tests;
public sealed class R254AdvancedAccuracyBatchTests
{
    private static TrafficRecord Sample() => NetworkBatch251255Context.Sample(254);
    private static RuleEvaluationContext At(TrafficRecord r, double seconds = 0)
        => NetworkBatch251255Context.At(r, seconds);
    private static async Task<bool> Hit(TrafficRecord r)
        => (await new R254_RepeatedSmallChunkUploadsRule().EvaluateAsync(At(r))).Matched;

    private static async Task Seed(R254_RepeatedSmallChunkUploadsRule rule, int count,
        string source = "10.254.0.10", double start = 0)
    {
        for (var i = 0; i < count; i++) {
            var r = Sample(); r.Source = source;
            await rule.EvaluateAsync(At(r, start + i));
        }
    }
    [Fact] public async Task Twelve_Distinct_Small_Requests_Match() {
        var rule = new R254_RepeatedSmallChunkUploadsRule();
        await Seed(rule, 11);
        Assert.True((await rule.EvaluateAsync(At(Sample(), 11))).Matched);
    }
    [Fact] public async Task Eleven_Requests_Are_Below_Threshold() {
        var rule = new R254_RepeatedSmallChunkUploadsRule();
        await Seed(rule, 10);
        Assert.False((await rule.EvaluateAsync(At(Sample(), 10))).Matched);
    }
    [Fact] public async Task Duplicate_Id_Does_Not_Inflate_Count() {
        var rule = new R254_RepeatedSmallChunkUploadsRule();
        await Seed(rule, 10);
        var r = Sample();
        Assert.False((await rule.EvaluateAsync(At(r, 10))).Matched);
        Assert.False((await rule.EvaluateAsync(At(r, 11))).Matched);
        Assert.True((await rule.EvaluateAsync(At(Sample(), 12))).Matched);
    }
    [Fact] public async Task Out_Of_Order_Observation_Is_Rejected() {
        var rule = new R254_RepeatedSmallChunkUploadsRule();
        await Seed(rule, 11, start: 20);
        Assert.False((await rule.EvaluateAsync(At(Sample(), 1))).Matched);
        Assert.True((await rule.EvaluateAsync(At(Sample(), 31))).Matched);
    }
    [Fact] public async Task Independent_Sources_Do_Not_Share_Requests() {
        var rule = new R254_RepeatedSmallChunkUploadsRule();
        await Seed(rule, 11);
        var other = Sample(); other.Source = "10.254.0.20";
        Assert.False((await rule.EvaluateAsync(At(other, 11))).Matched);
        Assert.True((await rule.EvaluateAsync(At(Sample(), 12))).Matched);
    }
    [Fact] public async Task Independent_Paths_Do_Not_Share_Requests() {
        var rule = new R254_RepeatedSmallChunkUploadsRule();
        await Seed(rule, 11);
        var other = Sample(); other.HttpUri = "/api/chunks/other";
        Assert.False((await rule.EvaluateAsync(At(other, 11))).Matched);
        Assert.True((await rule.EvaluateAsync(At(Sample(), 12))).Matched);
    }
    [Fact] public async Task Expired_Requests_Do_Not_Count() {
        var rule = new R254_RepeatedSmallChunkUploadsRule();
        await Seed(rule, 11);
        Assert.False((await rule.EvaluateAsync(At(Sample(), 360))).Matched);
    }
    [Fact] public async Task Approved_Sync_Client_Is_Suppressed() {
        var r = Sample(); r.ProcessName = "onedrive.exe"; Assert.False(await Hit(r));
    }
    [Fact] public async Task Request_Path_Is_Redacted() {
        var rule = new R254_RepeatedSmallChunkUploadsRule();
        await Seed(rule, 11);
        var r = Sample(); r.HttpUri = "/api/chunks/part";
        var result = await rule.EvaluateAsync(At(r, 11));
        Assert.True(result.Matched);
        var evt = Assert.Single(result.Events);
        Assert.DoesNotContain("/api/chunks/part", evt.Evidence ?? "", StringComparison.Ordinal);
    }
    [Fact] public void Original_Alert_Mode_And_Threshold_Are_Preserved() {
        var p = new R254_RepeatedSmallChunkUploadsRule().PrecisionProfile;
        Assert.Equal(82, p.MinimumConfidence); Assert.Equal(RuleRuntimeMode.Alert, p.DefaultMode);
        Assert.Equal(12, p.Threshold);
    }
}
