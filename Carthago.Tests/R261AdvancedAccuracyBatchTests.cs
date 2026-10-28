// SPDX-License-Identifier: MIT
using System;
using System.Threading.Tasks;
using Carthago.Engine.Rules;
using Carthago.Engine.Rules.Expansion;
using Carthago.Models;
using Xunit;

namespace Carthago.Tests;
public sealed class R261AdvancedAccuracyBatchTests
{
    private static TrafficRecord Sample() => NetworkBatch261265Context.Sample(261);
    private static RuleEvaluationContext At(TrafficRecord r, double seconds = 0)
        => NetworkBatch261265Context.At(r, seconds);
    private static async Task<bool> Hit(TrafficRecord r)
        => (await new R261_TtlAnomalyToSameServiceRule().EvaluateAsync(At(r))).Matched;
    [Fact] public async Task Three_Distinct_Typed_Ttl_Observations_Produce_Path_Anomaly() {
        var rule = new R261_TtlAnomalyToSameServiceRule();
        Assert.False((await rule.EvaluateAsync(At(Sample(), 0))).Matched);
        Assert.False((await rule.EvaluateAsync(At(Sample(), 1))).Matched);
        var changed = Sample(); changed.TTL = "32";
        Assert.True((await rule.EvaluateAsync(At(changed, 2))).Matched);
    }
    [Fact] public async Task Stable_Ttl_Is_Benign() {
        var rule = new R261_TtlAnomalyToSameServiceRule();
        for (var i = 0; i < 4; i++) Assert.False((await rule.EvaluateAsync(At(Sample(), i))).Matched);
    }
    [Fact] public async Task Packet_Info_Cannot_Fabricate_Ttl() {
        var r = Sample(); r.TTL = null; r.Info = "ttl mismatch ttl=32";
        Assert.False(await Hit(r));
    }
    [Fact] public async Task Malformed_Ttl_Is_Rejected() {
        var r = Sample(); r.TTL = "999"; Assert.False(await Hit(r));
    }
    [Fact] public async Task Duplicate_And_Out_Of_Order_Are_Ignored() {
        var rule = new R261_TtlAnomalyToSameServiceRule(); var first = Sample();
        Assert.False((await rule.EvaluateAsync(At(first, 10))).Matched);
        first.TTL = "32"; Assert.False((await rule.EvaluateAsync(At(first, 11))).Matched);
        var old = Sample(); old.TTL = "32"; Assert.False((await rule.EvaluateAsync(At(old, 1))).Matched);
    }
    [Fact] public async Task Independent_Destinations_Do_Not_Mix() {
        var rule = new R261_TtlAnomalyToSameServiceRule();
        Assert.False((await rule.EvaluateAsync(At(Sample()))).Matched);
        var second = Sample(); second.Destination = "198.51.100.62"; second.TTL = "32";
        Assert.False((await rule.EvaluateAsync(At(second, 1))).Matched);
    }
    [Fact] public async Task Observation_Outside_Window_Does_Not_Complete_Sequence() {
        var rule = new R261_TtlAnomalyToSameServiceRule();
        Assert.False((await rule.EvaluateAsync(At(Sample()))).Matched);
        Assert.False((await rule.EvaluateAsync(At(Sample(), 901))).Matched);
        var changed = Sample(); changed.TTL = "32";
        Assert.False((await rule.EvaluateAsync(At(changed, 902))).Matched);
    }
    [Fact] public async Task Info_Is_Not_Emitted_In_Matched_Evidence() {
        var rule = new R261_TtlAnomalyToSameServiceRule();
        Assert.False((await rule.EvaluateAsync(At(Sample()))).Matched);
        Assert.False((await rule.EvaluateAsync(At(Sample(), 1))).Matched);
        var changed = Sample(); changed.TTL = "32"; changed.Info = "secret-marker";
        var evt = Assert.Single((await rule.EvaluateAsync(At(changed, 2))).Events);
        Assert.DoesNotContain("secret-marker", evt.Evidence ?? "", StringComparison.Ordinal);
    }
    [Fact] public void Original_Confidence_Threshold_And_Mode_Are_Preserved() {
        var p = new R261_TtlAnomalyToSameServiceRule().PrecisionProfile;
        Assert.Equal(75, p.MinimumConfidence);
        Assert.Equal(3, p.Threshold);
        Assert.Equal(RuleRuntimeMode.Alert, p.DefaultMode);
    }
}
