// SPDX-License-Identifier: MIT
using System;
using System.Threading.Tasks;
using Carthago.Engine.Rules;
using Carthago.Engine.Rules.Expansion;
using Carthago.Models;
using Xunit;

namespace Carthago.Tests;
public sealed class R258AdvancedAccuracyBatchTests
{
    private static TrafficRecord Sample() => NetworkBatch256260Context.Sample(258);
    private static RuleEvaluationContext At(TrafficRecord r, double seconds = 0)
        => NetworkBatch256260Context.At(r, seconds);
    private static async Task<bool> Hit(TrafficRecord r)
        => (await new R258_IcmpDestinationUnreachableSpikeRule().EvaluateAsync(At(r))).Matched;
    private static async Task<bool> Burst(R258_IcmpDestinationUnreachableSpikeRule rule, int count)
    {
        bool hit = false;
        for (var i = 0; i < count; i++) hit = (await rule.EvaluateAsync(At(Sample(), i))).Matched;
        return hit;
    }
    [Fact] public async Task Eight_Distinct_Typed_Unreachables_Match()
        => Assert.True(await Burst(new R258_IcmpDestinationUnreachableSpikeRule(), 8));
    [Fact] public async Task Seven_Are_Below_Threshold()
        => Assert.False(await Burst(new R258_IcmpDestinationUnreachableSpikeRule(), 7));
    [Fact] public async Task Echo_Request_Is_Benign() {
        var r = Sample(); r.IcmpTypeCode = 0x0800; Assert.False(await Hit(r));
    }
    [Fact] public async Task Info_Spoof_Cannot_Replace_Typed_Code() {
        var r = Sample(); r.IcmpTypeCode = null; r.Info = "type 3 destination unreachable";
        Assert.False(await Hit(r));
    }
    [Fact] public async Task Protocol_Contradiction_Is_Rejected() {
        var r = Sample(); r.Protocol = "TCP"; Assert.False(await Hit(r));
    }
    [Fact] public async Task Version_Contradiction_Is_Rejected() {
        var r = Sample(); r.IpVersion = 6; Assert.False(await Hit(r));
    }
    [Fact] public async Task Duplicate_Ids_Do_Not_Count() {
        var rule = new R258_IcmpDestinationUnreachableSpikeRule(); var r = Sample();
        for (var i = 0; i < 9; i++) Assert.False((await rule.EvaluateAsync(At(r, i))).Matched);
    }
    [Fact] public async Task Out_Of_Order_Observations_Are_Rejected() {
        var rule = new R258_IcmpDestinationUnreachableSpikeRule();
        Assert.False((await rule.EvaluateAsync(At(Sample(), 30))).Matched);
        for (var i = 1; i < 8; i++) Assert.False((await rule.EvaluateAsync(At(Sample(), i))).Matched);
    }
    [Fact] public async Task Independent_Sources_Do_Not_Combine() {
        var rule = new R258_IcmpDestinationUnreachableSpikeRule();
        for (var i = 0; i < 12; i++) {
            var r = Sample(); if (i % 2 == 0) r.Source = "10.58.0.11";
            Assert.False((await rule.EvaluateAsync(At(r, i))).Matched);
        }
    }
    [Fact] public async Task Raw_Info_Secrets_Are_Not_In_Evidence() {
        var rule = new R258_IcmpDestinationUnreachableSpikeRule();
        RuleEvaluationResult result = RuleEvaluationResult.NoMatch("R258");
        for (var i = 0; i < 8; i++) {
            var r = Sample(); r.Info = "password=secret-marker";
            result = await rule.EvaluateAsync(At(r, i));
        }
        Assert.DoesNotContain("secret-marker", Assert.Single(result.Events).Evidence ?? "", StringComparison.Ordinal);
    }
    [Fact] public void Original_Alert_Confidence_And_Threshold_Remain() {
        var p = new R258_IcmpDestinationUnreachableSpikeRule().PrecisionProfile;
        Assert.Equal(75, p.MinimumConfidence); Assert.Equal(8, p.Threshold);
        Assert.Equal(RuleRuntimeMode.Alert, p.DefaultMode);
    }
}
