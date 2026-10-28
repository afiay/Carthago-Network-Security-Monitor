// SPDX-License-Identifier: MIT
using System;
using System.Threading.Tasks;
using Carthago.Engine.Rules;
using Carthago.Engine.Rules.Expansion;
using Carthago.Models;
using Xunit;

namespace Carthago.Tests;
public sealed class R262AdvancedAccuracyBatchTests
{
    private static TrafficRecord Sample() => NetworkBatch261265Context.Sample(262);
    private static RuleEvaluationContext At(TrafficRecord r, double seconds = 0)
        => NetworkBatch261265Context.At(r, seconds);
    private static async Task<bool> Hit(TrafficRecord r)
        => (await new R262_SuspiciousPacketFragmentationRule().EvaluateAsync(At(r))).Matched;
    [Fact] public async Task Two_Typed_Tiny_Fragments_Match_Contract() {
        var rule = new R262_SuspiciousPacketFragmentationRule();
        Assert.False((await rule.EvaluateAsync(At(Sample()))).Matched);
        Assert.True((await rule.EvaluateAsync(At(Sample(), 1))).Matched);
    }
    [Fact] public async Task Unpopulated_Capture_Contract_Does_Not_Match() {
        var r = Sample(); r.IpFragmentOffset = null; Assert.False(await Hit(r));
    }
    [Fact] public async Task Packet_Info_Spoof_Cannot_Replace_Typed_Fragment() {
        var r = Sample(); r.IpMoreFragments = null; r.Info = "overlapping tiny fragment";
        Assert.False(await Hit(r));
    }
    [Fact] public async Task Large_Fragment_Payload_Is_Benign() {
        var r = Sample(); r.IpFragmentPayloadLength = 1200; Assert.False(await Hit(r));
    }
    [Fact] public async Task IPv6_Without_Parser_Contract_Is_Rejected() {
        var r = Sample(); r.IpVersion = 6; Assert.False(await Hit(r));
    }
    [Fact] public async Task Contradictory_L7_Is_Rejected() {
        var r = Sample(); r.HttpMethod = "POST"; Assert.False(await Hit(r));
    }
    [Fact] public async Task Duplicate_And_Older_Fragment_Do_Not_Complete_Window() {
        var rule = new R262_SuspiciousPacketFragmentationRule(); var first = Sample();
        Assert.False((await rule.EvaluateAsync(At(first, 20))).Matched);
        Assert.False((await rule.EvaluateAsync(At(first, 21))).Matched);
        Assert.False((await rule.EvaluateAsync(At(Sample(), 1))).Matched);
    }
    [Fact] public async Task Independent_Sources_Are_Isolated() {
        var rule = new R262_SuspiciousPacketFragmentationRule();
        Assert.False((await rule.EvaluateAsync(At(Sample()))).Matched);
        var other = Sample(); other.Source = "10.62.0.10";
        Assert.False((await rule.EvaluateAsync(At(other, 1))).Matched);
    }
    [Fact] public async Task Info_Is_Not_Emitted_In_Matched_Evidence() {
        var rule = new R262_SuspiciousPacketFragmentationRule();
        Assert.False((await rule.EvaluateAsync(At(Sample()))).Matched);
        var second = Sample(); second.Info = "secret-marker";
        var evt = Assert.Single((await rule.EvaluateAsync(At(second, 1))).Events);
        Assert.DoesNotContain("secret-marker", evt.Evidence ?? "", StringComparison.Ordinal);
    }
    [Fact] public void Original_Confidence_Threshold_And_Mode_Are_Preserved() {
        var p = new R262_SuspiciousPacketFragmentationRule().PrecisionProfile;
        Assert.Equal(82, p.MinimumConfidence);
        Assert.Equal(2, p.Threshold);
        Assert.Equal(RuleRuntimeMode.Alert, p.DefaultMode);
    }
}
