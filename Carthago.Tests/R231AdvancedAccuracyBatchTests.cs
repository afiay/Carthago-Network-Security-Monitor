// SPDX-License-Identifier: MIT
using System;
using System.Threading.Tasks;
using Carthago.Engine.Rules;
using Carthago.Engine.Rules.Expansion;
using Carthago.Models;
using Xunit;

namespace Carthago.Tests;
public sealed class R231AdvancedAccuracyBatchTests
{
    private static TrafficRecord Sample() => NetworkBatch231235Context.Sample(231);
    private static RuleEvaluationContext At(TrafficRecord r, int seconds = 0)
        => NetworkBatch231235Context.At(r, seconds);
    private static async Task<bool> Hit(TrafficRecord r)
        => (await new R231_CoapMulticastDiscoveryBurstRule().EvaluateAsync(At(r))).Matched;

    [Fact] public async Task Ten_Parsed_Coap_Get_Discovery_Packets_Match()
    {
        var rule = new R231_CoapMulticastDiscoveryBurstRule(); var source = Sample().Source;
        for (int i = 0; i < 9; i++)
        {
            var r = Sample(); r.Source = source;
            Assert.False((await rule.EvaluateAsync(At(r, i))).Matched);
        }
        var last = Sample(); last.Source = source;
        Assert.True((await rule.EvaluateAsync(At(last, 9))).Matched);
    }
    [Fact] public async Task Isolated_Discovery_Is_Benign()
        => Assert.False(await Hit(Sample()));
    [Fact] public async Task Info_Spoof_Without_Decoded_Coap_Is_Rejected()
    {
        var r = Sample(); r.ApplicationProtocol = null; r.Info = "GET /.well-known/core CoAP";
        Assert.False(await Hit(r));
    }
    [Fact] public async Task Non_Discovery_Coap_Traffic_Does_Not_Count()
    {
        var r = Sample(); r.ApplicationProtocol = "coap";
        Assert.False(await Hit(r));
    }
    [Fact] public async Task Contradictory_Tcp_Flags_Are_Rejected()
    {
        var r = Sample(); r.IsTcp = true;
        Assert.False(await Hit(r));
    }
    [Fact] public async Task Duplicate_Packet_Cannot_Fill_Burst()
    {
        var rule = new R231_CoapMulticastDiscoveryBurstRule(); var r = Sample();
        for (int i = 0; i < 10; i++)
            Assert.False((await rule.EvaluateAsync(At(r, i))).Matched);
    }
    [Fact] public async Task Independent_Sources_Do_Not_Join_Burst()
    {
        var rule = new R231_CoapMulticastDiscoveryBurstRule();
        var a = Sample().Source; var b = Sample().Source;
        for (int i = 0; i < 5; i++)
        {
            var r = Sample(); r.Source = a;
            Assert.False((await rule.EvaluateAsync(At(r, i))).Matched);
            r = Sample(); r.Source = b;
            Assert.False((await rule.EvaluateAsync(At(r, i))).Matched);
        }
    }
    [Fact] public async Task Out_Of_Order_Packet_Does_Not_Advance_Count()
    {
        var rule = new R231_CoapMulticastDiscoveryBurstRule(); var r = Sample();
        Assert.False((await rule.EvaluateAsync(At(r, 20))).Matched);
        var old = Sample(); old.Source = r.Source;
        Assert.False((await rule.EvaluateAsync(At(old, 5))).Matched);
    }
    [Fact] public void Original_Shadow_And_Confidence_Floor()
    {
        var p = new R231_CoapMulticastDiscoveryBurstRule().PrecisionProfile;
        Assert.Equal(76, p.MinimumConfidence); Assert.Equal(RuleRuntimeMode.Shadow, p.DefaultMode);
    }
}
