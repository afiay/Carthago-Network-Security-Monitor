// SPDX-License-Identifier: MIT
using System;
using System.Threading.Tasks;
using Carthago.Engine.Rules;
using Carthago.Engine.Rules.Expansion;
using Carthago.Models;
using Xunit;

namespace Carthago.Tests;
public sealed class R226AdvancedAccuracyBatchTests
{
    private static TrafficRecord Sample() => NetworkBatch226230Context.Sample(226);
    private static RuleEvaluationContext At(TrafficRecord r, int seconds = 0)
        => NetworkBatch226230Context.At(r, seconds);
    private static async Task<bool> Hit(TrafficRecord r)
        => (await new R226_EthernetipCipDiscoveryBurstRule().EvaluateAsync(At(r))).Matched;

    [Fact] public async Task Parsed_ListIdentity_Eight_Distinct_Destinations_Match()
    {
        var rule = new R226_EthernetipCipDiscoveryBurstRule();
        var source = Sample().Source;
        for (var i = 0; i < 7; i++)
        {
            var r = Sample(); r.Source = source; r.Destination = "10.227.0." + (30 + i);
            Assert.False((await rule.EvaluateAsync(At(r, i))).Matched);
        }
        var last = Sample(); last.Source = source; last.Destination = "10.227.0.40";
        Assert.True((await rule.EvaluateAsync(At(last, 7))).Matched);
    }
    [Fact] public async Task Isolated_Inventory_Request_Remains_Benign()
        => Assert.False(await Hit(Sample()));
    [Fact] public async Task Info_Claim_And_Port_Without_Parsed_Command_Do_Not_Match()
    {
        var r = Sample(); r.ApplicationProtocol = null; r.Info = "ListIdentity CIP discovery";
        Assert.False(await Hit(r));
    }
    [Fact] public async Task Generic_Cip_Without_ListIdentity_Is_Not_Discovery()
    {
        var r = Sample(); r.ApplicationProtocol = "cip";
        Assert.False(await Hit(r));
    }
    [Fact] public async Task Contradictory_Transport_Is_Rejected()
    {
        var r = Sample(); r.IsUdp = true;
        Assert.False(await Hit(r));
    }
    [Fact] public async Task Duplicate_Id_Does_Not_Complete_Distinct_Target_Window()
    {
        var rule = new R226_EthernetipCipDiscoveryBurstRule(); var source = Sample().Source;
        TrafficRecord? previous = null;
        for (int i = 0; i < 7; i++)
        {
            var r = Sample(); r.Source = source; r.Destination = "10.227.1." + (20 + i);
            Assert.False((await rule.EvaluateAsync(At(r, i))).Matched); previous = r;
        }
        var duplicate = Sample(); duplicate.Source = source; duplicate.Id = previous!.Id;
        duplicate.Destination = "10.227.1.90";
        Assert.False((await rule.EvaluateAsync(At(duplicate, 7))).Matched);
    }
    [Fact] public async Task Independent_Sources_Cannot_Combine_Their_Destinations()
    {
        var rule = new R226_EthernetipCipDiscoveryBurstRule();
        var a = Sample().Source; var b = Sample().Source;
        for (int i = 0; i < 4; i++)
        {
            var r = Sample(); r.Source = a; r.Destination = "10.227.2." + (20 + i);
            Assert.False((await rule.EvaluateAsync(At(r, i))).Matched);
            r = Sample(); r.Source = b; r.Destination = "10.227.3." + (20 + i);
            Assert.False((await rule.EvaluateAsync(At(r, i))).Matched);
        }
    }
    [Fact] public async Task Out_Of_Order_Frame_Does_Not_Advance_Burst()
    {
        var rule = new R226_EthernetipCipDiscoveryBurstRule(); var source = Sample().Source;
        for (int i = 0; i < 7; i++)
        {
            var r = Sample(); r.Source = source; r.Destination = "10.227.4." + (20 + i);
            Assert.False((await rule.EvaluateAsync(At(r, 20 + i))).Matched);
        }
        var old = Sample(); old.Source = source; old.Destination = "10.227.4.90";
        Assert.False((await rule.EvaluateAsync(At(old, 5))).Matched);
    }
    [Fact] public void Original_Shadow_Mode_And_Confidence_Floor_Remain()
    {
        var p = new R226_EthernetipCipDiscoveryBurstRule().PrecisionProfile;
        Assert.Equal(76, p.MinimumConfidence); Assert.Equal(RuleRuntimeMode.Shadow, p.DefaultMode);
    }
}
