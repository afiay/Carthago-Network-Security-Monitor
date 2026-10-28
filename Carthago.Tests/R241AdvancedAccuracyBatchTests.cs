// SPDX-License-Identifier: MIT
using System;
using System.Threading.Tasks;
using Carthago.Engine.Rules;
using Carthago.Engine.Rules.Expansion;
using Carthago.Models;
using Xunit;
namespace Carthago.Tests;
public sealed class R241AdvancedAccuracyBatchTests
{
    private static TrafficRecord Sample() => NetworkBatch241245Context.Sample(241);
    private static RuleEvaluationContext At(TrafficRecord r, int seconds = 0)
        => NetworkBatch241245Context.At(r, seconds);
    private static async Task<bool> Hit(TrafficRecord r)
        => (await new R241_BacnetWhoIsIAmBurstRule().EvaluateAsync(At(r))).Matched;

    [Fact] public async Task Parsed_Independent_Burst_Matches()
    {
        var rule = new R241_BacnetWhoIsIAmBurstRule(); bool matched = false;
        for (int i = 0; i < 15; i++)
            matched = (await rule.EvaluateAsync(At(Sample(), i))).Matched;
        Assert.True(matched);
    }
    [Fact] public async Task Below_Threshold_Remains_Benign()
    {
        var rule = new R241_BacnetWhoIsIAmBurstRule();
        for (int i = 0; i < 14; i++)
            Assert.False((await rule.EvaluateAsync(At(Sample(), i))).Matched);
    }
    [Fact] public async Task Port_And_Info_Cannot_Forge_Parsed_Operation()
    {
        var r = Sample(); r.ApplicationProtocol = null; r.Info = "BACnet Who-Is";
        Assert.False(await Hit(r));
    }
    [Fact] public async Task Generic_Protocol_Without_Operation_Is_Benign()
    {
        var r = Sample(); r.ApplicationProtocol = "bacnet";
        Assert.False(await Hit(r));
    }
    [Fact] public async Task Contradictory_Tcp_Transport_Is_Rejected()
    {
        var r = Sample(); r.IsUdp = false; r.IsTcp = true; r.Protocol = "TCP";
        Assert.False(await Hit(r));
    }
    [Fact] public async Task Wrong_Destination_Port_Is_Rejected()
    {
        var r = Sample(); r.DestinationPort = 47809; r.SourcePort = 51000;
        Assert.False(await Hit(r));
    }
    [Fact] public async Task Duplicate_Id_Cannot_Fill_Threshold()
    {
        var rule = new R241_BacnetWhoIsIAmBurstRule(); var same = Sample();
        for (int i = 0; i < 15; i++)
            Assert.False((await rule.EvaluateAsync(At(same, i))).Matched);
    }
    [Fact] public async Task Independent_Source_Does_Not_Complete_Other_Window()
    {
        var rule = new R241_BacnetWhoIsIAmBurstRule();
        for (int i = 0; i < 14; i++)
            Assert.False((await rule.EvaluateAsync(At(Sample(), i))).Matched);
        var other = Sample(); other.Source = "10.241.0.99";
        Assert.False((await rule.EvaluateAsync(At(other, 15))).Matched);
    }
    [Fact] public async Task Out_Of_Order_Observation_Cannot_Complete_Burst()
    {
        var rule = new R241_BacnetWhoIsIAmBurstRule();
        for (int i = 0; i < 14; i++)
            Assert.False((await rule.EvaluateAsync(At(Sample(), i + 30))).Matched);
        Assert.False((await rule.EvaluateAsync(At(Sample(), 0))).Matched);
    }
    [Fact] public async Task Window_Expiration_Removes_Stale_Packets()
    {
        var rule = new R241_BacnetWhoIsIAmBurstRule();
        Assert.False((await rule.EvaluateAsync(At(Sample(), 0))).Matched);
        for (int i = 0; i < 14; i++)
            Assert.False((await rule.EvaluateAsync(At(Sample(), 121 + i))).Matched);
    }
    [Fact] public async Task Packet_Info_Secret_Is_Not_Emitted()
    {
        var rule = new R241_BacnetWhoIsIAmBurstRule(); RuleEvaluationResult result = null!;
        for (int i = 0; i < 15; i++)
        {
            var r = Sample(); r.Info = "token=private-bacnet-marker";
            result = await rule.EvaluateAsync(At(r, i));
        }
        Assert.True(result.Matched);
        var evt = Assert.Single(result.Events);
        Assert.DoesNotContain("private-bacnet-marker", evt.Evidence ?? "", StringComparison.Ordinal);
        Assert.DoesNotContain(evt.StructuredEvidence!.Items, item => item.Value.Contains("private-bacnet-marker", StringComparison.Ordinal));
    }
    [Fact] public void Existing_Confidence_And_Default_Mode_Are_Preserved()
    {
        var p = new R241_BacnetWhoIsIAmBurstRule().PrecisionProfile;
        Assert.Equal(76, p.MinimumConfidence);
        Assert.Equal(RuleRuntimeMode.Shadow, p.DefaultMode);
    }

}
