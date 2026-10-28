// SPDX-License-Identifier: MIT
using System;
using System.Threading.Tasks;
using Carthago.Engine.Rules;
using Carthago.Engine.Rules.Expansion;
using Carthago.Models;
using Xunit;

namespace Carthago.Tests;
public sealed class R223AdvancedAccuracyBatchTests
{
    private static TrafficRecord Sample() => NetworkBatch221225Context.Flow(223);
    private static RuleEvaluationContext At(TrafficRecord r, int seconds = 0)
        => NetworkBatch221225Context.At(r, seconds);
    private static async Task<bool> Hit(TrafficRecord r)
        => (await new R223_IcsProtocolToInternetRule().EvaluateAsync(At(r))).Matched;

    [Fact] public async Task Typed_L7_Industrial_Protocol_With_Coherent_Transport_Matches()
        => Assert.True(await Hit(Sample()));

    [Fact] public async Task Port_Only_With_No_Parsed_L7_Protocol_Is_Rejected()
    {
        var r = Sample(); r.ApplicationProtocol = null;
        Assert.False(await Hit(r));
    }

    [Fact] public async Task Guessed_ApplicationService_Does_Not_Prove_Ot_Decoding()
    {
        var r = Sample(); r.ApplicationProtocol = null;
        r.ApplicationService = "DNP3 S7comm";
        Assert.False(await Hit(r));
    }

    [Fact] public async Task Packet_Info_Cannot_Fabricate_Industrial_Protocol()
    {
        var r = Sample(); r.ApplicationProtocol = null;
        r.Info = "DNP3 S7comm write var master outstation operate";
        Assert.False(await Hit(r));
    }

    [Fact] public async Task Contradictory_Udp_Transport_Is_Rejected()
    {
        var r = Sample(); r.IsTcp = false; r.IsUdp = true; r.Protocol = "UDP";
        Assert.False(await Hit(r));
    }

    [Fact] public async Task Wrong_Service_Port_Is_Not_Attributed_Ot()
    {
        var r = Sample(); r.DestinationPort = 443;
        Assert.False(await Hit(r));
    }

    [Fact] public async Task Wrong_L7_Protocol_Is_Not_This_Rule()
    {
        var r = Sample(); r.ApplicationProtocol = "HTTP";
        Assert.False(await Hit(r));
    }

    [Fact] public async Task Duplicate_Packet_Id_Is_Not_A_Second_Detection()
    {
        var rule = new R223_IcsProtocolToInternetRule(); var r = Sample();
        Assert.True((await rule.EvaluateAsync(At(r))).Matched);
        Assert.False((await rule.EvaluateAsync(At(r, 1))).Matched);
    }

    [Fact] public async Task Out_Of_Order_Packet_Is_Not_New_Evidence()
    {
        var rule = new R223_IcsProtocolToInternetRule(); var r = Sample();
        Assert.True((await rule.EvaluateAsync(At(r, 10))).Matched);
        var old = Sample(); old.Source = r.Source;
        Assert.False((await rule.EvaluateAsync(At(old, 5))).Matched);
    }

    [Fact] public async Task Independent_Source_Remains_Independent()
    {
        var rule = new R223_IcsProtocolToInternetRule();
        Assert.True((await rule.EvaluateAsync(At(Sample()))).Matched);
        Assert.True((await rule.EvaluateAsync(At(Sample(), 1))).Matched);
    }

    [Fact] public async Task Raw_Industrial_Info_And_Host_Are_Not_In_Evidence()
    {
        var r = Sample(); r.Info = "secretInfoMarker: password=private";
        var x = await new R223_IcsProtocolToInternetRule().EvaluateAsync(At(r));
        Assert.True(x.Matched);
        Assert.DoesNotContain(Assert.Single(x.Events).StructuredEvidence!.Items,
            e => e.Value.Contains("secretInfoMarker", StringComparison.Ordinal)
                || e.Value.Contains("password=private", StringComparison.Ordinal));
    }

    [Fact] public void Confidence_And_Default_Mode_Are_Preserved()
    {
        var p = new R223_IcsProtocolToInternetRule().PrecisionProfile;
        Assert.Equal(88, p.MinimumConfidence);
        Assert.Equal(RuleRuntimeMode.Alert, p.DefaultMode);
    }

    [Fact] public async Task Internal_Only_Dnp3_Flow_Is_Not_Internet_Egress()
    {
        var r = Sample(); r.Destination = "10.224.0.20";
        Assert.False(await Hit(r));
    }
    [Fact] public async Task Modbus_Parsed_L7_And_Tcp_502_To_Internet_Matches()
    {
        var r = Sample(); r.ApplicationProtocol = "modbus"; r.DestinationPort = 502;
        Assert.True(await Hit(r));
    }
    [Fact] public async Task Bacnet_Parsed_Udp_47808_To_Internet_Matches()
    {
        var r = Sample(); r.ApplicationProtocol = "bacnet"; r.DestinationPort = 47808;
        r.IsTcp = false; r.IsUdp = true; r.Protocol = "UDP";
        Assert.True(await Hit(r));
    }
}
