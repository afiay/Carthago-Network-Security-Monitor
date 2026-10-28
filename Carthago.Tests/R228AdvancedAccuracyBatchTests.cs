// SPDX-License-Identifier: MIT
using System;
using System.Threading.Tasks;
using Carthago.Engine.Rules;
using Carthago.Engine.Rules.Expansion;
using Carthago.Models;
using Xunit;

namespace Carthago.Tests;
public sealed class R228AdvancedAccuracyBatchTests
{
    private static TrafficRecord Sample() => NetworkBatch226230Context.Sample(228);
    private static RuleEvaluationContext At(TrafficRecord r, int seconds = 0)
        => NetworkBatch226230Context.At(r, seconds);
    private static async Task<bool> Hit(TrafficRecord r)
        => (await new R228_OpcUaInternetEgressRule().EvaluateAsync(At(r))).Matched;

    [Fact] public async Task Typed_OpcUa_Tcp_4840_To_External_Address_Matches()
        => Assert.True(await Hit(Sample()));
    [Fact] public async Task Internal_Historian_Session_Does_Not_Cross_Internet()
    {
        var r = Sample(); r.Destination = "10.228.0.40";
        Assert.False(await Hit(r));
    }
    [Fact] public async Task Port_Only_Is_Not_Parsed_OpcUa()
    {
        var r = Sample(); r.ApplicationProtocol = null; r.Info = "opc.tcp://remote:4840";
        Assert.False(await Hit(r));
    }
    [Fact] public async Task Contradictory_Udp_Flags_Reject_Application_Claim()
    {
        var r = Sample(); r.IsTcp = false; r.IsUdp = true; r.Protocol = "UDP";
        Assert.False(await Hit(r));
    }
    [Fact] public async Task Unattributed_Service_Guess_Is_Not_L7_Proof()
    {
        var r = Sample(); r.ApplicationProtocol = null; r.ApplicationService = "OPC UA";
        Assert.False(await Hit(r));
    }
    [Fact] public async Task Duplicate_Packet_Id_Is_Rejected()
    {
        var rule = new R228_OpcUaInternetEgressRule(); var r = Sample();
        Assert.True((await rule.EvaluateAsync(At(r))).Matched);
        Assert.False((await rule.EvaluateAsync(At(r, 1))).Matched);
    }
    [Fact] public async Task External_Source_Is_Not_Internal_Egress()
    {
        var r = Sample(); r.Source = "198.51.100.10";
        Assert.False(await Hit(r));
    }
    [Fact] public async Task Sensitive_Info_Is_Not_Stored_As_Iot_Info()
    {
        var r = Sample(); r.Info = "secret-opc-marker password=private";
        var x = await new R228_OpcUaInternetEgressRule().EvaluateAsync(At(r));
        Assert.True(x.Matched);
        Assert.DoesNotContain(Assert.Single(x.Events).StructuredEvidence!.Items,
            e => e.Value.Contains("secret-opc-marker", StringComparison.Ordinal));
    }
    [Fact] public void Alert_Mode_And_Confidence_Floor_Remain()
    {
        var p = new R228_OpcUaInternetEgressRule().PrecisionProfile;
        Assert.Equal(84, p.MinimumConfidence); Assert.Equal(RuleRuntimeMode.Alert, p.DefaultMode);
    }
}
