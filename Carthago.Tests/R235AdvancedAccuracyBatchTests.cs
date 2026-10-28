// SPDX-License-Identifier: MIT
using System;
using System.Threading.Tasks;
using Carthago.Engine.Rules;
using Carthago.Engine.Rules.Expansion;
using Carthago.Models;
using Xunit;

namespace Carthago.Tests;
public sealed class R235AdvancedAccuracyBatchTests
{
    private static TrafficRecord Sample() => NetworkBatch231235Context.Sample(235);
    private static RuleEvaluationContext At(TrafficRecord r, int seconds = 0)
        => NetworkBatch231235Context.At(r, seconds);
    private static async Task<bool> Hit(TrafficRecord r)
        => (await new R235_OnvifDiscoveryFromWorkstationRule().EvaluateAsync(At(r))).Matched;

    [Fact] public async Task Five_Typed_WsDiscovery_Probes_From_Workstation_Match()
    {
        var rule = new R235_OnvifDiscoveryFromWorkstationRule(); var source = Sample().Source;
        for (int i = 0; i < 4; i++)
        {
            var r = Sample(); r.Source = source;
            Assert.False((await rule.EvaluateAsync(At(r, i))).Matched);
        }
        var last = Sample(); last.Source = source;
        Assert.True((await rule.EvaluateAsync(At(last, 4))).Matched);
    }
    [Fact] public async Task Single_Camera_Onboarding_Probe_Is_Benign()
        => Assert.False(await Hit(Sample()));
    [Fact] public async Task Unparsed_Info_Probe_Claim_Is_Rejected()
    {
        var r = Sample(); r.ApplicationProtocol = null; r.Info = "ONVIF WS-Discovery Probe";
        Assert.False(await Hit(r));
    }
    [Fact] public async Task Unknown_Process_Does_Not_Prove_Workstation()
    {
        var r = Sample(); r.ProcessName = null;
        Assert.False(await Hit(r));
    }
    [Fact] public async Task Camera_Process_Is_Not_Workstation()
    {
        var r = Sample(); r.ProcessName = "camera.exe";
        Assert.False(await Hit(r));
    }
    [Fact] public async Task Wrong_Multicast_Address_Is_Not_Probe_Contract()
    {
        var r = Sample(); r.Destination = "224.0.0.251";
        Assert.False(await Hit(r));
    }
    [Fact] public async Task Duplicate_Id_Does_Not_Fill_Burst()
    {
        var rule = new R235_OnvifDiscoveryFromWorkstationRule(); var r = Sample();
        for (int i = 0; i < 6; i++)
            Assert.False((await rule.EvaluateAsync(At(r, i))).Matched);
    }
    [Fact] public async Task Independent_Workstations_Do_Not_Share_Window()
    {
        var rule = new R235_OnvifDiscoveryFromWorkstationRule();
        var a = Sample().Source; var b = Sample().Source;
        for (int i = 0; i < 3; i++)
        {
            var r = Sample(); r.Source = a;
            Assert.False((await rule.EvaluateAsync(At(r, i))).Matched);
            r = Sample(); r.Source = b;
            Assert.False((await rule.EvaluateAsync(At(r, i))).Matched);
        }
    }
    [Fact] public async Task Out_Of_Order_Probe_Does_Not_Advance_Window()
    {
        var rule = new R235_OnvifDiscoveryFromWorkstationRule();
        var r = Sample(); Assert.False((await rule.EvaluateAsync(At(r, 20))).Matched);
        var old = Sample(); old.Source = r.Source;
        Assert.False((await rule.EvaluateAsync(At(old, 5))).Matched);
    }
    [Fact] public void Original_Shadow_And_Confidence_Floor()
    {
        var p = new R235_OnvifDiscoveryFromWorkstationRule().PrecisionProfile;
        Assert.Equal(76, p.MinimumConfidence); Assert.Equal(RuleRuntimeMode.Shadow, p.DefaultMode);
    }
}
