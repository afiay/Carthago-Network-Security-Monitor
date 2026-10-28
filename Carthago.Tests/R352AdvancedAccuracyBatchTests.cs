// SPDX-License-Identifier: MIT
// CANDIDATE — UNVERIFIED. Trusted process and name-resolution producers pending.
using System;
using System.Threading.Tasks;
using Carthago.Engine.Rules;
using Carthago.Engine.Rules.Expansion;
using Xunit;

namespace Carthago.Tests;

public sealed class R352AdvancedAccuracyBatchTests
{
    private static Task<RuleEvaluationResult> Evaluate(Carthago.Models.TrafficRecord r)
        => new R352_LLMNRNBNSResponderToolIndicatorRule().EvaluateAsync(NetworkBatch351355Context.At(r)).AsTask();

    [Fact] public async Task Typed_Llmnr_And_Exact_Responder_Process_Is_Eligible()
    {
        var result = await Evaluate(NetworkBatch351355Context.NameResolution());
        Assert.True(result.Matched);
        Assert.Equal("R352", Assert.Single(result.Events).RuleId);
    }

    [Fact] public async Task Typed_Nbns_And_Exact_Inveigh_Process_Is_Eligible()
    {
        var r = NetworkBatch351355Context.NameResolution();
        r.ApplicationProtocol = "NBNS"; r.ProcessName = @"C:\Tools\Inveigh.ps1";
        r.DestinationPort = 137; r.Info = "NBNS responder poisoning";
        Assert.True((await Evaluate(r)).Matched);
    }

    [Theory]
    [InlineData("responder-monitor.exe")]
    [InlineData("not-responder.py")]
    [InlineData("inveigh-helper.ps1")]
    [InlineData("chrome.exe")]
    public async Task Similar_Process_Names_Are_Not_Executable_Attribution(string process)
    {
        var r = NetworkBatch351355Context.NameResolution(); r.ProcessName = process;
        var result = await Evaluate(r);
        Assert.False(result.Matched);
        Assert.Contains(result.NoMatchReasons, x => x.Code == "RESPONDER_PROCESS_NOT_ATTRIBUTED");
    }

    [Fact] public async Task Unattributed_Process_Is_Rejected_Despite_Info_Spoofing()
    {
        var r = NetworkBatch351355Context.NameResolution(); r.ProcessName = null;
        r.Info = "Responder Inveigh tool poisoned LLMNR";
        Assert.Contains((await Evaluate(r)).NoMatchReasons, x => x.Code == "RESPONDER_PROCESS_NOT_ATTRIBUTED");
    }

    [Fact] public async Task Missing_Application_Classification_Is_Rejected()
    {
        var r = NetworkBatch351355Context.NameResolution(); r.ApplicationProtocol = "UDP";
        Assert.Contains((await Evaluate(r)).NoMatchReasons, x => x.Code == "NAME_RESOLUTION_PROTOCOL_NOT_ATTRIBUTED");
    }

    [Fact] public async Task Missing_Transport_Is_Rejected()
    {
        var r = NetworkBatch351355Context.NameResolution(); r.IsUdp = false;
        Assert.Contains((await Evaluate(r)).NoMatchReasons, x => x.Code == "NAME_RESOLUTION_TRANSPORT_NOT_ATTRIBUTED");
    }

    [Fact] public async Task Conflicting_Transport_Is_Rejected()
    {
        var r = NetworkBatch351355Context.NameResolution(); r.IsTcp = true;
        Assert.Contains((await Evaluate(r)).NoMatchReasons, x => x.Code == "NAME_RESOLUTION_TRANSPORT_NOT_ATTRIBUTED");
    }

    [Fact] public void Existing_Profile_Floor_Mode_And_Threshold_Are_Preserved()
    {
        var p = new R352_LLMNRNBNSResponderToolIndicatorRule().PrecisionProfile;
        Assert.Equal(78, p.MinimumConfidence);
        Assert.Equal(1, p.Threshold);
        Assert.Equal(RuleRuntimeMode.Alert, p.DefaultMode);
    }
}
