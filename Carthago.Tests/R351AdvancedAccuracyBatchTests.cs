// SPDX-License-Identifier: MIT
// CANDIDATE — UNVERIFIED. NTLM-aware live producer not connected.
using System;
using System.Threading.Tasks;
using Carthago.Engine.Rules;
using Carthago.Engine.Rules.Expansion;
using Xunit;

namespace Carthago.Tests;

public sealed class R351AdvancedAccuracyBatchTests
{
    private static Task<RuleEvaluationResult> Evaluate(Carthago.Models.TrafficRecord r)
        => new R351_NTLMAuthenticationToExternalHostRule().EvaluateAsync(NetworkBatch351355Context.At(r)).AsTask();

    [Fact] public async Task Typed_Ntlm_Over_Tcp_To_External_Host_Is_Eligible()
    {
        var result = await Evaluate(NetworkBatch351355Context.Ntlm());
        Assert.True(result.Matched);
        Assert.Equal("R351", Assert.Single(result.Events).RuleId);
    }

    [Theory]
    [InlineData("SMB")]
    [InlineData("HTTP")]
    [InlineData("TCP")]
    public async Task Transport_Service_Alone_Does_Not_Prove_Ntlm(string application)
    {
        var r = NetworkBatch351355Context.Ntlm(); r.ApplicationProtocol = application;
        var result = await Evaluate(r);
        Assert.False(result.Matched);
        Assert.Contains(result.NoMatchReasons, x => x.Code == "NTLM_PROTOCOL_NOT_ATTRIBUTED");
    }

    [Fact] public async Task Spoofed_Protocol_Label_Does_Not_Prove_Ntlm()
    {
        var r = NetworkBatch351355Context.Ntlm(); r.Protocol = "NTLM"; r.ApplicationProtocol = "SMB";
        Assert.Contains((await Evaluate(r)).NoMatchReasons, x => x.Code == "NTLM_PROTOCOL_NOT_ATTRIBUTED");
    }

    [Fact] public async Task Udp_Ntlm_Claim_Is_Not_An_Attributed_Tcp_Exchange()
    {
        var r = NetworkBatch351355Context.Ntlm(); r.IsTcp = false; r.IsUdp = true;
        Assert.Contains((await Evaluate(r)).NoMatchReasons, x => x.Code == "NTLM_TCP_TRANSPORT_NOT_ATTRIBUTED");
    }

    [Fact] public async Task Contradictory_Transport_Flags_Are_Rejected()
    {
        var r = NetworkBatch351355Context.Ntlm(); r.IsUdp = true;
        Assert.Contains((await Evaluate(r)).NoMatchReasons, x => x.Code == "NTLM_TCP_TRANSPORT_NOT_ATTRIBUTED");
    }

    [Fact] public async Task Internal_Destination_Does_Not_Satisfy_External_Boundary()
    {
        var r = NetworkBatch351355Context.Ntlm(); r.Destination = "10.61.0.20";
        Assert.False((await Evaluate(r)).Matched);
    }

    [Fact] public async Task Missing_Source_Does_Not_Satisfy_Core_Telemetry()
    {
        var r = NetworkBatch351355Context.Ntlm(); r.Source = null;
        Assert.False((await Evaluate(r)).Matched);
    }

    [Fact] public void Existing_Profile_Floor_Mode_And_Threshold_Are_Preserved()
    {
        var p = new R351_NTLMAuthenticationToExternalHostRule().PrecisionProfile;
        Assert.Equal(78, p.MinimumConfidence);
        Assert.Equal(1, p.Threshold);
        Assert.Equal(RuleRuntimeMode.Alert, p.DefaultMode);
    }
}
