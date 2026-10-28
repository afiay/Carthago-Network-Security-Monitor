// SPDX-License-Identifier: MIT
using System;
using System.Threading.Tasks;
using Carthago.Engine.Rules;
using Carthago.Engine.Rules.Expansion;
using Carthago.Models;
using Xunit;

namespace Carthago.Tests;
public sealed class R206AdvancedAccuracyBatchTests
{
    private static TrafficRecord Sample() => NetworkBatch206210Context.Request(206);
    private static RuleEvaluationContext At(TrafficRecord r, int sec = 0)
        => NetworkBatch206210Context.At(r, sec);
    private static async Task<bool> Hit(TrafficRecord r)
        => (await new R206_GitCloneFromUnknownExternalHostRule().EvaluateAsync(At(r))).Matched;

    [Fact] public async Task Typed_Request_With_Coherent_Transport_Matches()
        => Assert.True(await Hit(Sample()));

    [Fact] public async Task Official_Provider_Is_Close_Benign_Negative()
    {
        var r = Sample(); r.HttpHost = "github.com";
        r.HttpRequestHeaders = "Host: github.com";
        Assert.False(await Hit(r));
    }

    [Fact] public async Task Packet_Info_Only_Claim_Cannot_Manufacture_Operation()
    {
        var r = Sample(); r.HttpUri = "/news"; r.Info = "git clone git push npm postinstall pip download";
        Assert.False(await Hit(r));
    }

    [Fact] public async Task Contradictory_Host_Header_Is_Rejected()
    {
        var r = Sample(); r.HttpRequestHeaders = "Host: attacker.example.net";
        Assert.False(await Hit(r));
    }

    [Fact] public async Task Contradictory_Udp_Transport_Is_Rejected()
    {
        var r = Sample(); r.IsTcp = false; r.IsUdp = true; r.Protocol = "UDP";
        Assert.False(await Hit(r));
    }

    [Fact] public async Task Wrong_Http_Method_Does_Not_Qualify()
    {
        var r = Sample(); r.HttpMethod = "POST";
        Assert.False(await Hit(r));
    }

    [Fact] public async Task Same_Packet_Id_Cannot_Replay_Into_New_Detection()
    {
        var rule = new R206_GitCloneFromUnknownExternalHostRule(); var r = Sample();
        Assert.True((await rule.EvaluateAsync(At(r))).Matched);
        Assert.False((await rule.EvaluateAsync(At(r, 1))).Matched);
    }

    [Fact] public async Task Out_Of_Order_Observation_Is_Not_Another_First_Seen()
    {
        var rule = new R206_GitCloneFromUnknownExternalHostRule(); var r = Sample();
        Assert.True((await rule.EvaluateAsync(At(r, 10))).Matched);
        var earlier = Sample(); earlier.Source = r.Source;
        Assert.False((await rule.EvaluateAsync(At(earlier, 5))).Matched);
    }

    [Fact] public async Task Separate_Source_Remains_Independent()
    {
        var rule = new R206_GitCloneFromUnknownExternalHostRule();
        Assert.True((await rule.EvaluateAsync(At(Sample()))).Matched);
        Assert.True((await rule.EvaluateAsync(At(Sample(), 1))).Matched);
    }

    [Fact] public async Task Query_Secret_Is_Not_Persisted_In_Structured_Evidence()
    {
        var r = Sample(); r.HttpUri += r.HttpUri!.Contains('?') ? "&token=superSecretMarker123" : "?token=superSecretMarker123";
        var result = await new R206_GitCloneFromUnknownExternalHostRule().EvaluateAsync(At(r));
        Assert.True(result.Matched);
        Assert.DoesNotContain(Assert.Single(result.Events).StructuredEvidence!.Items,
            item => item.Value.Contains("superSecretMarker123", StringComparison.Ordinal));
    }

    [Fact] public void Configured_Confidence_And_Default_Mode_Remain_Intact()
    {
        var p = new R206_GitCloneFromUnknownExternalHostRule().PrecisionProfile;
        Assert.Equal(76, p.MinimumConfidence);
        Assert.Equal(RuleRuntimeMode.Shadow, p.DefaultMode);
    }
}
