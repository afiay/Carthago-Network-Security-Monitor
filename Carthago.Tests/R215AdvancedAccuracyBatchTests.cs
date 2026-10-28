// SPDX-License-Identifier: MIT
using System;
using System.Threading.Tasks;
using Carthago.Engine.Rules;
using Carthago.Engine.Rules.Expansion;
using Carthago.Models;
using Xunit;

namespace Carthago.Tests;
public sealed class R215AdvancedAccuracyBatchTests
{
    private static TrafficRecord Sample() => NetworkBatch211215Context.Request(215);
    private static RuleEvaluationContext At(TrafficRecord r, int seconds = 0)
        => NetworkBatch211215Context.At(r, seconds);
    private static async Task<bool> Hit(TrafficRecord r)
        => (await new R215_AzureBlobContainerEnumerationRule().EvaluateAsync(At(r))).Matched;

    [Fact] public async Task Typed_Request_With_Coherent_Transport_Matches()
        => Assert.True(await Hit(Sample()));

    [Fact] public async Task Close_Benign_Host_Does_Not_Match()
    {
        var r = Sample(); r.HttpHost = "docs.example.net"; r.HttpRequestHeaders = "Host: docs.example.net";
        Assert.False(await Hit(r));
    }

    [Fact] public async Task Info_Only_Claim_Without_Relevant_Request_Is_Rejected()
    {
        var r = Sample(); r.HttpUri = "/docs"; r.HttpHost = "docs.example.net";
        r.HttpRequestHeaders = "Host: docs.example.net";
        r.Info = "git postinstall curl | sh s3 bucket list comp=list powershell bootstrap";
        Assert.False(await Hit(r));
    }

    [Fact] public async Task Contradictory_Http_Authority_Is_Rejected()
    {
        var r = Sample(); r.HttpRequestHeaders = "Host: attacker.example.net";
        Assert.False(await Hit(r));
    }

    [Fact] public async Task Contradictory_Udp_Transport_Is_Rejected()
    {
        var r = Sample(); r.IsTcp = false; r.IsUdp = true; r.Protocol = "UDP";
        Assert.False(await Hit(r));
    }

    [Fact] public async Task Wrong_Http_Method_Is_Rejected()
    {
        var r = Sample(); r.HttpMethod = "POST";
        Assert.False(await Hit(r));
    }

    [Fact] public async Task Same_Packet_Id_Cannot_Repeat_Detection()
    {
        var rule = new R215_AzureBlobContainerEnumerationRule(); var r = Sample();
        Assert.True((await rule.EvaluateAsync(At(r))).Matched);
        Assert.False((await rule.EvaluateAsync(At(r, 1))).Matched);
    }

    [Fact] public async Task Out_Of_Order_Packet_Is_Not_New_Observation()
    {
        var rule = new R215_AzureBlobContainerEnumerationRule(); var r = Sample();
        Assert.True((await rule.EvaluateAsync(At(r, 10))).Matched);
        var earlier = Sample(); earlier.Source = r.Source;
        Assert.False((await rule.EvaluateAsync(At(earlier, 5))).Matched);
    }

    [Fact] public async Task Independent_Source_Still_Matches()
    {
        var rule = new R215_AzureBlobContainerEnumerationRule();
        Assert.True((await rule.EvaluateAsync(At(Sample()))).Matched);
        Assert.True((await rule.EvaluateAsync(At(Sample(), 1))).Matched);
    }

    [Fact] public async Task Query_Secret_Not_In_Structured_Evidence()
    {
        var r = Sample(); r.HttpUri += r.HttpUri!.Contains('?') ? "&token=superSecretMarker123" : "?token=superSecretMarker123";
        var x = await new R215_AzureBlobContainerEnumerationRule().EvaluateAsync(At(r));
        Assert.True(x.Matched);
        Assert.DoesNotContain(Assert.Single(x.Events).StructuredEvidence!.Items,
            e => e.Value.Contains("superSecretMarker123", StringComparison.Ordinal));
    }

    [Fact] public void Existing_Confidence_And_Runtime_Mode_Preserved()
    {
        var p = new R215_AzureBlobContainerEnumerationRule().PrecisionProfile;
        Assert.Equal(74, p.MinimumConfidence);
        Assert.Equal(RuleRuntimeMode.Shadow, p.DefaultMode);
    }

    [Fact] public async Task Object_Path_With_Enumeration_Query_Is_Not_Container_List()
    {
        var r = Sample(); r.HttpUri = "/container/object?restype=container&comp=list";
        Assert.False(await Hit(r));
    }
}
