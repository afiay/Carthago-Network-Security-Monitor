// SPDX-License-Identifier: MIT
using System;
using System.Threading.Tasks;
using Carthago.Engine.Rules;
using Carthago.Engine.Rules.Expansion;
using Carthago.Models;
using Xunit;

namespace Carthago.Tests;
public sealed class R213AdvancedAccuracyBatchTests
{
    private static TrafficRecord Sample(int i = 0) => NetworkBatch211215Context.Request(213, i);
    private static RuleEvaluationContext At(TrafficRecord r, int seconds = 0)
        => NetworkBatch211215Context.At(r, seconds);
    private static async Task<bool> Hit(TrafficRecord r)
        => (await new R213_CloudStoragePresignedUrlMassAccessRule().EvaluateAsync(At(r))).Matched;

    private static async Task<RuleEvaluationResult> Burst(R213_CloudStoragePresignedUrlMassAccessRule rule, int count, string? source = null)
    {
        var first = Sample(); source ??= first.Source;
        RuleEvaluationResult? result = null;
        for (var i = 0; i < count; i++)
        {
            var r = Sample(i); r.Source = source;
            result = await rule.EvaluateAsync(At(r, i * 5));
        }
        return result!;
    }

    [Fact] public async Task Eight_Distinct_Signed_Objects_Reach_Configured_Threshold()
        => Assert.True((await Burst(new R213_CloudStoragePresignedUrlMassAccessRule(), 8)).Matched);

    [Fact] public async Task Seven_Distinct_Objects_Remain_Below_Threshold()
        => Assert.False((await Burst(new R213_CloudStoragePresignedUrlMassAccessRule(), 7)).Matched);

    [Fact] public async Task One_Signed_Url_Is_Not_Mass_Access()
        => Assert.False(await Hit(Sample()));

    [Fact] public async Task Missing_Signature_Cannot_Qualify()
    {
        var r = Sample(); r.HttpUri = "/archive/file0.zip?X-Amz-Algorithm=AWS4-HMAC-SHA256";
        Assert.False(await Hit(r));
    }

    [Fact] public async Task Generic_Non_Cloud_Signature_Is_Benign()
    {
        var r = Sample(); r.HttpHost = "docs.example.net"; r.HttpRequestHeaders = "Host: docs.example.net";
        Assert.False(await Hit(r));
    }

    [Fact] public async Task Packet_Info_Cannot_Replace_Parsed_Signed_Query()
    {
        var r = Sample(); r.HttpUri = "/archive/file0.zip"; r.Info = "X-Amz-Signature=secret";
        Assert.False(await Hit(r));
    }

    [Fact] public async Task Contradictory_Authority_Is_Rejected()
    {
        var r = Sample(); r.HttpRequestHeaders = "Host: attacker.example.net";
        Assert.False(await Hit(r));
    }

    [Fact] public async Task Contradictory_Udp_Is_Rejected()
    {
        var r = Sample(); r.IsTcp = false; r.IsUdp = true; r.Protocol = "UDP";
        Assert.False(await Hit(r));
    }

    [Fact] public async Task Repeated_Packet_Id_Cannot_Reach_Threshold()
    {
        var rule = new R213_CloudStoragePresignedUrlMassAccessRule(); var r = Sample();
        for (var i = 0; i < 8; i++)
            Assert.False((await rule.EvaluateAsync(At(r, i))).Matched);
    }

    [Fact] public async Task Changed_Signature_For_Same_Object_Is_Not_Distinct_Object()
    {
        var rule = new R213_CloudStoragePresignedUrlMassAccessRule(); var first = Sample();
        for (var i = 0; i < 8; i++)
        {
            var r = Sample(); r.Source = first.Source;
            r.HttpUri = "/archive/same.zip?X-Amz-Algorithm=AWS4-HMAC-SHA256&X-Amz-Signature=signature" + i;
            Assert.False((await rule.EvaluateAsync(At(r, i))).Matched);
        }
    }

    [Fact] public async Task Out_Of_Order_Observation_Does_Not_Advance_Burst()
    {
        var rule = new R213_CloudStoragePresignedUrlMassAccessRule(); var r = Sample();
        Assert.False((await rule.EvaluateAsync(At(r, 10))).Matched);
        var older = Sample(1); older.Source = r.Source;
        Assert.False((await rule.EvaluateAsync(At(older, 5))).Matched);
    }

    [Fact] public async Task Independent_Sources_Cannot_Combine_Seven_And_One()
    {
        var rule = new R213_CloudStoragePresignedUrlMassAccessRule();
        Assert.False((await Burst(rule, 7)).Matched);
        Assert.False((await Burst(rule, 1)).Matched);
    }

    [Fact] public async Task Signed_Query_Secrets_Are_Not_In_Structured_Evidence()
    {
        var x = await Burst(new R213_CloudStoragePresignedUrlMassAccessRule(), 8);
        Assert.True(x.Matched);
        Assert.DoesNotContain(Assert.Single(x.Events).StructuredEvidence!.Items,
            e => e.Value.Contains("signature", StringComparison.OrdinalIgnoreCase)
                || e.Value.Contains("credential0", StringComparison.OrdinalIgnoreCase));
    }

    [Fact] public void Threshold_Confidence_And_Shadow_Mode_Preserved()
    {
        var p = new R213_CloudStoragePresignedUrlMassAccessRule().PrecisionProfile;
        Assert.Equal(8, p.Threshold);
        Assert.Equal(82, p.MinimumConfidence);
        Assert.Equal(RuleRuntimeMode.Shadow, p.DefaultMode);
    }
}
