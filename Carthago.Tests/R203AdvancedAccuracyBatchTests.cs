// SPDX-License-Identifier: MIT
using System;
using System.Threading.Tasks;
using Carthago.Engine.Rules;
using Carthago.Engine.Rules.Expansion;
using Carthago.Models;
using Xunit;
namespace Carthago.Tests;
public sealed class R203AdvancedAccuracyBatchTests
{
    private static TrafficRecord R(int i) => NetworkBatch201205Context.Registry(i, layer: true);
    [Fact] public async Task Six_Independent_Valid_Digest_Layer_Requests_Qualify()
    {
        var rule = new R203_ContainerImageLayerBulkDownloadRule();
        for (var i = 0; i < 5; i++) Assert.False((await rule.EvaluateAsync(NetworkBatch201205Context.At(R(i), i))).Matched);
        Assert.True((await rule.EvaluateAsync(NetworkBatch201205Context.At(R(5), 5))).Matched);
    }
    [Fact] public async Task Short_Nonsha256_Digest_Is_Rejected()
    {
        var r = R(1); r.HttpUri = "/v2/team/app/blobs/sha256:abc";
        Assert.False((await new R203_ContainerImageLayerBulkDownloadRule().EvaluateAsync(NetworkBatch201205Context.At(r))).Matched);
    }
    [Fact] public async Task Low_Volume_Six_Layer_Requests_Do_Not_Qualify()
    {
        var rule = new R203_ContainerImageLayerBulkDownloadRule();
        for (var i = 0; i < 6; i++)
        {
            var r = R(i); r.Length = 100_000; r.L4Len = 100_000;
            Assert.False((await rule.EvaluateAsync(NetworkBatch201205Context.At(r, i))).Matched);
        }
    }
    [Fact] public async Task Official_Registry_Excluded()
    {
        var r = R(1); r.HttpHost = "ghcr.io"; r.HttpRequestHeaders = "Host: ghcr.io";
        Assert.False((await new R203_ContainerImageLayerBulkDownloadRule().EvaluateAsync(NetworkBatch201205Context.At(r))).Matched);
    }
    [Fact] public async Task Info_Only_Digest_Does_Not_Prove_Blob_Request()
    {
        var r = R(1); r.HttpUri = "/status"; r.Info = "docker-content-digest sha256:" + new string('a', 64);
        Assert.False((await new R203_ContainerImageLayerBulkDownloadRule().EvaluateAsync(NetworkBatch201205Context.At(r))).Matched);
    }
    [Fact] public async Task Duplicate_Packet_Does_Not_Inflate_Bytes()
    {
        var rule = new R203_ContainerImageLayerBulkDownloadRule(); var r = R(1);
        for (var i = 0; i < 12; i++) Assert.False((await rule.EvaluateAsync(NetworkBatch201205Context.At(r, i))).Matched);
    }
    [Fact] public async Task Different_Source_Does_Not_Complete_Burst()
    {
        var rule = new R203_ContainerImageLayerBulkDownloadRule();
        for (var i = 0; i < 5; i++) Assert.False((await rule.EvaluateAsync(NetworkBatch201205Context.At(R(i), i))).Matched);
        var other = R(5); other.Source = "10.201.0.99";
        Assert.False((await rule.EvaluateAsync(NetworkBatch201205Context.At(other, 5))).Matched);
    }
    [Fact] public async Task Out_Of_Order_Layer_Does_Not_Advance()
    {
        var rule = new R203_ContainerImageLayerBulkDownloadRule();
        Assert.False((await rule.EvaluateAsync(NetworkBatch201205Context.At(R(0), 10))).Matched);
        Assert.False((await rule.EvaluateAsync(NetworkBatch201205Context.At(R(1), 5))).Matched);
    }
    [Fact] public async Task Registry_Host_And_Layer_Digest_Are_Redacted()
    {
        var rule = new R203_ContainerImageLayerBulkDownloadRule();
        Carthago.Engine.Rules.RuleEvaluationResult? last = null;
        for (var i = 0; i < 6; i++) last = await rule.EvaluateAsync(NetworkBatch201205Context.At(R(i), i));
        Assert.True(last!.Matched);
        Assert.DoesNotContain(Assert.Single(last.Events).StructuredEvidence!.Items, e =>
            e.Value.Contains("registry.external.example", StringComparison.Ordinal)
            || e.Value.Contains("sha256:", StringComparison.Ordinal));
    }
    [Fact] public void Shadow_And_Confidence_Floor_Unchanged()
    {
        var p = new R203_ContainerImageLayerBulkDownloadRule().PrecisionProfile;
        Assert.Equal(76, p.MinimumConfidence); Assert.Equal(RuleRuntimeMode.Shadow, p.DefaultMode);
    }
}
