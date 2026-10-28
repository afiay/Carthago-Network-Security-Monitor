// SPDX-License-Identifier: MIT
using System;
using System.Threading.Tasks;
using Carthago.Engine.Rules;
using Carthago.Engine.Rules.Expansion;
using Carthago.Models;
using Xunit;
namespace Carthago.Tests;
public sealed class R202AdvancedAccuracyBatchTests
{
    private static TrafficRecord R(int i) => NetworkBatch201205Context.Registry(i);
    [Fact] public async Task Six_Distinct_Registry_Manifest_Pulls_Qualify()
    {
        var rule = new R202_DockerRegistryPushPullAnomalyRule();
        for (var i = 0; i < 5; i++) Assert.False((await rule.EvaluateAsync(NetworkBatch201205Context.At(R(i), i))).Matched);
        Assert.True((await rule.EvaluateAsync(NetworkBatch201205Context.At(R(5), 5))).Matched);
    }
    [Fact] public async Task Single_Registry_Operation_Is_Not_Burst()
        => Assert.False((await new R202_DockerRegistryPushPullAnomalyRule().EvaluateAsync(NetworkBatch201205Context.At(R(1)))).Matched);
    [Fact] public async Task Official_Registry_Excluded()
    {
        var r = R(1); r.HttpHost = "ghcr.io"; r.HttpRequestHeaders = "Host: ghcr.io";
        Assert.False((await new R202_DockerRegistryPushPullAnomalyRule().EvaluateAsync(NetworkBatch201205Context.At(r))).Matched);
    }
    [Fact] public async Task Packet_Info_Claim_Without_Registry_Path_Is_Rejected()
    {
        var r = R(1); r.HttpUri = "/v2/status"; r.Info = "docker-registry upload";
        Assert.False((await new R202_DockerRegistryPushPullAnomalyRule().EvaluateAsync(NetworkBatch201205Context.At(r))).Matched);
    }
    [Fact] public async Task Contradictory_Http_Transport_Is_Rejected()
    {
        var r = R(1); r.IsTcp = false; r.IsUdp = true;
        Assert.False((await new R202_DockerRegistryPushPullAnomalyRule().EvaluateAsync(NetworkBatch201205Context.At(r))).Matched);
    }
    [Fact] public async Task Duplicate_Id_Does_Not_Fill_Distinct_Artifact_Window()
    {
        var rule = new R202_DockerRegistryPushPullAnomalyRule(); var r = R(1);
        for (var i = 0; i < 10; i++) Assert.False((await rule.EvaluateAsync(NetworkBatch201205Context.At(r, i))).Matched);
    }
    [Fact] public async Task Different_Source_Does_Not_Fill_Window()
    {
        var rule = new R202_DockerRegistryPushPullAnomalyRule();
        for (var i = 0; i < 5; i++) Assert.False((await rule.EvaluateAsync(NetworkBatch201205Context.At(R(i), i))).Matched);
        var other = R(5); other.Source = "10.201.0.99";
        Assert.False((await rule.EvaluateAsync(NetworkBatch201205Context.At(other, 5))).Matched);
    }
    [Fact] public async Task Out_Of_Order_Registry_Operation_Is_Not_Added()
    {
        var rule = new R202_DockerRegistryPushPullAnomalyRule();
        Assert.False((await rule.EvaluateAsync(NetworkBatch201205Context.At(R(0), 10))).Matched);
        Assert.False((await rule.EvaluateAsync(NetworkBatch201205Context.At(R(1), 5))).Matched);
    }
    [Fact] public void Shadow_And_Confidence_Floor_Unchanged()
    {
        var p = new R202_DockerRegistryPushPullAnomalyRule().PrecisionProfile;
        Assert.Equal(76, p.MinimumConfidence); Assert.Equal(RuleRuntimeMode.Shadow, p.DefaultMode);
    }
}
