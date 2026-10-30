// SPDX-License-Identifier: MIT
// CANDIDATE — UNVERIFIED. These authored xUnit scenarios have NOT been executed.
using System;
using System.Threading.Tasks;
using Carthago.Engine.Rules;
using Carthago.Engine.Rules.Expansion;
using Carthago.Models;
using Xunit;

namespace Carthago.Tests;

public sealed class R368AdvancedAccuracyBatchTests
{
    private static Task<RuleEvaluationResult> Eval(TrafficRecord r, int seconds = 0)
        => new R368_DockerHubPullStormRule().EvaluateAsync(NetworkBatch361370Context.At(r, seconds)).AsTask();

    private static TrafficRecord Candidate()
    {
        var r = NetworkBatch361370Context.Http("registry-1.docker.io", "/v2/library/alpine/manifests/latest", "GET");
        
        
        return r;
    }

    [Fact] public async Task Distinct_Requests_Only_Match_At_Original_Threshold()
    {
        var seed = Candidate();
        for (int i = 0; i < 9; i++)
        {
            var r = NetworkBatch361370Context.NewPacket(seed);
            var result = await Eval(r, i);
            Assert.False(result.Matched);
        }
        var final = await Eval(NetworkBatch361370Context.NewPacket(seed), 9);
        Assert.True(final.Matched);
        Assert.Equal("R368", Assert.Single(final.Events).RuleId);
    }
    [Fact] public async Task Duplicate_Packet_Id_Does_Not_Fill_Burst()
    {
        var r = Candidate();
        var first = await Eval(r);
        Assert.False(first.Matched);
        var duplicate = await Eval(r, 1);
        Assert.Contains(duplicate.NoMatchReasons, x => x.Code == "DEVOPS_BURST_DUPLICATE_PACKET");
    }
    [Fact] public async Task Out_Of_Order_Packet_Does_Not_Advance_Burst()
    {
        var r = Candidate();
        await Eval(r, 10);
        var older = NetworkBatch361370Context.NewPacket(r);
        Assert.Contains((await Eval(older, 9)).NoMatchReasons, x => x.Code == "DEVOPS_BURST_OUT_OF_ORDER");
    }
    [Fact] public async Task Unrelated_Endpoint_Is_Not_Proof()
    {
        var r = Candidate(); r.HttpUri = "/not-the-required-endpoint";
        Assert.False((await Eval(r)).Matched);
    }
    [Fact] public async Task Tls_Only_Cannot_Assert_Cleartext_Http()
    {
        var r = Candidate(); r.ApplicationProtocol = "TLS";
        Assert.Contains((await Eval(r)).NoMatchReasons, x => x.Code == "DEVOPS_PARSED_HTTP_REQUIRED");
    }
    [Fact] public async Task Contradictory_Udp_Cannot_Assert_Http()
    {
        var r = Candidate(); r.IsUdp = true;
        Assert.False((await Eval(r)).Matched);
    }
    [Fact] public async Task Absolute_Url_Target_Is_Rejected()
    {
        var r = Candidate(); r.HttpUri = "http://registry-1.docker.io/v2/library/alpine/manifests/latest";
        Assert.Contains((await Eval(r)).NoMatchReasons, x => x.Code == "DEVOPS_ORIGIN_TARGET_REQUIRED");
    }
    [Fact] public async Task Missing_Http_Method_Is_Not_Parsed_Request()
    {
        var r = Candidate(); r.HttpMethod = null;
        Assert.False((await Eval(r)).Matched);
    }
    [Fact] public async Task Spoofed_Provider_Host_Is_Rejected()
    {
        var r = Candidate(); r.HttpHost = "registry-1.docker.io.attacker.invalid";
        Assert.False((await Eval(r)).Matched);
    }
    [Fact] public void Existing_Mode_Threshold_And_Confidence_Are_Unchanged()
    {
        var p = new R368_DockerHubPullStormRule().PrecisionProfile;
        Assert.Equal(10, p.Threshold);
        Assert.Equal(74, p.MinimumConfidence);
        Assert.Equal(RuleRuntimeMode.Alert, p.DefaultMode);
    }
}
