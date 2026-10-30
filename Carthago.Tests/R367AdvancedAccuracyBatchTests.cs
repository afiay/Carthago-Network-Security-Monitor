// SPDX-License-Identifier: MIT
// CANDIDATE — UNVERIFIED. These authored xUnit scenarios have NOT been executed.
using System;
using System.Threading.Tasks;
using Carthago.Engine.Rules;
using Carthago.Engine.Rules.Expansion;
using Carthago.Models;
using Xunit;

namespace Carthago.Tests;

public sealed class R367AdvancedAccuracyBatchTests
{
    private static Task<RuleEvaluationResult> Eval(TrafficRecord r, int seconds = 0)
        => new R367_TerraformCloudTokenExposureRule().EvaluateAsync(NetworkBatch361370Context.At(r, seconds)).AsTask();

    private static TrafficRecord Candidate()
    {
        var r = NetworkBatch361370Context.Http("app.terraform.io", "/api/v2/organizations/example", "GET");
        NetworkBatch361370Context.Flag(r, "HttpTerraformTokenPatternObserved");
        
        return r;
    }

    [Fact] public async Task Eligible_Parsed_Request_Shape_Is_Recognized()
    {
        var result = await Eval(Candidate());
        Assert.True(result.Matched);
        Assert.Equal("R367", Assert.Single(result.Events).RuleId);
    }
    [Fact] public async Task Evidence_Does_Not_Retain_Sensitive_Request_Query()
    {
        var r = Candidate();
        r.HttpUri += "?private=synthetic-private";
        var result = await Eval(r);
        Assert.True(result.Matched);
        Assert.DoesNotContain("synthetic-private", Assert.Single(result.Events).Evidence ?? string.Empty);
    }
    [Fact] public async Task Provider_Vocabulary_Without_Parser_Flag_Fails_Closed()
    {
        var r = Candidate();
        r.HttpTerraformTokenPatternObserved = false;
        r.Info = "token provider enumeration secret";
        Assert.False((await Eval(r)).Matched);
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
        var r = Candidate(); r.HttpUri = "http://app.terraform.io/api/v2/organizations/example";
        Assert.Contains((await Eval(r)).NoMatchReasons, x => x.Code == "DEVOPS_ORIGIN_TARGET_REQUIRED");
    }
    [Fact] public async Task Missing_Http_Method_Is_Not_Parsed_Request()
    {
        var r = Candidate(); r.HttpMethod = null;
        Assert.False((await Eval(r)).Matched);
    }
    [Fact] public async Task Spoofed_Provider_Host_Is_Rejected()
    {
        var r = Candidate(); r.HttpHost = "app.terraform.io.attacker.invalid";
        Assert.False((await Eval(r)).Matched);
    }
    [Fact] public void Existing_Mode_Threshold_And_Confidence_Are_Unchanged()
    {
        var p = new R367_TerraformCloudTokenExposureRule().PrecisionProfile;
        Assert.Equal(1, p.Threshold);
        Assert.Equal(78, p.MinimumConfidence);
        Assert.Equal(RuleRuntimeMode.Alert, p.DefaultMode);
    }
}
