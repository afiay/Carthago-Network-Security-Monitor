// SPDX-License-Identifier: MIT
// CANDIDATE — UNVERIFIED. Endpoint probe is not authenticated execution.
using System;
using System.Threading.Tasks;
using Carthago.Engine.Rules;
using Carthago.Engine.Rules.Expansion;
using Xunit;

namespace Carthago.Tests;

public sealed class R355AdvancedAccuracyBatchTests
{
    private static Task<RuleEvaluationResult> Evaluate(Carthago.Models.TrafficRecord r)
        => new R355_JenkinsScriptConsoleProbeRule().EvaluateAsync(NetworkBatch351355Context.At(r)).AsTask();

    [Fact] public async Task Inbound_Parsed_Get_To_Script_Console_Is_Eligible()
    {
        var result = await Evaluate(NetworkBatch351355Context.Jenkins());
        Assert.True(result.Matched);
        Assert.Equal("R355", Assert.Single(result.Events).RuleId);
    }

    [Fact] public async Task Post_To_Context_Path_ScriptText_Is_Eligible_And_Query_Redacted()
    {
        var r = NetworkBatch351355Context.Jenkins();
        r.HttpMethod = "POST"; r.HttpUri = "/jenkins/scriptText?token=private-secret";
        var result = await Evaluate(r);
        var evt = Assert.Single(result.Events);
        Assert.DoesNotContain("private-secret", evt.Evidence ?? string.Empty);
        Assert.DoesNotContain(evt.StructuredEvidence!.Items, item => item.Value.Contains("private-secret", StringComparison.Ordinal));
    }

    [Theory]
    [InlineData("/scripture")]
    [InlineData("/scriptTextual")]
    [InlineData("/job/build")]
    [InlineData("/script/other")]
    public async Task Similar_But_Not_Console_Path_Is_Rejected(string path)
    {
        var r = NetworkBatch351355Context.Jenkins(); r.HttpUri = path;
        Assert.Contains((await Evaluate(r)).NoMatchReasons, x => x.Code == "JENKINS_CONSOLE_PATH_NOT_OBSERVED");
    }

    [Fact] public async Task Delete_To_Console_Is_Not_Eligible()
    {
        var r = NetworkBatch351355Context.Jenkins(); r.HttpMethod = "DELETE";
        Assert.Contains((await Evaluate(r)).NoMatchReasons, x => x.Code == "JENKINS_UNEXPECTED_HTTP_METHOD");
    }

    [Fact] public async Task Tls_Sni_Only_Is_Not_Parsed_Http()
    {
        var r = NetworkBatch351355Context.Jenkins(); r.ApplicationProtocol = "TLS";
        Assert.Contains((await Evaluate(r)).NoMatchReasons, x => x.Code == "JENKINS_HTTP_PROTOCOL_NOT_ATTRIBUTED");
    }

    [Fact] public async Task Missing_Request_Target_Is_Not_A_Probe()
    {
        var r = NetworkBatch351355Context.Jenkins(); r.HttpUri = null;
        Assert.Contains((await Evaluate(r)).NoMatchReasons, x => x.Code == "JENKINS_HTTP_REQUEST_NOT_OBSERVED");
    }

    [Theory]
    [InlineData("http://other.example/script")]
    [InlineData("//other.example/script")]
    [InlineData(@"\script")]
    public async Task Ambiguous_Authority_Or_Path_Is_Rejected(string path)
    {
        var r = NetworkBatch351355Context.Jenkins(); r.HttpUri = path;
        Assert.Contains((await Evaluate(r)).NoMatchReasons, x => x.Code == "JENKINS_REQUEST_TARGET_UNTRUSTED");
    }

    [Fact] public async Task Internal_To_Internal_Is_Not_Inbound_External()
    {
        var r = NetworkBatch351355Context.Jenkins(); r.Source = "10.61.0.11";
        Assert.False((await Evaluate(r)).Matched);
    }

    [Fact] public void Existing_Profile_Floor_Mode_And_Threshold_Are_Preserved()
    {
        var p = new R355_JenkinsScriptConsoleProbeRule().PrecisionProfile;
        Assert.Equal(78, p.MinimumConfidence);
        Assert.Equal(1, p.Threshold);
        Assert.Equal(RuleRuntimeMode.Alert, p.DefaultMode);
    }
}
