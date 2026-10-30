// SPDX-License-Identifier: MIT
// CANDIDATE — UNVERIFIED. A crumb API request is not proof of enumeration intent.
using System;
using System.Threading.Tasks;
using Carthago.Engine.Rules;
using Carthago.Engine.Rules.Expansion;
using Xunit;

namespace Carthago.Tests;

public sealed class R356AdvancedAccuracyBatchTests
{
    private static Task<RuleEvaluationResult> Eval(Carthago.Models.TrafficRecord r)
        => new R356_JenkinsCrumbIssuerEnumerationRule().EvaluateAsync(NetworkBatch356360Context.At(r)).AsTask();

    [Theory]
    [InlineData("/crumbIssuer/api/json")]
    [InlineData("/jenkins/crumbIssuer/api/xml")]
    public async Task Parsed_Crumb_Api_Get_Is_Eligible_Request_Shape(string path)
    {
        var result = await Eval(NetworkBatch356360Context.Http("jenkins.internal", path));
        Assert.True(result.Matched);
        Assert.Equal("R356", Assert.Single(result.Events).RuleId);
    }

    [Theory]
    [InlineData("/crumbIssuer")]
    [InlineData("/crumbIssuer/api")]
    [InlineData("/crumbIssuer/api/jsonx")]
    [InlineData("/crumbIssuer/api/json/other")]
    [InlineData("/unrelated/crumbIssuer.json")]
    public async Task Lookalike_Or_Non_Api_Path_Is_Rejected(string path)
    {
        var result = await Eval(NetworkBatch356360Context.Http("jenkins.internal", path));
        Assert.Contains(result.NoMatchReasons, x => x.Code == "JENKINS_CRUMB_ENDPOINT_NOT_OBSERVED");
    }

    [Fact] public async Task Post_Is_Not_An_Eligible_Crumb_Read()
    {
        var result = await Eval(NetworkBatch356360Context.Http("jenkins.internal", "/crumbIssuer/api/json", "POST"));
        Assert.Contains(result.NoMatchReasons, x => x.Code == "JENKINS_CRUMB_ENDPOINT_NOT_OBSERVED");
    }

    [Fact] public async Task Tls_Sni_Is_Not_Cleartext_Parsed_Http()
    {
        var r = NetworkBatch356360Context.Http("jenkins.internal", "/crumbIssuer/api/json");
        r.ApplicationProtocol = "TLS";
        Assert.Contains((await Eval(r)).NoMatchReasons, x => x.Code == "JENKINS_CRUMB_HTTP_REQUEST_MISSING");
    }

    [Fact] public async Task Missing_Method_Is_Not_Parsed_Request()
    {
        var r = NetworkBatch356360Context.Http("jenkins.internal", "/crumbIssuer/api/json");
        r.HttpMethod = null;
        Assert.Contains((await Eval(r)).NoMatchReasons, x => x.Code == "JENKINS_CRUMB_HTTP_REQUEST_MISSING");
    }

    [Theory]
    [InlineData("http://other.example/crumbIssuer/api/json")]
    [InlineData("//other.example/crumbIssuer/api/json")]
    [InlineData("/jenkins/%2fcrumbIssuer/api/json")]
    public async Task Ambiguous_Request_Target_Is_Rejected(string uri)
    {
        Assert.Contains((await Eval(NetworkBatch356360Context.Http("jenkins.internal", uri))).NoMatchReasons,
            x => x.Code == "JENKINS_CRUMB_TARGET_UNTRUSTED");
    }

    [Fact] public async Task Event_Does_Not_Leak_Query_Parameters()
    {
        var r = NetworkBatch356360Context.Http("jenkins.internal", "/crumbIssuer/api/json?secret=synthetic-private");
        var result = await Eval(r);
        Assert.True(result.Matched);
        var evt = Assert.Single(result.Events);
        Assert.DoesNotContain("synthetic-private", evt.Evidence ?? string.Empty);
        Assert.DoesNotContain(evt.StructuredEvidence!.Items, x => x.Value.Contains("synthetic-private", StringComparison.Ordinal));
    }

    [Fact] public void Original_Confidence_Mode_And_Threshold_Remain()
    {
        var p = new R356_JenkinsCrumbIssuerEnumerationRule().PrecisionProfile;
        Assert.Equal(74, p.MinimumConfidence);
        Assert.Equal(1, p.Threshold);
        Assert.Equal(RuleRuntimeMode.Alert, p.DefaultMode);
    }
}
