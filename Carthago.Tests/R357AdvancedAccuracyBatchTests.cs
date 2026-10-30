// SPDX-License-Identifier: MIT
// CANDIDATE — UNVERIFIED. Probe-shaped HTTP is not authenticated bypass proof.
using System;
using System.Threading.Tasks;
using Carthago.Engine.Rules;
using Carthago.Engine.Rules.Expansion;
using Xunit;

namespace Carthago.Tests;

public sealed class R357AdvancedAccuracyBatchTests
{
    private static Task<RuleEvaluationResult> Eval(Carthago.Models.TrafficRecord r)
        => new R357_TeamCityAuthBypassProbeRule().EvaluateAsync(NetworkBatch356360Context.At(r)).AsTask();

    [Theory]
    [InlineData("GET", "/app/rest/users/id:1/tokens?jsp=/app/rest/users/id:1/tokens")]
    [InlineData("POST", "/admin/diagnostic?jsp=/admin/diagnostic")]
    public async Task Specific_Inbound_Bypass_Shaped_Request_Is_Eligible(string method, string uri)
    {
        var result = await Eval(NetworkBatch356360Context.Http("teamcity.internal", uri, method, inbound: true));
        Assert.True(result.Matched);
        Assert.Equal("R357", Assert.Single(result.Events).RuleId);
    }

    [Theory]
    [InlineData("/app/rest/users/id:1/tokens")]
    [InlineData("/admin/diagnostic")]
    [InlineData("/login?jsp=/app/rest/users/id:1/tokens")]
    [InlineData("/app/rest/users?jsp=harmless")]
    public async Task Ordinary_Admin_Or_Unrelated_Jsp_Parameter_Is_Not_Bypass_Probe(string uri)
    {
        Assert.Contains((await Eval(NetworkBatch356360Context.Http("teamcity.internal", uri, inbound: true))).NoMatchReasons,
            x => x.Code == "TEAMCITY_BYPASS_SHAPE_NOT_OBSERVED");
    }

    [Fact] public async Task Delete_Request_Is_Not_Eligible()
    {
        var r = NetworkBatch356360Context.Http("teamcity.internal", "/app/rest/users?jsp=/app/rest/users/id:1", "DELETE", true);
        Assert.Contains((await Eval(r)).NoMatchReasons, x => x.Code == "TEAMCITY_METHOD_NOT_ELIGIBLE");
    }

    [Fact] public async Task Internal_Source_Does_Not_Satisfy_Inbound_External_Gate()
    {
        var r = NetworkBatch356360Context.Http("teamcity.internal", "/app/rest/users?jsp=/app/rest/users/id:1");
        Assert.False((await Eval(r)).Matched);
    }

    [Fact] public async Task Tls_Only_Is_Not_Parsed_Http()
    {
        var r = NetworkBatch356360Context.Http("teamcity.internal", "/app/rest/users?jsp=/app/rest/users/id:1", inbound: true);
        r.ApplicationProtocol = "TLS";
        Assert.Contains((await Eval(r)).NoMatchReasons, x => x.Code == "TEAMCITY_HTTP_REQUEST_MISSING");
    }

    [Fact] public async Task Absolute_Request_Target_Is_Not_Trusted()
    {
        var r = NetworkBatch356360Context.Http("teamcity.internal", "http://teamcity.internal/app/rest/users?jsp=/app/rest/users/id:1", inbound: true);
        Assert.Contains((await Eval(r)).NoMatchReasons, x => x.Code == "TEAMCITY_TARGET_UNTRUSTED");
    }

    [Fact] public async Task Descriptive_Info_Alone_Is_Not_Bypass_Evidence()
    {
        var r = NetworkBatch356360Context.Http("teamcity.internal", "/app/rest/users", inbound: true);
        r.Info = "TeamCity CVE auth bypass exploited";
        Assert.Contains((await Eval(r)).NoMatchReasons, x => x.Code == "TEAMCITY_BYPASS_SHAPE_NOT_OBSERVED");
    }

    [Fact] public async Task Probe_Event_Redacts_Request_Query()
    {
        var r = NetworkBatch356360Context.Http("teamcity.internal", "/app/rest/users?jsp=/app/rest/users/id:1&token=synthetic-private", inbound: true);
        var result = await Eval(r);
        Assert.True(result.Matched);
        Assert.DoesNotContain("synthetic-private", Assert.Single(result.Events).Evidence ?? string.Empty);
    }

    [Fact] public void Original_Confidence_Mode_And_Threshold_Remain()
    {
        var p = new R357_TeamCityAuthBypassProbeRule().PrecisionProfile;
        Assert.Equal(78, p.MinimumConfidence);
        Assert.Equal(1, p.Threshold);
        Assert.Equal(RuleRuntimeMode.Alert, p.DefaultMode);
    }
}
