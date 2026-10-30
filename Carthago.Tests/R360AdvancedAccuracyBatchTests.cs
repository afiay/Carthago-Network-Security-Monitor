// SPDX-License-Identifier: MIT
// CANDIDATE — UNVERIFIED. Token-shaped header is not verified credential use.
using System;
using System.Threading.Tasks;
using Carthago.Engine.Rules;
using Carthago.Engine.Rules.Expansion;
using Xunit;

namespace Carthago.Tests;

public sealed class R360AdvancedAccuracyBatchTests
{
    private static Task<RuleEvaluationResult> Eval(Carthago.Models.TrafficRecord r)
        => new R360_CircleCIAPITokenExposureRule().EvaluateAsync(NetworkBatch356360Context.At(r)).AsTask();

    private static Carthago.Models.TrafficRecord Candidate(string host = "circleci.com")
    {
        var r = NetworkBatch356360Context.Http(host, "/api/v2/project");
        r.HttpRequestHeaders = "Circle-Token: [REDACTED]";
        NetworkBatch356360Context.ParserFlag(r, "HttpCircleCiTokenPatternObserved");
        return r;
    }

    [Fact] public async Task Parser_Observed_Token_Header_And_CircleCI_Host_Are_Eligible()
    {
        var result = await Eval(Candidate());
        Assert.True(result.Matched);
        Assert.Equal("R360", Assert.Single(result.Events).RuleId);
    }

    [Fact] public async Task CircleCI_Api_Subdomain_Is_Eligible()
    {
        Assert.True((await Eval(Candidate("api.circleci.com"))).Matched);
    }

    [Theory]
    [InlineData("circleci.com.attacker.invalid")]
    [InlineData("github.com")]
    public async Task Spoofed_Or_Wrong_Host_Is_Not_Provider_Proof(string host)
    {
        Assert.Contains((await Eval(Candidate(host))).NoMatchReasons, x => x.Code == "CIRCLECI_HOST_NOT_OBSERVED");
    }

    [Fact] public async Task Info_Only_Token_Words_Do_Not_Assert_Header_Provenance()
    {
        var r = NetworkBatch356360Context.Http("circleci.com", "/api/v2/project");
        r.Info = "circle-token " + new string('A', 40);
        Assert.Contains((await Eval(r)).NoMatchReasons, x => x.Code == "CIRCLECI_TOKEN_PARSER_FLAG_NOT_OBSERVED");
    }

    [Fact] public async Task Redacted_Header_Name_Alone_Is_Not_Token_Observation()
    {
        var r = NetworkBatch356360Context.Http("circleci.com", "/api/v2/project");
        r.HttpRequestHeaders = "Circle-Token: [REDACTED]";
        Assert.Contains((await Eval(r)).NoMatchReasons, x => x.Code == "CIRCLECI_TOKEN_PARSER_FLAG_NOT_OBSERVED");
    }

    [Fact] public async Task Tls_Only_Is_Not_Parsed_Http()
    {
        var r = Candidate(); r.ApplicationProtocol = "TLS";
        Assert.Contains((await Eval(r)).NoMatchReasons, x => x.Code == "CIRCLECI_HTTP_REQUEST_MISSING");
    }

    [Fact] public async Task Udp_Contradiction_Is_Not_Parsed_Http()
    {
        var r = Candidate(); r.IsUdp = true;
        Assert.Contains((await Eval(r)).NoMatchReasons, x => x.Code == "CIRCLECI_HTTP_REQUEST_MISSING");
    }

    [Fact] public async Task Absolute_Request_Target_Is_Rejected()
    {
        var r = Candidate(); r.HttpUri = "http://circleci.com/api/v2/project";
        Assert.Contains((await Eval(r)).NoMatchReasons, x => x.Code == "CIRCLECI_TARGET_UNTRUSTED");
    }

    [Fact] public async Task Missing_Method_Is_Not_A_Parsed_Request()
    {
        var r = Candidate(); r.HttpMethod = null;
        Assert.Contains((await Eval(r)).NoMatchReasons, x => x.Code == "CIRCLECI_HTTP_REQUEST_MISSING");
    }

    [Fact] public async Task Query_Secret_Is_Redacted_In_Event()
    {
        var r = Candidate(); r.HttpUri = "/api/v2/project?secret=synthetic-private";
        var result = await Eval(r);
        Assert.True(result.Matched);
        Assert.DoesNotContain("synthetic-private", Assert.Single(result.Events).Evidence ?? string.Empty);
    }

    [Fact] public void Existing_Confidence_Mode_And_Threshold_Remain()
    {
        var p = new R360_CircleCIAPITokenExposureRule().PrecisionProfile;
        Assert.Equal(78, p.MinimumConfidence);
        Assert.Equal(1, p.Threshold);
        Assert.Equal(RuleRuntimeMode.Alert, p.DefaultMode);
    }
}
