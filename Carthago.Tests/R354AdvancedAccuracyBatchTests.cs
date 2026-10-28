// SPDX-License-Identifier: MIT
// CANDIDATE — UNVERIFIED. Synthetic parser flag is NOT a live token observation.
using System;
using System.Threading.Tasks;
using Carthago.Engine.Rules;
using Carthago.Engine.Rules.Expansion;
using Xunit;

namespace Carthago.Tests;

public sealed class R354AdvancedAccuracyBatchTests
{
    private static Carthago.Models.TrafficRecord Record()
    {
        var r = NetworkBatch351355Context.Http();
        r.HttpHost = "gitlab.com";
        r.Info = "ordinary HTTP request";
        return r;
    }

    private static void Mark(Carthago.Models.TrafficRecord r)
        => NetworkBatch351355Context.SyntheticParserFlag(r, "HttpGitLabTokenPatternObserved");

    private static Task<RuleEvaluationResult> Evaluate(Carthago.Models.TrafficRecord r)
        => new R354_GitLabPrivateTokenInTrafficRule().EvaluateAsync(NetworkBatch351355Context.At(r)).AsTask();

    [Fact] public async Task Parser_Attributed_Token_Candidate_Is_Eligible()
    {
        var r = Record(); Mark(r);
        var result = await Evaluate(r);
        Assert.True(result.Matched);
        Assert.Equal("R354", Assert.Single(result.Events).RuleId);
    }

    [Fact] public async Task Untrusted_Info_Token_Cannot_Create_Parser_Flag()
    {
        var r = Record(); r.Info = "glpat-ABCDEFGHIJKLMNOPQRSTUVWXYZ012345";
        var result = await Evaluate(r);
        Assert.False(result.Matched);
        Assert.Contains(result.NoMatchReasons, x => x.Code == "GITLAB_PRIVATE_TOKEN_PATTERN_NOT_OBSERVED");
    }

    [Fact] public async Task Other_Provider_Flag_Cannot_Impersonate_This_Token()
    {
        var r = Record();
        NetworkBatch351355Context.SyntheticParserFlag(r, "HttpGitHubTokenPatternObserved");
        Assert.False((await Evaluate(r)).Matched);
    }

    [Fact] public async Task Tls_Sni_Only_Does_Not_Expose_Http_Token()
    {
        var r = Record(); Mark(r); r.ApplicationProtocol = "TLS";
        Assert.Contains((await Evaluate(r)).NoMatchReasons, x => x.Code == "CAPTURED_HTTP_REQUEST_NOT_ATTRIBUTED");
    }

    [Fact] public async Task Missing_Parsed_Method_Is_Rejected()
    {
        var r = Record(); Mark(r); r.HttpMethod = null;
        Assert.Contains((await Evaluate(r)).NoMatchReasons, x => x.Code == "CAPTURED_HTTP_REQUEST_NOT_ATTRIBUTED");
    }

    [Fact] public async Task Missing_Parsed_Request_Target_Is_Rejected()
    {
        var r = Record(); Mark(r); r.HttpUri = null;
        Assert.Contains((await Evaluate(r)).NoMatchReasons, x => x.Code == "CAPTURED_HTTP_REQUEST_NOT_ATTRIBUTED");
    }

    [Fact] public async Task Udp_Transport_Contradiction_Is_Rejected()
    {
        var r = Record(); Mark(r); r.IsUdp = true;
        Assert.Contains((await Evaluate(r)).NoMatchReasons, x => x.Code == "CAPTURED_HTTP_REQUEST_NOT_ATTRIBUTED");
    }

    [Fact] public async Task Token_Exposed_To_NonProvider_Host_Is_Still_Eligible()
    {
        var r = Record(); Mark(r); r.HttpHost = "collector.example.org";
        Assert.True((await Evaluate(r)).Matched);
    }

    [Fact] public async Task Token_Bearing_Query_Is_Redacted_From_All_Event_Evidence()
    {
        var r = Record(); Mark(r);
        var secret = "glpat-ABCDEFGHIJKLMNOPQRSTUVWXYZ012345";
        r.HttpUri = "/api/v4/projects?access_token=" + secret;
        var result = await Evaluate(r);
        var evt = Assert.Single(result.Events);
        Assert.DoesNotContain(secret, evt.Evidence ?? string.Empty);
        Assert.DoesNotContain(secret, evt.Summary ?? string.Empty);
        Assert.DoesNotContain(evt.StructuredEvidence!.Items, item =>
            item.Value.Contains(secret, StringComparison.Ordinal));
    }

    [Fact] public void Existing_Profile_Floor_Mode_And_Threshold_Are_Preserved()
    {
        var p = new R354_GitLabPrivateTokenInTrafficRule().PrecisionProfile;
        Assert.Equal(78, p.MinimumConfidence);
        Assert.Equal(1, p.Threshold);
        Assert.Equal(RuleRuntimeMode.Alert, p.DefaultMode);
    }
}
