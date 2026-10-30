// SPDX-License-Identifier: MIT
// CANDIDATE — UNVERIFIED. Parser bit means token-shaped URL, not credential validity.
using System;
using System.Threading.Tasks;
using Carthago.Engine.Rules;
using Carthago.Engine.Rules.Expansion;
using Xunit;

namespace Carthago.Tests;

public sealed class R359AdvancedAccuracyBatchTests
{
    private static Task<RuleEvaluationResult> Eval(Carthago.Models.TrafficRecord r)
        => new R359_AzureDevOpsPATInURLRule().EvaluateAsync(NetworkBatch356360Context.At(r)).AsTask();

    private static Carthago.Models.TrafficRecord Candidate(string host = "dev.azure.com")
    {
        var r = NetworkBatch356360Context.Http(host, "/org/_apis?pat=[REDACTED]");
        NetworkBatch356360Context.ParserFlag(r, "HttpAzureDevOpsPatUrlObserved");
        return r;
    }

    [Fact] public async Task Parser_Flag_And_Provider_Host_Are_Eligible()
    {
        var result = await Eval(Candidate());
        Assert.True(result.Matched);
        Assert.Equal("R359", Assert.Single(result.Events).RuleId);
    }

    [Fact] public async Task Azure_DevOps_Organization_Subdomain_Is_Eligible()
    {
        Assert.True((await Eval(Candidate("example.visualstudio.com"))).Matched);
    }

    [Fact] public async Task Untrusted_Info_With_Long_Token_Does_Not_Assert_Pat()
    {
        var r = NetworkBatch356360Context.Http("dev.azure.com", "/org/_apis");
        r.Info = "pat=" + new string('A', 52);
        Assert.Contains((await Eval(r)).NoMatchReasons, x => x.Code == "AZURE_PAT_PARSER_FLAG_NOT_OBSERVED");
    }

    [Fact] public async Task Raw_HttpUri_Without_Parser_Flag_Does_Not_Assert_Pat()
    {
        var r = NetworkBatch356360Context.Http("dev.azure.com", "/org/_apis?pat=" + new string('A', 52));
        Assert.Contains((await Eval(r)).NoMatchReasons, x => x.Code == "AZURE_PAT_PARSER_FLAG_NOT_OBSERVED");
    }

    [Theory]
    [InlineData("dev.azure.com.attacker.invalid")]
    [InlineData("visualstudio.com.attacker.invalid")]
    [InlineData("github.com")]
    public async Task Spoofed_Or_Wrong_Provider_Host_Fails_Closed(string host)
    {
        Assert.Contains((await Eval(Candidate(host))).NoMatchReasons, x => x.Code == "AZURE_PAT_HOST_NOT_OBSERVED");
    }

    [Fact] public async Task Tls_Only_Is_Not_Parsed_Cleartext_Http()
    {
        var r = Candidate(); r.ApplicationProtocol = "TLS";
        Assert.Contains((await Eval(r)).NoMatchReasons, x => x.Code == "AZURE_PAT_HTTP_REQUEST_MISSING");
    }

    [Fact] public async Task Ambiguous_Absolute_Request_Target_Fails_Closed()
    {
        var r = Candidate(); r.HttpUri = "http://dev.azure.com/org/_apis?pat=[REDACTED]";
        Assert.Contains((await Eval(r)).NoMatchReasons, x => x.Code == "AZURE_PAT_TARGET_UNTRUSTED");
    }

    [Fact] public async Task Udp_Contradiction_Is_Not_Http_Provenance()
    {
        var r = Candidate(); r.IsUdp = true;
        Assert.Contains((await Eval(r)).NoMatchReasons, x => x.Code == "AZURE_PAT_HTTP_REQUEST_MISSING");
    }

    [Fact] public async Task Event_Does_Not_Expose_Raw_Request_Target()
    {
        var r = Candidate(); r.HttpUri = "/org/_apis?pat=synthetic-private";
        var result = await Eval(r);
        Assert.True(result.Matched);
        var evt = Assert.Single(result.Events);
        Assert.DoesNotContain("synthetic-private", evt.Evidence ?? string.Empty);
        Assert.DoesNotContain(evt.StructuredEvidence!.Items, x => x.Value.Contains("synthetic-private", StringComparison.Ordinal));
    }

    [Fact] public void Existing_Mode_Threshold_And_Confidence_Are_Preserved()
    {
        var p = new R359_AzureDevOpsPATInURLRule().PrecisionProfile;
        Assert.Equal(78, p.MinimumConfidence);
        Assert.Equal(1, p.Threshold);
        Assert.Equal(RuleRuntimeMode.Alert, p.DefaultMode);
    }
}
