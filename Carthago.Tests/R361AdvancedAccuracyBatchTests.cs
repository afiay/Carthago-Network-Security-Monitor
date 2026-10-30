// SPDX-License-Identifier: MIT
// CANDIDATE — UNVERIFIED. These authored xUnit scenarios have NOT been executed.
using System;
using System.Threading.Tasks;
using Carthago.Engine.Rules;
using Carthago.Engine.Rules.Expansion;
using Carthago.Models;
using Xunit;

namespace Carthago.Tests;

public sealed class R361AdvancedAccuracyBatchTests
{
    private static Task<RuleEvaluationResult> Eval(TrafficRecord r, int seconds = 0)
        => new R361_GitHubActionsOIDCTokenRequestRule().EvaluateAsync(NetworkBatch361370Context.At(r, seconds)).AsTask();

    private static TrafficRecord Candidate()
    {
        var r = NetworkBatch361370Context.Http("token.actions.githubusercontent.com", "/actions/oidc", "GET");
        
        
        return r;
    }

    [Fact] public async Task Runtime_Oidc_Url_Without_Authenticated_Runner_Is_Blocked()
    {
        Assert.Contains((await Eval(Candidate())).NoMatchReasons, x => x.Code == "GITHUB_OIDC_RUNNER_AUDIT_UNAVAILABLE");
    }
    [Fact] public async Task Provider_Host_Does_Not_Authenticate_Runner()
    {
        var r = Candidate(); r.HttpHost = "token.actions.githubusercontent.com";
        Assert.False((await Eval(r)).Matched);
    }
    [Fact] public async Task Info_Claim_Of_IdToken_Is_Not_Audit()
    {
        var r = Candidate(); r.Info = "ACTIONS_ID_TOKEN_REQUEST_URL github actions oidc";
        Assert.False((await Eval(r)).Matched);
    }
    [Fact] public async Task Fake_Environment_Headers_Are_Not_Runner_Attestation()
    {
        var r = Candidate(); r.HttpRequestHeaders = "X-GitHub-Runner: trusted";
        Assert.False((await Eval(r)).Matched);
    }
    [Fact] public async Task Tls_Only_Cannot_Provide_Authenticated_Oidc()
    {
        var r = Candidate(); r.ApplicationProtocol = "TLS";
        Assert.False((await Eval(r)).Matched);
    }
    [Fact] public async Task Spoofed_Host_Cannot_Provide_Authenticated_Oidc()
    {
        var r = Candidate(); r.HttpHost = "token.actions.githubusercontent.com.attacker.invalid";
        Assert.False((await Eval(r)).Matched);
    }
}
