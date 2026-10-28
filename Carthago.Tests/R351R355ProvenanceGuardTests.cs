// SPDX-License-Identifier: MIT
// CANDIDATE — UNVERIFIED. Authored only; never executed.
using System.Threading.Tasks;
using Carthago.Engine.Rules;
using Carthago.Engine.Rules.Expansion;
using Carthago.Models;
using Xunit;

namespace Carthago.Tests;

public sealed class R351R355ProvenanceGuardTests
{
    private static TrafficRecord Sample()
    {
        var r = NetworkBatch321325Context.Sample();
        r.Protocol = "TCP";
        r.IsTcp = true;
        r.IsUdp = false;
        return r;
    }

    [Theory]
    [InlineData("SMB")]
    [InlineData("HTTP")]
    [InlineData("TCP")]
    public async Task R351_WithoutNtlmProtocolAttribution_DoesNotMatch(string protocol)
    {
        var r = Sample();
        r.ApplicationProtocol = protocol;
        r.ApplicationService = protocol;
        r.Info = "NTLM challenge response external host";
        var result = await new R351_NTLMAuthenticationToExternalHostRule()
            .EvaluateAsync(NetworkBatch321325Context.At(r));
        Assert.False(result.Matched);
        Assert.Contains(result.NoMatchReasons, reason => reason.Code == "NTLM_PROTOCOL_NOT_ATTRIBUTED");
    }

    [Theory]
    [InlineData("LLMNR")]
    [InlineData("NBNS")]
    public async Task R352_ProtocolAndSpoofedInfoWithoutProcess_DoesNotMatch(string protocol)
    {
        var r = Sample();
        r.ApplicationProtocol = protocol;
        r.ProcessName = null;
        r.Info = "Responder Inveigh poisoning";
        r.DestinationPort = 5355;
        var result = await new R352_LLMNRNBNSResponderToolIndicatorRule()
            .EvaluateAsync(NetworkBatch321325Context.At(r));
        Assert.False(result.Matched);
        Assert.Contains(result.NoMatchReasons, reason => reason.Code == "RESPONDER_PROCESS_NOT_ATTRIBUTED");
    }

    [Theory]
    [InlineData("R353")]
    [InlineData("R354")]
    public async Task TokenInUntrustedInfoWithoutCaptureFlag_DoesNotMatch(string ruleId)
    {
        var r = Sample();
        r.ApplicationProtocol = "HTTP";
        r.HttpMethod = "GET";
        r.HttpHost = ruleId == "R353" ? "api.github.com" : "gitlab.com";
        r.Info = ruleId == "R353"
            ? "ghp_abcdefghijklmnopqrstuvwxyz012345"
            : "glpat-abcdefghijklmnopqrstuvwxyz012345";
        var result = ruleId == "R353"
            ? await new R353_GitHubPersonalAccessTokenInTrafficRule().EvaluateAsync(NetworkBatch321325Context.At(r))
            : await new R354_GitLabPrivateTokenInTrafficRule().EvaluateAsync(NetworkBatch321325Context.At(r));
        Assert.False(result.Matched);
        Assert.Contains(result.NoMatchReasons, reason =>
            reason.Code == (ruleId == "R353" ? "GITHUB_PAT_PATTERN_NOT_OBSERVED" : "GITLAB_PRIVATE_TOKEN_PATTERN_NOT_OBSERVED"));
    }

    [Theory]
    [InlineData("GET", "/job/example")]
    [InlineData("DELETE", "/script")]
    [InlineData("POST", "/scripture")]
    [InlineData("POST", "/scriptTextual")]
    public async Task R355_UnrelatedMethodOrPath_DoesNotMatch(string method, string uri)
    {
        var r = Sample();
        r.ApplicationProtocol = "HTTP";
        r.HttpMethod = method;
        r.HttpUri = uri;
        r.HttpHost = "jenkins.internal";
        r.Info = "Jenkins script console groovy";
        var result = await new R355_JenkinsScriptConsoleProbeRule()
            .EvaluateAsync(NetworkBatch321325Context.At(r));
        Assert.False(result.Matched);
    }
}
