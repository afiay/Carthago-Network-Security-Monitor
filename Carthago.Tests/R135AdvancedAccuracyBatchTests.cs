// SPDX-License-Identifier: MIT
using System;
using System.Threading.Tasks;
using Carthago.Engine.Rules;
using Carthago.Engine.Rules.Expansion;
using Xunit;

namespace Carthago.Tests;

public sealed class R135AdvancedAccuracyBatchTests
{
    private readonly R135_BearerTokenOverCleartextHttpRule _rule = new();
    private const string Token = "eyJhbGciOiJIUzI1NiJ9.payload.signature";

    [Fact] public async Task Captured_Bearer_Header_Over_Cleartext_Matches()
    {
        var evt = Assert.Single((await _rule.EvaluateAsync(NetworkBatch131135Context.At(NetworkBatch131135Context.Bearer()))).Events);
        Assert.Contains(evt.StructuredEvidence!.Items, x => x.Key == "matched_conditions" && x.Value.Contains("bearer_authorization_header"));
    }

    [Fact] public async Task Https_Bearer_Is_Not_Cleartext()
    {
        var r = NetworkBatch131135Context.Bearer();
        r.DestinationPort = 443; r.Protocol = "HTTPS"; r.ApplicationProtocol = "HTTPS"; r.ApplicationService = "HTTPS"; r.Sni = r.HttpHost;
        Assert.False((await _rule.EvaluateAsync(NetworkBatch131135Context.At(r))).Matched);
    }

    [Fact] public async Task Info_Only_Token_Cannot_Impersonate_Parsed_Header()
    {
        var r = NetworkBatch131135Context.Web("/v1/profile", true);
        r.Info = "Authorization: Bearer " + Token;
        Assert.False((await _rule.EvaluateAsync(NetworkBatch131135Context.At(r))).Matched);
    }

    [Fact] public async Task Missing_Tcp_And_Udp_Contradictions_Are_Rejected()
    {
        var missing = NetworkBatch131135Context.Bearer(); missing.IsTcp = false;
        Assert.False((await _rule.EvaluateAsync(NetworkBatch131135Context.At(missing))).Matched);
        var udp = NetworkBatch131135Context.Bearer(); udp.IsUdp = true;
        Assert.False((await _rule.EvaluateAsync(NetworkBatch131135Context.At(udp))).Matched);
    }

    [Fact] public async Task Placeholder_And_Short_Bearer_Are_Not_Credentials()
    {
        foreach (var token in new[] { "short", "placeholder123456", "aaaaabbbbbcccc" })
        {
            var r = NetworkBatch131135Context.Bearer();
            r.HttpRequestHeaders = "Authorization: Bearer " + token;
            Assert.False((await _rule.EvaluateAsync(NetworkBatch131135Context.At(r))).Matched);
        }
    }

    [Fact] public async Task Proxy_Authorization_Is_Recognized_Without_Persisting_Token()
    {
        var r = NetworkBatch131135Context.Bearer();
        r.HttpRequestHeaders = "Proxy-Authorization: Bearer " + Token;
        var evt = Assert.Single((await _rule.EvaluateAsync(NetworkBatch131135Context.At(r))).Events);
        Assert.DoesNotContain(Token, evt.Evidence);
    }

    [Fact] public async Task Tls_Metadata_Rejects_Cleartext_Classification()
    {
        var r = NetworkBatch131135Context.Bearer(); r.Alpn = "h2";
        Assert.False((await _rule.EvaluateAsync(NetworkBatch131135Context.At(r))).Matched);
    }

    [Fact] public async Task Secret_Path_Is_Redacted_And_Alert_Mode_Unchanged()
    {
        Assert.Equal(RuleRuntimeMode.Alert, _rule.PrecisionProfile.DefaultMode);
        Assert.Equal(88, _rule.PrecisionProfile.MinimumConfidence);
        var evt = Assert.Single((await _rule.EvaluateAsync(NetworkBatch131135Context.At(NetworkBatch131135Context.Bearer("/v1/private-secret-135")))).Events);
        Assert.DoesNotContain("private-secret-135", evt.Evidence);
        Assert.DoesNotContain(Token, evt.Evidence);
        Assert.DoesNotContain(evt.StructuredEvidence!.Items, x => x.Value.Contains("private-secret-135", StringComparison.Ordinal) || x.Value.Contains(Token, StringComparison.Ordinal));
    }
}
