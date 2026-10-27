// SPDX-License-Identifier: MIT
using System;
using System.Threading.Tasks;
using Carthago.Engine.Rules;
using Carthago.Engine.Rules.Expansion;
using Xunit;

namespace Carthago.Tests;

public sealed class R134AdvancedAccuracyBatchTests
{
    private readonly R134_ApiTokenInUrlQueryRule _rule = new();
    private const string Token = "eyJhbGciOiJIUzI1NiJ9.payload.signature";

    [Fact] public async Task Opaque_Access_Token_In_Observed_Query_Matches()
    {
        var r = NetworkBatch131135Context.Web("/v1/data?access_token=" + Token);
        Assert.True((await _rule.EvaluateAsync(NetworkBatch131135Context.At(r))).Matched);
    }

    [Fact] public async Task Csrf_State_Nonce_And_Pagination_Are_Negative()
    {
        foreach (var name in new[] { "csrf_token", "state", "nonce", "page_token", "reset_token" })
        {
            var r = NetworkBatch131135Context.Web("/form?" + name + "=" + Token);
            Assert.False((await _rule.EvaluateAsync(NetworkBatch131135Context.At(r))).Matched);
        }
    }

    [Fact] public async Task Fragment_Is_Not_Observable_Http_Query()
    {
        var r = NetworkBatch131135Context.Web("/v1/data#access_token=" + Token);
        Assert.False((await _rule.EvaluateAsync(NetworkBatch131135Context.At(r))).Matched);
    }

    [Fact] public async Task Placeholder_And_Low_Entropy_Are_Rejected()
    {
        foreach (var value in new[] { "placeholder123456", "aaaaaaaaaaaa", "short", "changeme123456789" })
        {
            var r = NetworkBatch131135Context.Web("/v1/data?api_key=" + value);
            Assert.False((await _rule.EvaluateAsync(NetworkBatch131135Context.At(r))).Matched);
        }
    }

    [Fact] public async Task Percent_Encoded_Valid_Token_Still_Matches()
    {
        var r = NetworkBatch131135Context.Web("/v1/data?access_token=" + Token.Replace(".", "%2E"));
        Assert.True((await _rule.EvaluateAsync(NetworkBatch131135Context.At(r))).Matched);
    }

    [Fact] public async Task Missing_Tcp_Or_Host_Mismatch_Fails_Closed()
    {
        var missing = NetworkBatch131135Context.Web("/v1/data?access_token=" + Token);
        missing.IsTcp = false;
        Assert.False((await _rule.EvaluateAsync(NetworkBatch131135Context.At(missing))).Matched);
        var mismatch = NetworkBatch131135Context.Web("https://other.example.test/v1/data?access_token=" + Token);
        Assert.False((await _rule.EvaluateAsync(NetworkBatch131135Context.At(mismatch))).Matched);
    }

    [Fact] public async Task Token_Path_And_Query_Value_Never_Persist()
    {
        Assert.Equal(RuleRuntimeMode.Alert, _rule.PrecisionProfile.DefaultMode);
        Assert.Equal(86, _rule.PrecisionProfile.MinimumConfidence);
        var r = NetworkBatch131135Context.Web("/private-secret-134?api_key=" + Token);
        var evt = Assert.Single((await _rule.EvaluateAsync(NetworkBatch131135Context.At(r))).Events);
        Assert.DoesNotContain(Token, evt.Evidence);
        Assert.DoesNotContain("private-secret-134", evt.Evidence);
        Assert.DoesNotContain(evt.StructuredEvidence!.Items, x => x.Value.Contains(Token, StringComparison.Ordinal) || x.Value.Contains("private-secret-134", StringComparison.Ordinal));
        Assert.Contains(evt.StructuredEvidence.Items, x => x.Key == "token.parameter" && x.Value == "[sensitive-credential-query]");
    }

    [Fact] public async Task Query_Keyword_Only_In_Info_Is_Not_Evidence()
    {
        var r = NetworkBatch131135Context.Web("/v1/data");
        r.Info = "access_token=" + Token;
        Assert.False((await _rule.EvaluateAsync(NetworkBatch131135Context.At(r))).Matched);
    }
}
