// SPDX-License-Identifier: MIT
using System;
using System.Threading.Tasks;
using Carthago.Engine.Rules;
using Carthago.Engine.Rules.Expansion;
using Xunit;
namespace Carthago.Tests;

public sealed class R129AdvancedAccuracyBatchTests
{
    private readonly R129_SuspiciousSamlOidcCallbackTrafficRule _rule = new();
    [Fact] public async Task IdToken_In_Callback_Query_Matches()
    {
        Assert.True((await _rule.EvaluateAsync(NetworkBatch126130Context.At(NetworkBatch126130Context.Callback()))).Matched);
    }
    [Fact] public async Task Authorization_Code_State_Only_Is_Normal()
    {
        var r = NetworkBatch126130Context.Web("/signin-oidc?code=123&state=abc");
        Assert.False((await _rule.EvaluateAsync(NetworkBatch126130Context.At(r))).Matched);
    }
    [Fact] public async Task Fragment_Is_Not_Observable_Http_Query()
    {
        var r = NetworkBatch126130Context.Web("/signin-oidc#access_token=private");
        Assert.False((await _rule.EvaluateAsync(NetworkBatch126130Context.At(r))).Matched);
    }
    [Fact] public async Task Cleartext_Redirect_In_Callback_Query_Matches()
    {
        var r = NetworkBatch126130Context.Web("/oauth2/callback?redirect_uri=http%3A%2F%2Fevil.example%2Freturn");
        Assert.True((await _rule.EvaluateAsync(NetworkBatch126130Context.At(r))).Matched);
    }
    [Fact] public async Task Noncallback_Token_And_Empty_Token_Are_Benign()
    {
        var r = NetworkBatch126130Context.Web("/login?id_token=opaque");
        Assert.False((await _rule.EvaluateAsync(NetworkBatch126130Context.At(r))).Matched);
        var e = NetworkBatch126130Context.Web("/signin-oidc?id_token=");
        Assert.False((await _rule.EvaluateAsync(NetworkBatch126130Context.At(e))).Matched);
    }
    [Fact] public async Task Contradictory_Transport_Or_Sni_Fails_Closed()
    {
        var r = NetworkBatch126130Context.Callback(); r.IsTcp = false;
        Assert.False((await _rule.EvaluateAsync(NetworkBatch126130Context.At(r))).Matched);
        var s = NetworkBatch126130Context.Callback(); s.Sni = "other.example.test";
        Assert.False((await _rule.EvaluateAsync(NetworkBatch126130Context.At(s))).Matched);
    }
    [Fact] public async Task Callback_Secrets_Never_Persist_And_Shadow_Preserved()
    {
        Assert.Equal(RuleRuntimeMode.Shadow, _rule.PrecisionProfile.DefaultMode);
        var r = NetworkBatch126130Context.Web("/signin-oidc?access_token=private-secret-129");
        var evt = Assert.Single((await _rule.EvaluateAsync(NetworkBatch126130Context.At(r))).Events);
        Assert.DoesNotContain("private-secret-129", evt.Evidence);
        Assert.DoesNotContain(evt.StructuredEvidence!.Items, x => x.Value.Contains("private-secret-129", StringComparison.Ordinal));
    }
}
