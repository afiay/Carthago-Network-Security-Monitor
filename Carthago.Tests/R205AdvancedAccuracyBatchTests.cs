// SPDX-License-Identifier: MIT
using System;
using System.Threading.Tasks;
using Carthago.Engine.Rules;
using Carthago.Engine.Rules.Expansion;
using Carthago.Models;
using Xunit;
namespace Carthago.Tests;
public sealed class R205AdvancedAccuracyBatchTests
{
    private static TrafficRecord S() => NetworkBatch201205Context.Secret();
    private static async Task<bool> Hit(TrafficRecord r) => (await new R205_CiCdSecretTokenInUrlRule().EvaluateAsync(NetworkBatch201205Context.At(r))).Matched;
    [Fact] public async Task Exact_Token_Query_Parameter_Qualifies() => Assert.True(await Hit(S()));
    [Fact] public async Task Placeholder_Token_Value_Is_Not_Credential()
    {
        var r = S(); r.HttpUri = "/callback?github_token=placeholder012345678901";
        Assert.False(await Hit(r));
    }
    [Fact] public async Task Token_Name_Substring_Is_Not_Exact_Parameter()
    {
        var r = S(); r.HttpUri = "/callback?not_github_token=ghp_ABCDEFGHIJKLMNOPQRSTUVWXYZ123456";
        Assert.False(await Hit(r));
    }
    [Fact] public async Task Info_Only_Token_Claim_Is_Not_Parsed_Url()
    {
        var r = S(); r.HttpUri = "/callback"; r.Info = "github_token=ghp_ABCDEFGHIJKLMNOPQRSTUVWXYZ123456";
        Assert.False(await Hit(r));
    }
    [Fact] public async Task Contradictory_Http_Authority_Is_Rejected()
    {
        var r = S(); r.HttpRequestHeaders = "Host: attacker.example.net";
        Assert.False(await Hit(r));
    }
    [Fact] public async Task Duplicate_Packet_Id_Rejected()
    {
        var rule = new R205_CiCdSecretTokenInUrlRule(); var r = S();
        Assert.True((await rule.EvaluateAsync(NetworkBatch201205Context.At(r))).Matched);
        Assert.False((await rule.EvaluateAsync(NetworkBatch201205Context.At(r, 1))).Matched);
    }
    [Fact] public async Task Out_Of_Order_Secret_Url_Rejected()
    {
        var rule = new R205_CiCdSecretTokenInUrlRule();
        Assert.True((await rule.EvaluateAsync(NetworkBatch201205Context.At(S(), 10))).Matched);
        Assert.False((await rule.EvaluateAsync(NetworkBatch201205Context.At(S(), 5))).Matched);
    }
    [Fact] public async Task Secret_Value_And_Query_Redacted()
    {
        var x = await new R205_CiCdSecretTokenInUrlRule().EvaluateAsync(NetworkBatch201205Context.At(S()));
        Assert.True(x.Matched);
        Assert.DoesNotContain(Assert.Single(x.Events).StructuredEvidence!.Items,
            e => e.Value.Contains("ghp_", StringComparison.Ordinal) || e.Value.Contains("ABCDEFGHIJKLMNOPQRSTUVWXYZ", StringComparison.Ordinal));
    }
    [Fact] public void Alert_And_Confidence_Floor_Unchanged()
    {
        var p = new R205_CiCdSecretTokenInUrlRule().PrecisionProfile;
        Assert.Equal(86, p.MinimumConfidence); Assert.Equal(RuleRuntimeMode.Alert, p.DefaultMode);
    }
}
