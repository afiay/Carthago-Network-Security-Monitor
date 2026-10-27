// SPDX-License-Identifier: MIT
using System;
using System.Threading.Tasks;
using Carthago.Engine.Rules;
using Carthago.Engine.Rules.Expansion;
using Xunit;
namespace Carthago.Tests;

public sealed class R130AdvancedAccuracyBatchTests
{
    private readonly R130_CredentialStuffingAgainstWebLoginRule _rule = new();
    [Fact] public async Task Twenty_Independent_Failed_Logins_Match()
    {
        for (int i = 0; i < 19; i++)
            Assert.False((await _rule.EvaluateAsync(NetworkBatch126130Context.At(NetworkBatch126130Context.Login(), i))).Matched);
        var result = await _rule.EvaluateAsync(NetworkBatch126130Context.At(NetworkBatch126130Context.Login(), 19));
        Assert.True(result.Matched);
        Assert.Contains(Assert.Single(result.Events).StructuredEvidence!.Items, x => x.Key == "count" && x.Value == "20");
    }
    [Fact] public async Task Duplicate_Replayed_Record_Cannot_Inflate_Threshold()
    {
        var r = NetworkBatch126130Context.Login();
        for (int i = 0; i < 24; i++)
            Assert.False((await _rule.EvaluateAsync(NetworkBatch126130Context.At(r, i))).Matched);
    }
    [Fact] public async Task Normal_One_Identity_Login_Volume_Does_Not_Match()
    {
        for (int i = 0; i < 22; i++)
            Assert.False((await _rule.EvaluateAsync(NetworkBatch126130Context.At(NetworkBatch126130Context.Login("alice", false), i))).Matched);
    }
    [Fact] public async Task Multiple_Distinct_Identities_Provide_Independent_Signal()
    {
        for (int i = 0; i < 19; i++)
            Assert.False((await _rule.EvaluateAsync(NetworkBatch126130Context.At(NetworkBatch126130Context.Login("user" + (i % 6), false), i))).Matched);
        Assert.True((await _rule.EvaluateAsync(NetworkBatch126130Context.At(NetworkBatch126130Context.Login("user5", false), 19))).Matched);
    }
    [Fact] public async Task Get_And_Unsupported_Port_Only_Records_Fail_Closed()
    {
        var r = NetworkBatch126130Context.Login(); r.HttpMethod = "GET";
        Assert.False((await _rule.EvaluateAsync(NetworkBatch126130Context.At(r))).Matched);
        var p = NetworkBatch126130Context.Login(); p.IsTcp = false;
        Assert.False((await _rule.EvaluateAsync(NetworkBatch126130Context.At(p))).Matched);
    }
    [Fact] public async Task Out_Of_Window_And_Missing_Identity_Do_Not_Prime_Burst()
    {
        for (int i = 0; i < 19; i++)
            Assert.False((await _rule.EvaluateAsync(NetworkBatch126130Context.At(NetworkBatch126130Context.Login(), i))).Matched);
        var blank = NetworkBatch126130Context.Login("", false); blank.Info = "login submitted";
        Assert.False((await _rule.EvaluateAsync(NetworkBatch126130Context.At(blank, 20))).Matched);
        Assert.False((await _rule.EvaluateAsync(NetworkBatch126130Context.At(NetworkBatch126130Context.Login(), 320))).Matched);
    }
    [Fact] public async Task Secret_Path_And_Shadow_Policy_Are_Preserved()
    {
        Assert.Equal(RuleRuntimeMode.Shadow, _rule.PrecisionProfile.DefaultMode);
        for (int i = 0; i < 19; i++)
            await _rule.EvaluateAsync(NetworkBatch126130Context.At(NetworkBatch126130Context.Login(), i));
        var r = NetworkBatch126130Context.Login(); r.HttpUri = "/login/private-secret-130?password=hidden";
        var evt = Assert.Single((await _rule.EvaluateAsync(NetworkBatch126130Context.At(r, 19))).Events);
        Assert.DoesNotContain("private-secret-130", evt.Evidence);
        Assert.DoesNotContain(evt.StructuredEvidence!.Items, x => x.Value.Contains("private-secret-130", StringComparison.Ordinal));
    }
}
