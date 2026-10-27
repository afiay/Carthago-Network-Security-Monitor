// SPDX-License-Identifier: MIT
using System;
using System.Linq;
using System.Threading.Tasks;
using Carthago.Engine.Rules;
using Carthago.Engine.Rules.Expansion;
using Carthago.Models;
using Xunit;
namespace Carthago.Tests;
public sealed class R156AdvancedAccuracyBatchTests
{

    [Fact] public async Task Bearer_None_Jwt_Is_Observable()
    {
        var r=NetworkBatch156165Context.Http("/login");r.HttpRequestHeaders+="\nAuthorization: Bearer "+NetworkBatch156165Context.Jwt();
        Assert.True((await new R156_JwtNoneAlgorithmIndicatorRule().EvaluateAsync(NetworkBatch156165Context.At(r))).Matched);
    }
    [Fact] public async Task Query_None_Jwt_Is_Observable()
    {
        var r=NetworkBatch156165Context.Http("/auth?jwt="+NetworkBatch156165Context.Jwt());
        Assert.True((await new R156_JwtNoneAlgorithmIndicatorRule().EvaluateAsync(NetworkBatch156165Context.At(r))).Matched);
    }
    [Fact] public async Task Signed_Jwt_Does_Not_Match_None()
    {
        var r=NetworkBatch156165Context.Http("/login");r.HttpRequestHeaders+="\nAuthorization: Bearer "+NetworkBatch156165Context.Jwt(false);
        Assert.False((await new R156_JwtNoneAlgorithmIndicatorRule().EvaluateAsync(NetworkBatch156165Context.At(r))).Matched);
    }
    [Fact] public async Task Info_Only_Is_Not_Jwt_Provenance()
    {
        var r=NetworkBatch156165Context.Http();r.Info="Bearer "+NetworkBatch156165Context.Jwt();
        Assert.False((await new R156_JwtNoneAlgorithmIndicatorRule().EvaluateAsync(NetworkBatch156165Context.At(r))).Matched);
    }
    [Fact] public async Task Contradictory_Udp_Does_Not_Match()
    {
        var r=NetworkBatch156165Context.Http("/auth?jwt="+NetworkBatch156165Context.Jwt());r.IsTcp=false;r.IsUdp=true;
        Assert.False((await new R156_JwtNoneAlgorithmIndicatorRule().EvaluateAsync(NetworkBatch156165Context.At(r))).Matched);
    }
    [Fact] public async Task Same_Packet_Cannot_Replay()
    {
        var rule=new R156_JwtNoneAlgorithmIndicatorRule();var r=NetworkBatch156165Context.Http("/auth?jwt="+NetworkBatch156165Context.Jwt());
        Assert.True((await rule.EvaluateAsync(NetworkBatch156165Context.At(r))).Matched);
        Assert.False((await rule.EvaluateAsync(NetworkBatch156165Context.At(r,10))).Matched);
    }
    [Fact] public async Task Jwt_Bytes_Are_Not_Persisted_In_Evidence()
    {
        var token=NetworkBatch156165Context.Jwt();var r=NetworkBatch156165Context.Http("/auth?jwt="+token);
        var result=await new R156_JwtNoneAlgorithmIndicatorRule().EvaluateAsync(NetworkBatch156165Context.At(r));
        Assert.True(result.Matched);
        Assert.DoesNotContain(Assert.Single(result.Events).StructuredEvidence!.Items,x=>x.Value.Contains(token,StringComparison.Ordinal));
    }
    [Fact] public void Configured_Mode_And_Confidence_Floor_Remain_Unchanged()
    {
        var profile=new R156_JwtNoneAlgorithmIndicatorRule().PrecisionProfile;
        Assert.Equal(80,profile.MinimumConfidence);
        Assert.Equal(RuleRuntimeMode.Alert,profile.DefaultMode);
    }
}
