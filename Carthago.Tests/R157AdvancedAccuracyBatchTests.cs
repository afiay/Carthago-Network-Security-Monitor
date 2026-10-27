// SPDX-License-Identifier: MIT
using System;
using System.Linq;
using System.Threading.Tasks;
using Carthago.Engine.Rules;
using Carthago.Engine.Rules.Expansion;
using Carthago.Models;
using Xunit;
namespace Carthago.Tests;
public sealed class R157AdvancedAccuracyBatchTests
{

    [Fact] public async Task AccessToken_Query_Signed_Jwt_Matches()
    {
        var r=NetworkBatch156165Context.Http("/callback?access_token="+NetworkBatch156165Context.Jwt(false));
        Assert.True((await new R157_JwtInUrlQueryRule().EvaluateAsync(NetworkBatch156165Context.At(r))).Matched);
    }
    [Fact] public async Task IdToken_Query_Signed_Jwt_Matches()
    {
        var r=NetworkBatch156165Context.Http("/callback?id_token="+NetworkBatch156165Context.Jwt(false));
        Assert.True((await new R157_JwtInUrlQueryRule().EvaluateAsync(NetworkBatch156165Context.At(r))).Matched);
    }
    [Fact] public async Task State_Parameter_Is_Not_Bearer_Exposure()
    {
        var r=NetworkBatch156165Context.Http("/callback?state="+NetworkBatch156165Context.Jwt(false));
        Assert.False((await new R157_JwtInUrlQueryRule().EvaluateAsync(NetworkBatch156165Context.At(r))).Matched);
    }
    [Fact] public async Task Alg_None_Is_Separate_Rule_Not_Signed_Jwt()
    {
        var r=NetworkBatch156165Context.Http("/callback?access_token="+NetworkBatch156165Context.Jwt());
        Assert.False((await new R157_JwtInUrlQueryRule().EvaluateAsync(NetworkBatch156165Context.At(r))).Matched);
    }
    [Fact] public async Task Header_Only_Token_Is_Not_Url_Exposure()
    {
        var r=NetworkBatch156165Context.Http("/callback");r.HttpRequestHeaders+="\nAuthorization: Bearer "+NetworkBatch156165Context.Jwt(false);
        Assert.False((await new R157_JwtInUrlQueryRule().EvaluateAsync(NetworkBatch156165Context.At(r))).Matched);
    }
    [Fact] public async Task Contradictory_Host_And_Absolute_Uri_Fail()
    {
        var r=NetworkBatch156165Context.Http("https://unrelated.test/callback?jwt="+NetworkBatch156165Context.Jwt(false));
        Assert.False((await new R157_JwtInUrlQueryRule().EvaluateAsync(NetworkBatch156165Context.At(r))).Matched);
    }
    [Fact] public async Task Duplicate_Record_Is_Not_Recounted()
    {
        var rule=new R157_JwtInUrlQueryRule();var r=NetworkBatch156165Context.Http("/callback?jwt="+NetworkBatch156165Context.Jwt(false));
        Assert.True((await rule.EvaluateAsync(NetworkBatch156165Context.At(r))).Matched);
        Assert.False((await rule.EvaluateAsync(NetworkBatch156165Context.At(r,1))).Matched);
    }
    [Fact] public async Task Query_Secret_Is_Not_Emitted()
    {
        var token=NetworkBatch156165Context.Jwt(false);var r=NetworkBatch156165Context.Http("/callback?jwt="+token);
        var result=await new R157_JwtInUrlQueryRule().EvaluateAsync(NetworkBatch156165Context.At(r));
        Assert.True(result.Matched);
        Assert.DoesNotContain(Assert.Single(result.Events).StructuredEvidence!.Items,x=>x.Value.Contains(token,StringComparison.Ordinal));
    }
    [Fact] public void Configured_Mode_And_Confidence_Floor_Remain_Unchanged()
    {
        var profile=new R157_JwtInUrlQueryRule().PrecisionProfile;
        Assert.Equal(74,profile.MinimumConfidence);
        Assert.Equal(RuleRuntimeMode.Shadow,profile.DefaultMode);
    }
}
