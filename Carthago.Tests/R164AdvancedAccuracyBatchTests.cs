// SPDX-License-Identifier: MIT
using System;
using System.Linq;
using System.Threading.Tasks;
using Carthago.Engine.Rules;
using Carthago.Engine.Rules.Expansion;
using Carthago.Models;
using Xunit;
namespace Carthago.Tests;
public sealed class R164AdvancedAccuracyBatchTests
{

    [Fact] public async Task Foreign_Redirect_Target_Matches()
    {
        var r=NetworkBatch156165Context.Http("/login?next=https%3A%2F%2Fevil.test%2Fcollect");
        Assert.True((await new R164_OpenRedirectParameterAbuseRule().EvaluateAsync(NetworkBatch156165Context.At(r))).Matched);
    }
    [Fact] public async Task Internal_Redirect_Target_Matches()
    {
        var r=NetworkBatch156165Context.Http("/login?return=http%3A%2F%2F127.0.0.1%2Fadmin");
        Assert.True((await new R164_OpenRedirectParameterAbuseRule().EvaluateAsync(NetworkBatch156165Context.At(r))).Matched);
    }
    [Fact] public async Task Same_Site_Return_Is_Benign()
    {
        var r=NetworkBatch156165Context.Http("/login?next=https%3A%2F%2Fapi.internal.local%2Fhome");
        Assert.False((await new R164_OpenRedirectParameterAbuseRule().EvaluateAsync(NetworkBatch156165Context.At(r))).Matched);
    }
    [Fact] public async Task Expected_Oidc_Callback_Is_Excluded()
    {
        var r=NetworkBatch156165Context.Http("/oauth/callback?redirect_uri=http%3A%2F%2Fevil.test%2Fcallback");
        Assert.False((await new R164_OpenRedirectParameterAbuseRule().EvaluateAsync(NetworkBatch156165Context.At(r))).Matched);
    }
    [Fact] public async Task Packet_Info_Alone_Does_Not_Create_Redirect()
    {
        var r=NetworkBatch156165Context.Http("/home");r.Info="next=http://evil.test";
        Assert.False((await new R164_OpenRedirectParameterAbuseRule().EvaluateAsync(NetworkBatch156165Context.At(r))).Matched);
    }
    [Fact] public async Task Duplicate_Id_Cannot_Realert()
    {
        var rule=new R164_OpenRedirectParameterAbuseRule();var r=NetworkBatch156165Context.Http("/login?next=https%3A%2F%2Fevil.test");
        Assert.True((await rule.EvaluateAsync(NetworkBatch156165Context.At(r))).Matched);
        Assert.False((await rule.EvaluateAsync(NetworkBatch156165Context.At(r,5))).Matched);
    }
    [Fact] public async Task Redirect_Target_Secret_Is_Not_Emitted()
    {
        var r=NetworkBatch156165Context.Http("/login?next=https%3A%2F%2Fevil.test%2Fcollect%3Ftoken%3DSECRET164");
        var result=await new R164_OpenRedirectParameterAbuseRule().EvaluateAsync(NetworkBatch156165Context.At(r));
        Assert.True(result.Matched);
        Assert.DoesNotContain(Assert.Single(result.Events).StructuredEvidence!.Items,x=>x.Value.Contains("SECRET164",StringComparison.Ordinal));
    }
    [Fact] public void Policy_And_Confidence_Floor_Are_Preserved()
    {
        var p=new R164_OpenRedirectParameterAbuseRule().PrecisionProfile;
        Assert.Equal(74,p.MinimumConfidence);
        Assert.Equal(RuleRuntimeMode.Shadow,p.DefaultMode);
    }
}
