// SPDX-License-Identifier: MIT
using System;
using System.Linq;
using System.Threading.Tasks;
using Carthago.Engine.Rules;
using Carthago.Engine.Rules.Expansion;
using Carthago.Models;
using Xunit;
namespace Carthago.Tests;
public sealed class R169AdvancedAccuracyBatchTests
{
    [Fact] public async Task Six_Independent_Failures_Cross_Threshold()
    {
        var rule=new R169_AdminLoginBruteIndicatorRule();RuleEvaluationResult? last=null;for(int i=0;i<6;i++)last=await rule.EvaluateAsync(NetworkBatch166175Context.At(NetworkBatch166175Context.Fail(),i*10));Assert.True(last!.Matched);
    }
    [Fact] public async Task Single_Failure_Is_Not_Brute_Force()
    {
        Assert.False((await new R169_AdminLoginBruteIndicatorRule().EvaluateAsync(NetworkBatch166175Context.At(NetworkBatch166175Context.Fail()))).Matched);
    }
    [Fact] public async Task Successful_Logins_Do_Not_Accumulate_Failures()
    {
        var rule=new R169_AdminLoginBruteIndicatorRule();for(int i=0;i<8;i++){var r=NetworkBatch166175Context.Fail();r.Info="login successful";Assert.False((await rule.EvaluateAsync(NetworkBatch166175Context.At(r,i))).Matched);}
    }
    [Fact] public async Task Duplicate_Packet_Ids_Cannot_Reach_Threshold()
    {
        var rule=new R169_AdminLoginBruteIndicatorRule();var r=NetworkBatch166175Context.Fail();for(int i=0;i<8;i++)Assert.False((await rule.EvaluateAsync(NetworkBatch166175Context.At(r,i))).Matched);
    }
    [Fact] public async Task Independent_Sources_Cannot_Combine_Three_Plus_Three()
    {
        var rule=new R169_AdminLoginBruteIndicatorRule();for(int i=0;i<6;i++){var r=NetworkBatch166175Context.Fail(i<3?"203.0.113.166":"203.0.113.169");Assert.False((await rule.EvaluateAsync(NetworkBatch166175Context.At(r,i*10))).Matched);}
    }
    [Fact] public async Task Older_Failures_Cannot_Rewind_State()
    {
        var rule=new R169_AdminLoginBruteIndicatorRule();Assert.False((await rule.EvaluateAsync(NetworkBatch166175Context.At(NetworkBatch166175Context.Fail(),100))).Matched);for(int i=0;i<6;i++)Assert.False((await rule.EvaluateAsync(NetworkBatch166175Context.At(NetworkBatch166175Context.Fail(),i))).Matched);
    }
    [Fact] public async Task Unattributed_Or_Contradictory_Http_Is_Not_Counted()
    {
        var rule=new R169_AdminLoginBruteIndicatorRule();for(int i=0;i<8;i++){var r=NetworkBatch166175Context.Fail();r.HttpRequestHeaders="Host: wrong.example";Assert.False((await rule.EvaluateAsync(NetworkBatch166175Context.At(r,i))).Matched);}
    }
    [Fact] public async Task Credential_Query_And_Info_Are_Not_Emitted()
    {
        var rule=new R169_AdminLoginBruteIndicatorRule();RuleEvaluationResult? last=null;for(int i=0;i<6;i++){var r=NetworkBatch166175Context.Fail();r.HttpUri="/admin/login?username=SECRET169";r.Info="invalid password SECRET169";last=await rule.EvaluateAsync(NetworkBatch166175Context.At(r,i));}Assert.True(last!.Matched);Assert.DoesNotContain(Assert.Single(last.Events).StructuredEvidence!.Items,i=>i.Value.Contains("SECRET169",StringComparison.Ordinal));
    }
    [Fact] public void Runtime_Policy_And_Confidence_Floor_Are_Preserved()
    {
        var p=new R169_AdminLoginBruteIndicatorRule().PrecisionProfile;
        Assert.Equal(74,p.MinimumConfidence);
        Assert.Equal(RuleRuntimeMode.Shadow,p.DefaultMode);
    }
}
