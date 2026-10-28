// SPDX-License-Identifier: MIT
using System;
using System.Threading.Tasks;
using Carthago.Engine.Rules;
using Carthago.Engine.Rules.Expansion;
using Carthago.Models;
using Xunit;
namespace Carthago.Tests;
public sealed class R287AdvancedAccuracyBatchTests
{
    private static TrafficRecord Sample()=>NetworkBatch286290Context.Sample();
    private static async Task<RuleEvaluationResult> Evaluate(TrafficRecord r,double seconds=0)
        =>await new R287_KerberosPreauthFailureDistributedSprayRule().EvaluateAsync(NetworkBatch286290Context.At(r,seconds));
    private static async Task<bool> Hit(TrafficRecord r,double seconds=0)=>(await Evaluate(r,seconds)).Matched;
    [Fact] public async Task Kdc_Port_Is_Not_Verified_Outcome(){var r=Sample();r.IsTcp=false;r.IsUdp=true;r.DestinationPort=88;Assert.False(await Hit(r));}
    [Fact] public async Task Preauth_Info_Is_Not_Verified_Outcome(){var r=Sample();r.Info="KDC_ERR_PREAUTH_FAILED distributed spray";Assert.False(await Hit(r));}
    [Fact] public async Task Kerberos_Label_Is_Not_Verified_Outcome(){var r=Sample();r.ApplicationProtocol="Kerberos";Assert.False(await Hit(r));}
    [Fact] public async Task AsReq_Label_Is_Not_Verified_Outcome(){var r=Sample();r.Info="AS-REQ 5 accounts";Assert.False(await Hit(r));}
    [Fact] public async Task Kdc_Reply_Is_Not_Verified_Outcome(){var r=Sample();r.SourcePort=88;r.DestinationPort=53000;Assert.False(await Hit(r));}
    [Fact] public async Task Info_Spoof_Is_Not_Trusted(){var r=Sample();r.Info="R287 verified attack";Assert.False(await Hit(r));}
    [Fact] public async Task Duplicate_Packet_Does_Not_Accumulate_Evidence(){var r=Sample();var rule=new R287_KerberosPreauthFailureDistributedSprayRule();Assert.False((await rule.EvaluateAsync(NetworkBatch286290Context.At(r))).Matched);Assert.False((await rule.EvaluateAsync(NetworkBatch286290Context.At(r,1))).Matched);}
    [Fact] public async Task Out_Of_Order_Packets_Do_Not_Accumulate_Evidence(){var r=Sample();var rule=new R287_KerberosPreauthFailureDistributedSprayRule();Assert.False((await rule.EvaluateAsync(NetworkBatch286290Context.At(r,30))).Matched);Assert.False((await rule.EvaluateAsync(NetworkBatch286290Context.At(r,1))).Matched);}
    [Fact] public async Task Missing_Source_Fails_Closed(){var r=Sample();r.Source=null;Assert.False(await Hit(r));}
    [Fact] public async Task Contradictory_Udp_Http_Fails_Closed(){var r=Sample();r.IsTcp=false;r.IsUdp=true;Assert.False(await Hit(r));}
    [Fact] public async Task Sensitive_Credentials_Are_Not_Emitted(){var r=Sample();r.HttpUri="/?password=private-secret";r.HttpRequestHeaders="Authorization: Basic c2VjcmV0";var result=await Evaluate(r);Assert.False(result.Matched);Assert.Empty(result.Events);}
    [Fact] public void Original_Profile_Is_Preserved(){var p=new R287_KerberosPreauthFailureDistributedSprayRule().PrecisionProfile;Assert.Equal(78,p.MinimumConfidence);Assert.Equal(5,p.Threshold);Assert.Equal(RuleRuntimeMode.Alert,p.DefaultMode);}
}
