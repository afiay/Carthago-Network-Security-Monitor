// SPDX-License-Identifier: MIT
using System;
using System.Threading.Tasks;
using Carthago.Engine.Rules;
using Carthago.Engine.Rules.Expansion;
using Carthago.Models;
using Xunit;
namespace Carthago.Tests;
public sealed class R286AdvancedAccuracyBatchTests
{
    private static TrafficRecord Sample()=>NetworkBatch286290Context.Sample();
    private static async Task<RuleEvaluationResult> Evaluate(TrafficRecord r,double seconds=0)
        =>await new R286_LDAPSimpleBindOverCleartextExternalRule().EvaluateAsync(NetworkBatch286290Context.At(r,seconds));
    private static async Task<bool> Hit(TrafficRecord r,double seconds=0)=>(await Evaluate(r,seconds)).Matched;
    [Fact] public async Task Ldap_Port_Is_Not_Verified_Outcome(){var r=Sample();r.DestinationPort=389;r.ApplicationProtocol="LDAP";Assert.False(await Hit(r));}
    [Fact] public async Task Bind_Info_Is_Not_Verified_Outcome(){var r=Sample();r.Info="LDAP simple bind password observed";Assert.False(await Hit(r));}
    [Fact] public async Task Ldap_Label_Is_Not_Verified_Outcome(){var r=Sample();r.ApplicationProtocol="LDAP";r.HttpUri=null;Assert.False(await Hit(r));}
    [Fact] public async Task Http_Basic_Is_Not_Verified_Outcome(){var r=Sample();r.HttpRequestHeaders="Authorization: Basic c2VjcmV0";Assert.False(await Hit(r));}
    [Fact] public async Task Ldap_External_Is_Not_Verified_Outcome(){var r=Sample();r.Destination="185.220.100.254";r.DestinationPort=389;Assert.False(await Hit(r));}
    [Fact] public async Task Info_Spoof_Is_Not_Trusted(){var r=Sample();r.Info="R286 verified attack";Assert.False(await Hit(r));}
    [Fact] public async Task Duplicate_Packet_Does_Not_Accumulate_Evidence(){var r=Sample();var rule=new R286_LDAPSimpleBindOverCleartextExternalRule();Assert.False((await rule.EvaluateAsync(NetworkBatch286290Context.At(r))).Matched);Assert.False((await rule.EvaluateAsync(NetworkBatch286290Context.At(r,1))).Matched);}
    [Fact] public async Task Out_Of_Order_Packets_Do_Not_Accumulate_Evidence(){var r=Sample();var rule=new R286_LDAPSimpleBindOverCleartextExternalRule();Assert.False((await rule.EvaluateAsync(NetworkBatch286290Context.At(r,30))).Matched);Assert.False((await rule.EvaluateAsync(NetworkBatch286290Context.At(r,1))).Matched);}
    [Fact] public async Task Missing_Source_Fails_Closed(){var r=Sample();r.Source=null;Assert.False(await Hit(r));}
    [Fact] public async Task Contradictory_Udp_Http_Fails_Closed(){var r=Sample();r.IsTcp=false;r.IsUdp=true;Assert.False(await Hit(r));}
    [Fact] public async Task Sensitive_Credentials_Are_Not_Emitted(){var r=Sample();r.HttpUri="/?password=private-secret";r.HttpRequestHeaders="Authorization: Basic c2VjcmV0";var result=await Evaluate(r);Assert.False(result.Matched);Assert.Empty(result.Events);}
    [Fact] public void Original_Profile_Is_Preserved(){var p=new R286_LDAPSimpleBindOverCleartextExternalRule().PrecisionProfile;Assert.Equal(78,p.MinimumConfidence);Assert.Equal(1,p.Threshold);Assert.Equal(RuleRuntimeMode.Alert,p.DefaultMode);}
}
