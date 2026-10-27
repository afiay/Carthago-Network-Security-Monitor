// SPDX-License-Identifier: MIT
using System;
using System.Threading;
using System.Threading.Tasks;
using Carthago.Engine.Rules.LateralMovement;
using Xunit;
namespace Carthago.Tests;
public sealed class R079AdvancedAccuracyBatchTests
{
    private readonly R079_LDAPEnumerationSpikeRule _rule=new();
    private async Task<bool> Seen(int s,string? app="LDAP",string? svc="SEARCH_REQUEST",
       int port=389,string src="10.76.0.10",string dst="10.76.1.10",string? info=null)
       =>(await _rule.EvaluateAsync(NetworkBatch076080Context.Event(s,app,svc,port,src,dst,info:info))).Matched;

    [Fact] public async Task Forty_Classified_Searches_In_Window_Trigger_Once()
    {
        for(int i=1;i<40;i++)Assert.False(await Seen(i));
        Assert.True(await Seen(40));
        Assert.False(await Seen(41));
    }
    [Fact] public async Task ThirtyNine_Legitimate_Directory_Searches_Stay_Below_Threshold()
    {for(int i=1;i<40;i++)Assert.False(await Seen(i));}
    [Fact] public async Task Keyword_Matches_And_NonSearch_Ldap_Are_Not_Proof()
    {
        for(int i=1;i<=45;i++){
            Assert.False(await Seen(i,app:null,svc:null,info:"objectClass memberOf adminCount"));
            Assert.False(await Seen(i+100,svc:"BIND_REQUEST",info:"LDAP search"));
        }
    }
    [Fact] public async Task Internal_Transport_Port_And_Identity_Are_Required()
    {
        for(int i=1;i<=50;i++){
            Assert.False(await Seen(i,port:80));
            Assert.False(await Seen(i,src:"8.8.8.8"));
        }
        var udp=NetworkBatch076080Context.Event(51,"LDAP","SEARCH_REQUEST",389,protocol:"UDP");
        Assert.False((await _rule.EvaluateAsync(udp)).Matched);
    }
    [Fact] public async Task Directory_Port_Target_And_Client_Are_Isolated()
    {
        for(int i=1;i<=20;i++){
            Assert.False(await Seen(i,src:"10.76.0.11"));
            Assert.False(await Seen(i+30,port:636,dst:"10.76.1.11"));
        }
        Assert.False(await Seen(52));
    }
    [Fact] public async Task Repeated_Record_Id_And_Long_Gap_Cannot_Fabricate_Spike()
    {
        var id=Guid.NewGuid();
        for(int i=1;i<=50;i++)Assert.False((await _rule.EvaluateAsync(NetworkBatch076080Context.Event(i,"LDAP","SEARCH_REQUEST",389,id:id))).Matched);
        Assert.False(await Seen(300));
    }
    [Fact] public async Task Cancellation_And_Redacted_Alert_Content()
    {
        using var c=new CancellationTokenSource();c.Cancel();
        await Assert.ThrowsAnyAsync<OperationCanceledException>(async()=>await _rule.EvaluateAsync(NetworkBatch076080Context.Event(1,"LDAP","SEARCH_REQUEST",389),c.Token));
        for(int i=1;i<40;i++)Assert.False(await Seen(i));
        var hit=await _rule.EvaluateAsync(NetworkBatch076080Context.Event(40,"LDAP","SEARCH_REQUEST",389,info:"cn=private-directory-79"));
        var e=Assert.Single(hit.Events);
        Assert.DoesNotContain("private-directory-79",e.Description);
        Assert.DoesNotContain("private-directory-79",e.Evidence);
    }
}
