// SPDX-License-Identifier: MIT
using System;
using System.Threading;
using System.Threading.Tasks;
using Carthago.Engine.Rules.LateralMovement;
using Xunit;
namespace Carthago.Tests;

public sealed class R082AdvancedAccuracyBatchTests
{
    private readonly R082_NTLMRelaySuspicionRule _rule=new();
    private async Task<bool> Seen(int sec,string? service="RELAY_CORROBORATED",
        string src="10.82.0.10",string dst="10.82.1.10",int port=445,string? info=null)
        =>(await _rule.EvaluateAsync(NetworkBatch081085Context.Ntlm(sec,service,src,dst,port,info:info))).Matched;

    [Fact] public async Task Eight_Independent_Corroborated_Relay_Observations_Trigger_Once()
    {for(var i=1;i<8;i++)Assert.False(await Seen(i));Assert.True(await Seen(8));Assert.False(await Seen(9));}
    [Fact] public async Task Normal_Ntlm_Challenge_And_Authentication_Are_Not_Relay()
    {
        for(var i=1;i<=10;i++)
        {
            Assert.False(await Seen(i,service:"NEGOTIATE",info:"relay"));
            Assert.False(await Seen(i+20,service:"CHALLENGE",info:"ntlmssp relay"));
            Assert.False(await Seen(i+40,service:"AUTHENTICATE"));
        }
    }
    [Fact] public async Task Port_Fanout_Without_Typed_Corroboration_Does_Not_Match()
    {
        for(var i=1;i<=10;i++)
            Assert.False(await Seen(i,service:null,dst:"10.82.1."+i,info:"NTLM relay"));
    }
    [Fact] public async Task Public_Destination_Wrong_Port_And_SynOnly_Are_Excluded()
    {
        Assert.False(await Seen(1,dst:"8.8.8.8"));
        Assert.False(await Seen(2,port:3389));
        var syn=NetworkBatch081085Context.Ntlm(3);syn.Record.TcpFlags=2;
        Assert.False((await _rule.EvaluateAsync(syn)).Matched);
        var udp=NetworkBatch081085Context.Ntlm(4);udp.Record.Protocol="UDP";udp.Record.IsUdp=true;udp.Record.IsTcp=false;
        Assert.False((await _rule.EvaluateAsync(udp)).Matched);
        Assert.False(await Seen(5));
    }
    [Fact] public async Task Source_Target_Isolation_And_Timeout_Are_Respected()
    {
        Assert.False(await Seen(1,src:"10.82.0.11"));
        Assert.False(await Seen(2,dst:"10.82.1.11"));
        Assert.False(await Seen(3));
        for(var i=300;i<307;i++)Assert.False(await Seen(i));
        Assert.True(await Seen(307));
    }
    [Fact] public async Task Duplicate_And_OutOfOrder_Records_Do_Not_Increment()
    {
        var id=Guid.NewGuid();
        Assert.False((await _rule.EvaluateAsync(NetworkBatch081085Context.Ntlm(1,id:id))).Matched);
        Assert.False((await _rule.EvaluateAsync(NetworkBatch081085Context.Ntlm(2,id:id))).Matched);
        Assert.False((await _rule.EvaluateAsync(NetworkBatch081085Context.Ntlm(0))).Matched);
        for(var i=3;i<9;i++)Assert.False(await Seen(i));
        Assert.True(await Seen(9));
    }
    [Fact] public async Task Cancellation_And_Redaction_Do_Not_Leak_Authentication_Data()
    {
        using var cts=new CancellationTokenSource();cts.Cancel();
        await Assert.ThrowsAnyAsync<OperationCanceledException>(async()=>
            await _rule.EvaluateAsync(NetworkBatch081085Context.Ntlm(1),cts.Token));
        for(var i=1;i<8;i++)Assert.False(await Seen(i));
        var e=Assert.Single((await _rule.EvaluateAsync(
            NetworkBatch081085Context.Ntlm(8,info:"NTLM challenge private-secret-82"))).Events);
        Assert.DoesNotContain("private-secret-82",e.Description);
        Assert.DoesNotContain("private-secret-82",e.Evidence);
    }
}
