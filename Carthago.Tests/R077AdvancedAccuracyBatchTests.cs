// SPDX-License-Identifier: MIT
using System;
using System.Threading;
using System.Threading.Tasks;
using Carthago.Engine.Rules.LateralMovement;
using Xunit;
namespace Carthago.Tests;
public sealed class R077AdvancedAccuracyBatchTests
{
    private readonly R077_RPCServiceControlPatternRule _rule=new();
    private async Task<bool> Seen(int s,string? app="DCE/RPC",string? svc="SVCCTL",
        int port=135,string src="10.76.0.10",string dst="10.76.1.10",string? info=null)
        =>(await _rule.EvaluateAsync(NetworkBatch076080Context.Event(s,app,svc,port,src,dst,info:info))).Matched;

    [Fact] public async Task Two_Classified_Service_Control_Requests_Trigger()
    {Assert.False(await Seen(1));Assert.True(await Seen(2));Assert.False(await Seen(3));}
    [Fact] public async Task Svcctl_Over_SmbNamedPipe_Port_Is_Supported()
    {Assert.False(await Seen(1,port:445));Assert.True(await Seen(2,port:445));}
    [Fact] public async Task Benign_Rpc_Lookups_And_Textual_Phrases_Are_Rejected()
    {for(var i=1;i<=7;i++){Assert.False(await Seen(i,svc:"EPM_LOOKUP",info:"CreateService"));Assert.False(await Seen(i+10,app:null,svc:null,info:"svcctl openSCManager"));}}
    [Fact] public async Task Wrong_Port_Transport_Or_Syn_Only_Cannot_Count()
    {
        Assert.False(await Seen(1,port:3389));
        var udp=NetworkBatch076080Context.Event(2,"DCE/RPC","SVCCTL",135,protocol:"UDP");
        Assert.False((await _rule.EvaluateAsync(udp)).Matched);
        var syn=NetworkBatch076080Context.Event(3,"DCE/RPC","SVCCTL",135);syn.Record.TcpFlags=2;
        Assert.False((await _rule.EvaluateAsync(syn)).Matched);
        Assert.False(await Seen(4));
    }
    [Fact] public async Task Different_Initiators_And_Targets_Do_Not_Join()
    {Assert.False(await Seen(1,src:"10.76.0.11"));Assert.False(await Seen(2,dst:"10.76.1.11"));Assert.False(await Seen(3));Assert.True(await Seen(4));}
    [Fact] public async Task Identical_Record_Stale_Window_And_Reverse_Time_Are_Ignored()
    {
        var id=Guid.NewGuid();
        Assert.False((await _rule.EvaluateAsync(NetworkBatch076080Context.Event(1,"DCE/RPC","SVCCTL",135,id:id))).Matched);
        Assert.False((await _rule.EvaluateAsync(NetworkBatch076080Context.Event(2,"DCE/RPC","SVCCTL",135,id:id))).Matched);
        Assert.False((await _rule.EvaluateAsync(NetworkBatch076080Context.Event(0,"DCE/RPC","SVCCTL",135))).Matched);
        Assert.True(await Seen(3));
    }
    [Fact] public async Task Cancellation_Privacy_And_Future_Timestamp_Are_Protected()
    {
        using var cancel=new CancellationTokenSource();cancel.Cancel();
        await Assert.ThrowsAnyAsync<OperationCanceledException>(async()=>await _rule.EvaluateAsync(NetworkBatch076080Context.Event(1,"DCE/RPC","SVCCTL",135),cancel.Token));
        var future=NetworkBatch076080Context.Event(1500,"DCE/RPC","SVCCTL",135);
        Assert.False((await _rule.EvaluateAsync(future)).Matched);
        Assert.False(await Seen(2));
        var hit=await _rule.EvaluateAsync(NetworkBatch076080Context.Event(3,"DCE/RPC","SVCCTL",135,info:"session-token-77"));
        var e=Assert.Single(hit.Events);
        Assert.DoesNotContain("session-token-77",e.Evidence);
        Assert.DoesNotContain("session-token-77",e.Description);
    }
}
