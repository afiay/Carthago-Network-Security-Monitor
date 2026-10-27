// SPDX-License-Identifier: MIT
using System;
using System.Threading;
using System.Threading.Tasks;
using Carthago.Engine.Rules.LateralMovement;
using Xunit;
namespace Carthago.Tests;
public sealed class R078AdvancedAccuracyBatchTests
{
    private readonly R078_PsExecLikeNetworkBehaviorRule _rule=new();
    private async Task<bool> Seen(int s,bool svc=false,string src="10.76.0.10",string dst="10.76.1.10",string? info=null)
        =>(await _rule.EvaluateAsync(NetworkBatch076080Context.Event(s,
            svc?"DCE/RPC":"SMB",svc?"SVCCTL":"ADMIN_SHARE",svc?135:445,src,dst,info:info))).Matched;

    [Fact] public async Task AdminShare_Followed_By_ServiceControl_Is_Corroborated()
    {Assert.False(await Seen(1));Assert.True(await Seen(2,svc:true));Assert.False(await Seen(3,svc:true));}
    [Fact] public async Task ServiceControl_Before_Share_Does_Not_Trigger()
    {Assert.False(await Seen(1,svc:true));Assert.False(await Seen(2));Assert.True(await Seen(3,svc:true));}
    [Fact] public async Task AdminShare_Alone_Or_PsExec_Text_Alone_Is_Insufficient()
    {
        for(int i=1;i<=6;i++)Assert.False(await Seen(i,info:"psexesvc"));
        var t=NetworkBatch076080Context.Event(7,app:null,service:null,info:"PsExec remcom");
        Assert.False((await _rule.EvaluateAsync(t)).Matched);
    }
    [Fact] public async Task Correlation_Requires_Same_Exact_Pair()
    {Assert.False(await Seen(1,src:"10.76.0.11"));Assert.False(await Seen(2,svc:true));Assert.False(await Seen(3,dst:"10.76.1.11"));Assert.False(await Seen(4,svc:true));}
    [Fact] public async Task Expired_Share_Does_Not_Join_Later_ServiceControl()
    {Assert.False(await Seen(1));Assert.False(await Seen(200,svc:true));Assert.False(await Seen(201));Assert.True(await Seen(202,svc:true));}
    [Fact] public async Task Unsupported_Transport_And_Replayed_Identity_Are_Rejected()
    {
        var udp=NetworkBatch076080Context.Event(1,protocol:"UDP");
        Assert.False((await _rule.EvaluateAsync(udp)).Matched);
        var id=Guid.NewGuid();
        Assert.False((await _rule.EvaluateAsync(NetworkBatch076080Context.Event(2,id:id))).Matched);
        Assert.False((await _rule.EvaluateAsync(NetworkBatch076080Context.Event(3,"DCE/RPC","SVCCTL",135,id:id))).Matched);
        Assert.True(await Seen(4,svc:true));
    }
    [Fact] public async Task Cancellation_And_Description_Do_Not_Leak_Raw_Info()
    {
        using var cancel=new CancellationTokenSource();cancel.Cancel();
        await Assert.ThrowsAnyAsync<OperationCanceledException>(async()=>await _rule.EvaluateAsync(NetworkBatch076080Context.Event(1),cancel.Token));
        Assert.False(await Seen(2));
        var c=NetworkBatch076080Context.Event(3,"DCE/RPC","SVCCTL",135,info:"password-reset-78");
        var e=Assert.Single((await _rule.EvaluateAsync(c)).Events);
        Assert.DoesNotContain("password-reset-78",e.Description);
        Assert.DoesNotContain("password-reset-78",e.Evidence);
    }
}
