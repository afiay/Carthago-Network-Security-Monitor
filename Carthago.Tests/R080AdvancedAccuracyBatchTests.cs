// SPDX-License-Identifier: MIT
using System;
using System.Threading;
using System.Threading.Tasks;
using Carthago.Engine.Rules.LateralMovement;
using Xunit;
namespace Carthago.Tests;
public sealed class R080AdvancedAccuracyBatchTests
{
    private readonly R080_KerberosTGSRequestSpikeRule _rule=new();
    private async Task<bool> Seen(int s,string? svc="TGS_REQ",int port=88,
        string proto="UDP",string src="10.76.0.10",string dst="10.76.1.10",string? info=null)
        =>(await _rule.EvaluateAsync(NetworkBatch076080Context.Event(s,"KERBEROS",svc,port,src,dst,proto,info))).Matched;

    [Fact] public async Task Sixty_Attributed_Tgs_Requests_Trigger_Once()
    {
        for(int i=1;i<60;i++)Assert.False(await Seen(i));
        Assert.True(await Seen(60));
        Assert.False(await Seen(61));
    }
    [Fact] public async Task Fewer_Than_Sixty_Requests_Are_Not_Spike()
    {for(int i=1;i<60;i++)Assert.False(await Seen(i));}
    [Fact] public async Task Ordinary_AsReq_PreAuth_And_Textual_Tgs_Do_Not_Count()
    {
        for(int i=1;i<=65;i++){
            Assert.False(await Seen(i,svc:"AS_REQ",info:"TGS-REQ sname"));
            var t=NetworkBatch076080Context.Event(i+100,app:null,service:null,port:88,protocol:"UDP",info:"Kerberos TGS request");
            Assert.False((await _rule.EvaluateAsync(t)).Matched);
        }
    }
    [Fact] public async Task Tcp_And_Udp_Tgs_Are_Recognized_But_Invalid_Sessions_Are_Not()
    {
        for(int i=1;i<60;i++)Assert.False(await Seen(i,proto:"TCP"));
        Assert.True(await Seen(60,proto:"TCP"));
        var q=NetworkBatch076080Context.Event(61,"KERBEROS","TGS_REQ",88,protocol:"UDP");
        q.Record.TcpFlags=0x18;
        Assert.False((await _rule.EvaluateAsync(q)).Matched);
    }
    [Fact] public async Task Clients_And_Kdc_Targets_Do_Not_Pool_Requests()
    {
        for(int i=1;i<=30;i++){
            Assert.False(await Seen(i,src:"10.76.0.11"));
            Assert.False(await Seen(i+30,dst:"10.76.1.11"));
        }
        Assert.False(await Seen(62));
    }
    [Fact] public async Task Replayed_Record_And_Expired_Observations_Do_Not_Count()
    {
        var id=Guid.NewGuid();
        for(int i=1;i<=70;i++)Assert.False((await _rule.EvaluateAsync(NetworkBatch076080Context.Event(i,"KERBEROS","TGS_REQ",88,protocol:"UDP",id:id))).Matched);
        Assert.False(await Seen(240));
    }
    [Fact] public async Task Cancellation_And_Sensitive_ServiceNames_Are_Redacted()
    {
        using var c=new CancellationTokenSource();c.Cancel();
        await Assert.ThrowsAnyAsync<OperationCanceledException>(async()=>await _rule.EvaluateAsync(NetworkBatch076080Context.Event(1,"KERBEROS","TGS_REQ",88,protocol:"UDP"),c.Token));
        for(int i=1;i<60;i++)Assert.False(await Seen(i));
        var hit=await _rule.EvaluateAsync(NetworkBatch076080Context.Event(60,"KERBEROS","TGS_REQ",88,protocol:"UDP",info:"sname=private-service-80"));
        var e=Assert.Single(hit.Events);
        Assert.DoesNotContain("private-service-80",e.Description);
        Assert.DoesNotContain("private-service-80",e.Evidence);
    }
}
