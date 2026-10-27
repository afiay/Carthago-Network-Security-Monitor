// SPDX-License-Identifier: MIT
using System;
using System.Threading;
using System.Threading.Tasks;
using Carthago.Engine.Rules.LateralMovement;
using Xunit;
namespace Carthago.Tests;
public sealed class R076AdvancedAccuracyBatchTests
{
    private readonly R076_SMBAdminShareAccessPatternRule _rule = new();
    private async Task<bool> Seen(int s, string? app="SMB", string? svc="ADMIN_SHARE",
        string dst="10.76.1.10", string src="10.76.0.10", int port=445, string? info=null)
        => (await _rule.EvaluateAsync(NetworkBatch076080Context.Event(s, app, svc, port, src, dst, info:info))).Matched;

    [Fact] public async Task Two_Independent_Typed_AdminShare_Requests_Are_Corroborated()
    {
        Assert.False(await Seen(1));
        Assert.True(await Seen(2));
        Assert.False(await Seen(3));
    }
    [Fact] public async Task Benign_FileShare_Ipc_And_Unstructured_Keywords_Do_Not_Match()
    {
        for(int i=1;i<=8;i++) {
            Assert.False(await Seen(i,svc:"FILE_SHARE",info:"ADMIN$"));
            Assert.False(await Seen(i+10,svc:"IPC_SHARE",info:"tree connect c$"));
            Assert.False(await Seen(i+20,svc:null,info:"ADMIN$"));
        }
    }
    [Fact] public async Task Invalid_Transport_And_Public_Target_Do_Not_Prime_Classification()
    {
        Assert.False(await Seen(1,port:139));
        var udp=NetworkBatch076080Context.Event(2,protocol:"UDP");
        Assert.False((await _rule.EvaluateAsync(udp)).Matched);
        var rst=NetworkBatch076080Context.Event(3);rst.Record.TcpFlags=0x14;
        Assert.False((await _rule.EvaluateAsync(rst)).Matched);
        Assert.False(await Seen(4,dst:"8.8.8.8"));
        Assert.False(await Seen(5));
    }
    [Fact] public async Task Source_And_Target_Are_Isolated()
    {
        Assert.False(await Seen(1,src:"10.76.0.11"));
        Assert.False(await Seen(2,dst:"10.76.1.11"));
        Assert.False(await Seen(3));
        Assert.True(await Seen(4));
    }
    [Fact] public async Task Duplicate_Id_And_OutOfOrder_Events_Do_Not_Increment()
    {
        var id=Guid.NewGuid();
        Assert.False((await _rule.EvaluateAsync(NetworkBatch076080Context.Event(1,id:id))).Matched);
        Assert.False((await _rule.EvaluateAsync(NetworkBatch076080Context.Event(2,id:id))).Matched);
        Assert.False((await _rule.EvaluateAsync(NetworkBatch076080Context.Event(0))).Matched);
        Assert.True(await Seen(3));
    }
    [Fact] public async Task Expired_Observations_Do_Not_Create_False_Corroboration()
    {
        Assert.False(await Seen(1));
        Assert.False(await Seen(200));
        Assert.True(await Seen(201));
    }
    [Fact] public async Task Cancellation_And_Alert_Redaction()
    {
        using var cancel=new CancellationTokenSource();cancel.Cancel();
        await Assert.ThrowsAnyAsync<OperationCanceledException>(async()=>await _rule.EvaluateAsync(NetworkBatch076080Context.Event(1),cancel.Token));
        Assert.False(await Seen(2));
        var e=Assert.Single((await _rule.EvaluateAsync(NetworkBatch076080Context.Event(3,info:"credential=secret76"))).Events);
        Assert.DoesNotContain("secret76",e.Description);
        Assert.DoesNotContain("secret76",e.Evidence);
    }
}
