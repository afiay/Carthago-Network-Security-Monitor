// SPDX-License-Identifier: MIT
using System;
using System.Threading;
using System.Threading.Tasks;
using Carthago.Engine.Rules.LateralMovement;
using Xunit;
namespace Carthago.Tests;

public sealed class R081AdvancedAccuracyBatchTests
{
    private readonly R081_ASREPRoastingHeuristicRule _rule = new();
    private async Task<bool> Seen(int sec, string? service="AS_REP_NO_PREAUTH",
        string kdc="10.81.1.10", string client="10.81.0.10", string protocol="UDP",
        string? info=null)
        => (await _rule.EvaluateAsync(NetworkBatch081085Context.AsRep(sec,service,kdc,client,protocol,info:info))).Matched;

    [Fact] public async Task Three_Corroborated_PreAuthless_AsRep_Replies_Trigger_Once()
    {
        Assert.False(await Seen(1));
        Assert.False(await Seen(2));
        Assert.True(await Seen(3));
        Assert.False(await Seen(4));
    }
    [Fact] public async Task Normal_AsRep_Tgs_And_Textual_Roasting_Claims_Are_Benign()
    {
        for (var i=1;i<=8;i++)
        {
            Assert.False(await Seen(i,service:"AS_REP"));
            Assert.False(await Seen(i+20,service:"TGS_REP",info:"preauth not required"));
            Assert.False(await Seen(i+40,service:null,info:"AS-REP roasting etype 23"));
        }
    }
    [Fact] public async Task Wrong_Direction_Port_And_Contradictory_Transport_Are_Rejected()
    {
        var c=NetworkBatch081085Context.AsRep(1); c.Record.SourcePort=52000; c.Record.DestinationPort=88;
        Assert.False((await _rule.EvaluateAsync(c)).Matched);
        c=NetworkBatch081085Context.AsRep(2);c.Record.IsTcp=true;
        Assert.False((await _rule.EvaluateAsync(c)).Matched);
        c=NetworkBatch081085Context.AsRep(3);c.Record.TcpFlags=0x18;
        Assert.False((await _rule.EvaluateAsync(c)).Matched);
        Assert.False(await Seen(4));
    }
    [Fact] public async Task Client_And_Kdc_Are_Independent()
    {
        Assert.False(await Seen(1,client:"10.81.0.11"));
        Assert.False(await Seen(2,kdc:"10.81.1.11"));
        Assert.False(await Seen(3));
        Assert.False(await Seen(4));
        Assert.True(await Seen(5));
    }
    [Fact] public async Task Replayed_Identity_And_Reversed_Time_Cannot_Fabricate_Burst()
    {
        var id=Guid.NewGuid();
        Assert.False((await _rule.EvaluateAsync(NetworkBatch081085Context.AsRep(1,id:id))).Matched);
        Assert.False((await _rule.EvaluateAsync(NetworkBatch081085Context.AsRep(2,id:id))).Matched);
        Assert.False((await _rule.EvaluateAsync(NetworkBatch081085Context.AsRep(0))).Matched);
        Assert.False(await Seen(3));
        Assert.True(await Seen(4));
    }
    [Fact] public async Task Expired_Window_Does_Not_Count_Old_Replies()
    {
        Assert.False(await Seen(1));
        Assert.False(await Seen(200));
        Assert.False(await Seen(201));
        Assert.True(await Seen(202));
    }
    [Fact] public async Task Cancellation_Future_Time_And_Privacy_Are_Enforced()
    {
        using var cts=new CancellationTokenSource();cts.Cancel();
        await Assert.ThrowsAnyAsync<OperationCanceledException>(async () =>
            await _rule.EvaluateAsync(NetworkBatch081085Context.AsRep(1),cts.Token));
        var future=NetworkBatch081085Context.AsRep(2000);
        Assert.False((await _rule.EvaluateAsync(future)).Matched);
        Assert.False(await Seen(1));Assert.False(await Seen(2));
        var e=Assert.Single((await _rule.EvaluateAsync(
            NetworkBatch081085Context.AsRep(3,info:"account=private-user-81"))).Events);
        Assert.DoesNotContain("private-user-81",e.Description);
        Assert.DoesNotContain("private-user-81",e.Evidence);
    }
}
