// SPDX-License-Identifier: MIT
using System;
using System.Threading;
using System.Threading.Tasks;
using Carthago.Engine.Rules.LateralMovement;
using Xunit;
namespace Carthago.Tests;

public sealed class R083AdvancedAccuracyBatchTests
{
    private readonly R083_LLMNRNBNSPoisoningAttemptRule _rule=new();
    private async Task<bool> Seen(int sec,string protocol="LLMNR",string? service="CONFLICTING_RESPONSE",
        string src="10.83.0.10",string dst="10.83.0.20",string? info=null)
        =>(await _rule.EvaluateAsync(NetworkBatch081085Context.NameService(sec,protocol,service,src,dst,info:info))).Matched;

    [Fact] public async Task Two_Parser_Corroborated_Llmnr_Conflicts_Trigger()
    {Assert.False(await Seen(1));Assert.True(await Seen(2));Assert.False(await Seen(3));}
    [Fact] public async Task Nbns_Broadcast_Conflict_Is_Recognized()
    {Assert.False(await Seen(1,protocol:"NBNS",dst:"255.255.255.255"));Assert.True(await Seen(2,protocol:"NBNS",dst:"255.255.255.255"));}
    [Fact] public async Task Ordinary_Responses_And_Poison_Prose_Are_Not_Evidence()
    {
        for(var i=1;i<=10;i++)
        {
            Assert.False(await Seen(i,service:"RESPONSE",info:"poison"));
            Assert.False(await Seen(i+20,service:null,info:"LLMNR spoof response"));
        }
    }
    [Fact] public async Task Queries_Incomplete_Answers_And_Port_Spoofs_Are_Rejected()
    {
        var q=NetworkBatch081085Context.NameService(1);q.Record.DnsIsResponse=false;
        Assert.False((await _rule.EvaluateAsync(q)).Matched);
        var empty=NetworkBatch081085Context.NameService(2);empty.Record.DnsAnswers=null;
        Assert.False((await _rule.EvaluateAsync(empty)).Matched);
        var wrong=NetworkBatch081085Context.NameService(3);wrong.Record.SourcePort=9999;
        Assert.False((await _rule.EvaluateAsync(wrong)).Matched);
        Assert.False(await Seen(4));
    }
    [Fact] public async Task Source_Destination_And_NameService_Are_Isolated()
    {
        Assert.False(await Seen(1,src:"10.83.0.11"));
        Assert.False(await Seen(2,dst:"10.83.0.21"));
        Assert.False(await Seen(3,protocol:"NBNS"));
        Assert.False(await Seen(4));
        Assert.True(await Seen(5));
    }
    [Fact] public async Task Replay_Stale_Window_And_Contradictory_Transport_Are_Rejected()
    {
        var id=Guid.NewGuid();
        Assert.False((await _rule.EvaluateAsync(NetworkBatch081085Context.NameService(1,id:id))).Matched);
        Assert.False((await _rule.EvaluateAsync(NetworkBatch081085Context.NameService(2,id:id))).Matched);
        var tcp=NetworkBatch081085Context.NameService(3);tcp.Record.IsTcp=true;
        Assert.False((await _rule.EvaluateAsync(tcp)).Matched);
        Assert.False(await Seen(200));
        Assert.True(await Seen(201));
    }
    [Fact] public async Task Cancellation_And_Redacted_Dns_Answers()
    {
        using var cts=new CancellationTokenSource();cts.Cancel();
        await Assert.ThrowsAnyAsync<OperationCanceledException>(async()=>
            await _rule.EvaluateAsync(NetworkBatch081085Context.NameService(1),cts.Token));
        Assert.False(await Seen(1));
        var hit=NetworkBatch081085Context.NameService(2,info:"secret-83");
        hit.Record.DnsAnswers="sensitive-dns-answer-83";
        var e=Assert.Single((await _rule.EvaluateAsync(hit)).Events);
        Assert.DoesNotContain("secret-83",e.Description);
        Assert.DoesNotContain("sensitive-dns-answer-83",e.Evidence);
    }
}
