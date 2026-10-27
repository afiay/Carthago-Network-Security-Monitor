// SPDX-License-Identifier: MIT
using System;
using System.Threading;
using System.Threading.Tasks;
using Carthago.Engine.Rules.Payloads;
using Xunit;
namespace Carthago.Tests;
public sealed class R086AdvancedAccuracyBatchTests
{
    private readonly R086_PathTraversalLFIPatternRule _rule=new();
    private const string Exploit="/fetch?file=../../etc/passwd";
    private async Task<bool> Seen(int t,string uri=Exploit,string? info=null)
        =>(await _rule.EvaluateAsync(NetworkBatch081085Context.Http(t,uri,info:info))).Matched;
    [Fact] public async Task Observed_Http_Traversal_To_Sensitive_File_Matches()
    {Assert.True(await Seen(1));}
    [Fact] public async Task Double_Encoded_DotDot_And_Windows_Target_Are_Recognized()
    {
        Assert.True(await Seen(1,uri:"/fetch?file=%252e%252e%252fetc%252fpasswd"));
        Assert.True(await Seen(2,uri:"/read?name=..%5cwindows%5cwin.ini"));
    }
    [Fact] public async Task Benign_Relative_Prose_And_Sensitive_Filename_Alone_Do_Not_Trigger()
    {
        Assert.False(await Seen(1,uri:"/docs?next=../overview"));
        Assert.False(await Seen(2,uri:"/docs?topic=/etc/passwd"));
        Assert.False(await Seen(3,uri:"/docs?readme=how-to-handle-paths"));
    }
    [Fact] public async Task Unparsed_Info_Is_Not_Payload_Evidence()
    {Assert.False(await Seen(1,uri:"/index",info:"../../etc/passwd")); }
    [Fact] public async Task Missing_And_Contradictory_Http_Fields_Fail_Closed()
    {
        var p=NetworkBatch081085Context.Http(1,Exploit);p.Record.HttpHost=null;
        Assert.False((await _rule.EvaluateAsync(p)).Matched);
        p=NetworkBatch081085Context.Http(2,Exploit);p.Record.IsUdp=true;
        Assert.False((await _rule.EvaluateAsync(p)).Matched);
        p=NetworkBatch081085Context.Http(3,Exploit);p.Record.TcpFlags=2;
        Assert.False((await _rule.EvaluateAsync(p)).Matched);
        p=NetworkBatch081085Context.Http(4,Exploit);p.Record.HttpRequestHeaders="Host: other.example.test\r\n\r\n";
        Assert.False((await _rule.EvaluateAsync(p)).Matched);
    }
    [Fact] public async Task Replayed_Identity_Does_Not_Fabricate_Second_Event()
    {
        var id=Guid.NewGuid();var a=NetworkBatch081085Context.Http(1,Exploit,id:id);
        Assert.True((await _rule.EvaluateAsync(a)).Matched);
        Assert.False((await _rule.EvaluateAsync(a)).Matched);
        Assert.True(await Seen(2));
    }
    [Fact] public async Task Cancellation_Long_Input_And_Secret_Redaction()
    {
        using var cts=new CancellationTokenSource();cts.Cancel();
        await Assert.ThrowsAnyAsync<OperationCanceledException>(async()=>await _rule.EvaluateAsync(NetworkBatch081085Context.Http(1,Exploit),cts.Token));
        Assert.False(await Seen(2,uri:"/x?y="+new string('a',4200)+Exploit));
        var hit=await _rule.EvaluateAsync(NetworkBatch081085Context.Http(3,Exploit+"&token=private86"));
        var ev=Assert.Single(hit.Events);
        Assert.DoesNotContain("private86",ev.Description);Assert.DoesNotContain("private86",ev.Evidence);
    }
}
