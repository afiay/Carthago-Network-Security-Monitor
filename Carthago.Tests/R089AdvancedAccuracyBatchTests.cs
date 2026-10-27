// SPDX-License-Identifier: MIT
using System;
using System.Threading;
using System.Threading.Tasks;
using Carthago.Engine.Rules.Payloads;
using Xunit;
namespace Carthago.Tests;
public sealed class R089AdvancedAccuracyBatchTests
{
    private readonly R089_CommandInjectionPatternRule _rule=new();
    private const string Exploit="/tools?host=example%3Bwhoami";
    private async Task<bool> Seen(int t,string uri=Exploit,string? info=null)
        =>(await _rule.EvaluateAsync(NetworkBatch081085Context.Http(t,uri,info:info))).Matched;
    [Fact] public async Task Encoded_Shell_Separator_With_Command_Matches()
    {Assert.True(await Seen(1));}
    [Fact] public async Task Double_Encoded_Pipe_With_Id_Command_Matches()
    {Assert.True(await Seen(1,uri:"/q?target=a%257Cid"));}
    [Fact] public async Task Authorized_Looking_Text_Without_Shell_Operator_Does_Not_Match()
    {
        Assert.False(await Seen(1,uri:"/help?q=whoami"));
        Assert.False(await Seen(2,uri:"/docs?q=powershell%20examples"));
        Assert.False(await Seen(3,uri:"/health?refresh=true"));
    }
    [Fact] public async Task Shell_Operator_Without_Command_And_Free_Text_Log_Are_Insufficient()
    {
        Assert.False(await Seen(1,uri:"/files?a=foo%26%26bar"));
        Assert.False(await Seen(2,uri:"/safe",info:";whoami; wget attack"));
    }
    [Fact] public async Task Contradictory_Http_Transport_Headers_And_Port_Are_NonEvidence()
    {
        var c=NetworkBatch081085Context.Http(1,Exploit);c.Record.TcpFlags=2;
        Assert.False((await _rule.EvaluateAsync(c)).Matched);
        c=NetworkBatch081085Context.Http(2,Exploit);c.Record.IsUdp=true;
        Assert.False((await _rule.EvaluateAsync(c)).Matched);
        c=NetworkBatch081085Context.Http(3,Exploit,headers:"Host: other.example.test\r\n\r\n");
        Assert.False((await _rule.EvaluateAsync(c)).Matched);
        c=NetworkBatch081085Context.Http(4,Exploit);c.Record.DestinationPort=null;
        Assert.False((await _rule.EvaluateAsync(c)).Matched);
    }
    [Fact] public async Task Duplicate_Record_Is_Stable_And_Different_Record_Can_Alert()
    {
        var c=NetworkBatch081085Context.Http(1,Exploit);
        Assert.True((await _rule.EvaluateAsync(c)).Matched);
        Assert.False((await _rule.EvaluateAsync(c)).Matched);
        Assert.True(await Seen(2));
    }
    [Fact] public async Task Cancellation_Long_And_Secret_Inputs_Are_FailClosed_Or_Redacted()
    {
        using var cts=new CancellationTokenSource();cts.Cancel();
        await Assert.ThrowsAnyAsync<OperationCanceledException>(async()=>await _rule.EvaluateAsync(NetworkBatch081085Context.Http(1,Exploit),cts.Token));
        Assert.False(await Seen(2,uri:"/x?text="+new string('a',4200)+Exploit));
        var e=Assert.Single((await _rule.EvaluateAsync(NetworkBatch081085Context.Http(3,Exploit+"&password=secret89"))).Events);
        Assert.DoesNotContain("secret89",e.Description);Assert.DoesNotContain("secret89",e.Evidence);
    }
}
