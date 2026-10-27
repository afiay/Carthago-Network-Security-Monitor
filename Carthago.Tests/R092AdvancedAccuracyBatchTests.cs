// SPDX-License-Identifier: MIT
using System;
using System.Threading;
using System.Threading.Tasks;
using Carthago.Engine.Rules.Payloads;
using Xunit;
namespace Carthago.Tests;
public sealed class R092AdvancedAccuracyBatchTests
{
    private readonly R092_KnownMalwareHTTPURIPatternRule _rule=new();
    private async Task<bool> Hit(int t,string uri="/gate.php",string? info=null)
        =>(await _rule.EvaluateAsync(NetworkBatch091095Context.Http(t,uri,info:info))).Matched;
    [Fact] public async Task Exact_GateEndpoint_With_Query_Is_Recognized()
    {Assert.True(await Hit(1,"/gate.php?client=123"));}
    [Fact] public async Task Nested_C2Gate_Endpoint_Is_Recognized()
    {Assert.True(await Hit(1,"/api/c2/gate.php"));}
    [Fact] public async Task Common_AdminPanel_Bot_And_Cnc_Paths_Are_Not_Malware_Proof()
    {Assert.False(await Hit(1,"/panel"));Assert.False(await Hit(2,"/bot"));Assert.False(await Hit(3,"/cnc"));Assert.False(await Hit(4,"/api/gate.php.bak"));}
    [Fact] public async Task Info_And_Hostname_Alone_Do_Not_Supply_Endpoint_Evidence()
    {Assert.False(await Hit(1,"/status",info:"/gate.php"));var c=NetworkBatch091095Context.Http(2,"/status");c.Record.HttpHost="gate.php";Assert.False((await _rule.EvaluateAsync(c)).Matched);}
    [Fact] public async Task Missing_Or_Conflicting_Http_Evidence_Is_Rejected()
    {
        var c=NetworkBatch091095Context.Http(1,"/gate.php");c.Record.TcpFlags=2;
        Assert.False((await _rule.EvaluateAsync(c)).Matched);
        c=NetworkBatch091095Context.Http(2,"/gate.php");c.Record.HttpHost=null;
        Assert.False((await _rule.EvaluateAsync(c)).Matched);
        c=NetworkBatch091095Context.Http(3,"/gate.php");c.Record.DnsQname="suspicious.example";
        Assert.False((await _rule.EvaluateAsync(c)).Matched);
    }
    [Fact] public async Task Repeated_Record_Is_Not_Recounted_But_New_Request_Is()
    {var c=NetworkBatch091095Context.Http(1,"/gate.php");Assert.True((await _rule.EvaluateAsync(c)).Matched);Assert.False((await _rule.EvaluateAsync(c)).Matched);Assert.True(await Hit(2));}
    [Fact] public async Task Cancellation_And_Sensitive_Url_Parameters_Are_Not_Exposed()
    {
        using var cts=new CancellationTokenSource();cts.Cancel();
        await Assert.ThrowsAnyAsync<OperationCanceledException>(async()=>await _rule.EvaluateAsync(NetworkBatch091095Context.Http(1,"/gate.php"),cts.Token));
        var e=Assert.Single((await _rule.EvaluateAsync(NetworkBatch091095Context.Http(2,"/gate.php?token=private92"))).Events);
        Assert.DoesNotContain("private92",e.Description);Assert.DoesNotContain("private92",e.Evidence);
    }
}
