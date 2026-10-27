// SPDX-License-Identifier: MIT
using System;
using System.Threading;
using System.Threading.Tasks;
using Carthago.Engine.Rules.Payloads;
using Xunit;
namespace Carthago.Tests;
public sealed class R091AdvancedAccuracyBatchTests
{
    private readonly R091_NmapMasscanZgrabUserAgentRule _rule=new();
    private async Task<bool> Hit(int t,string? agent="Nmap/7.94",string uri="/",string? info=null)
        =>(await _rule.EvaluateAsync(NetworkBatch091095Context.Http(t,uri,agent,info))).Matched;
    [Fact] public async Task Scanner_Declared_Recognizable_Nmap_Agent_Matches()
    {Assert.True(await Hit(1));}
    [Fact] public async Task Masscan_And_Zgrab_Agents_Are_Recognized()
    {Assert.True(await Hit(1,"masscan/1.3"));Assert.True(await Hit(2,"Mozilla/5.0 (zgrab/0.1)"));}
    [Fact] public async Task Benign_Substrings_And_Ordinary_Browsers_Do_Not_Match()
    {Assert.False(await Hit(1,"custom-nmap-library/1"));Assert.False(await Hit(2,"Mozilla/5.0 (Windows NT 10.0)"));Assert.False(await Hit(3,"ExampleApp/1.0"));}
    [Fact] public async Task Scanner_Words_In_Uri_Or_Untrusted_Info_Are_NonEvidence()
    {Assert.False(await Hit(1,agent:"Mozilla/5.0",uri:"/docs?q=masscan",info:"nmap/7.94")); }
    [Fact] public async Task Contradictory_Method_Headers_And_Transport_Fail_Closed()
    {
        var c=NetworkBatch091095Context.Http(1,userAgent:"Nmap/7.94");c.Record.IsUdp=true;
        Assert.False((await _rule.EvaluateAsync(c)).Matched);
        c=NetworkBatch091095Context.Http(2,userAgent:"Nmap/7.94");c.Record.HttpMethod=null;
        Assert.False((await _rule.EvaluateAsync(c)).Matched);
        c=NetworkBatch091095Context.Http(3,userAgent:"Nmap/7.94",headers:"Host: other.example.test\r\n\r\n");
        Assert.False((await _rule.EvaluateAsync(c)).Matched);
    }
    [Fact] public async Task Duplicate_Record_Is_Ignored_But_Distinct_Request_Remains_Detectable()
    {
        var c=NetworkBatch091095Context.Http(1,userAgent:"Nmap/7.94");
        Assert.True((await _rule.EvaluateAsync(c)).Matched);
        Assert.False((await _rule.EvaluateAsync(c)).Matched);
        Assert.True(await Hit(2));
    }
    [Fact] public async Task Cancelled_Evaluation_And_Sensitive_Agent_Are_Not_Leaked()
    {
        using var cts=new CancellationTokenSource();cts.Cancel();
        await Assert.ThrowsAnyAsync<OperationCanceledException>(async()=>await _rule.EvaluateAsync(NetworkBatch091095Context.Http(1,userAgent:"Nmap/7.94"),cts.Token));
        var e=Assert.Single((await _rule.EvaluateAsync(NetworkBatch091095Context.Http(2,userAgent:"Nmap/7.94 bearer=private91"))).Events);
        Assert.DoesNotContain("private91",e.Description);Assert.DoesNotContain("private91",e.Evidence);
    }
}
