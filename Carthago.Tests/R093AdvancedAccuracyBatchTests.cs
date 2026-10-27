// SPDX-License-Identifier: MIT
using System;
using System.Threading;
using System.Threading.Tasks;
using Carthago.Engine.Rules.Payloads;
using Xunit;
namespace Carthago.Tests;
public sealed class R093AdvancedAccuracyBatchTests
{
    private readonly R093_SuspiciousPowerShellDownloadCradleOverHTTPRule _rule=new();
    private const string Cradle="/x?cmd=powershell%20iex%20DownloadString(";
    private async Task<bool> Hit(int t,string uri=Cradle,string? info=null)
        =>(await _rule.EvaluateAsync(NetworkBatch091095Context.Http(t,uri,info:info))).Matched;
    [Fact] public async Task Structured_DownloadAndInvoke_PowerShell_Command_Matches()
    {Assert.True(await Hit(1));}
    [Fact] public async Task Encoded_And_Pwsh_InvokeExpression_Variant_Matches()
    {Assert.True(await Hit(1,"/run?x=pwsh%20Invoke-Expression%20Invoke-WebRequest"));}
    [Fact] public async Task Ordinary_PowerShell_And_Download_Without_Invocation_Do_Not_Match()
    {Assert.False(await Hit(1,"/docs?x=powershell"));Assert.False(await Hit(2,"/docs?x=powershell%20DownloadString("));Assert.False(await Hit(3,"/docs?x=iex"));}
    [Fact] public async Task Textual_Indicators_In_Packet_Info_Alone_Never_Match()
    {Assert.False(await Hit(1,"/health",info:"powershell iex DownloadString("));}
    [Fact] public async Task Invalid_Http_Metadata_Cannot_Produce_Match()
    {
        var c=NetworkBatch091095Context.Http(1,Cradle);c.Record.HttpMethod=null;
        Assert.False((await _rule.EvaluateAsync(c)).Matched);
        c=NetworkBatch091095Context.Http(2,Cradle);c.Record.IsQuic=true;
        Assert.False((await _rule.EvaluateAsync(c)).Matched);
        c=NetworkBatch091095Context.Http(3,Cradle);c.Record.HttpRequestHeaders="Host: wrong.example.test\r\n\r\n";
        Assert.False((await _rule.EvaluateAsync(c)).Matched);
    }
    [Fact] public async Task Same_Id_Is_Deduplicated_But_Another_Observation_Can_Match()
    {var c=NetworkBatch091095Context.Http(1,Cradle);Assert.True((await _rule.EvaluateAsync(c)).Matched);Assert.False((await _rule.EvaluateAsync(c)).Matched);Assert.True(await Hit(2));}
    [Fact] public async Task Cancellation_Long_Input_And_Raw_Secrets_Are_Protected()
    {
        using var cts=new CancellationTokenSource();cts.Cancel();
        await Assert.ThrowsAnyAsync<OperationCanceledException>(async()=>await _rule.EvaluateAsync(NetworkBatch091095Context.Http(1,Cradle),cts.Token));
        Assert.False(await Hit(2,"/q?payload="+new string('x',4200)+Cradle));
        var e=Assert.Single((await _rule.EvaluateAsync(NetworkBatch091095Context.Http(3,Cradle+"&secret=private93"))).Events);
        Assert.DoesNotContain("private93",e.Description);Assert.DoesNotContain("private93",e.Evidence);
    }
}
