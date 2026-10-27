// SPDX-License-Identifier: MIT
using System;
using System.Threading;
using System.Threading.Tasks;
using Carthago.Engine.Rules.Payloads;
using Xunit;
namespace Carthago.Tests;

public sealed class R085AdvancedAccuracyBatchTests
{
    private readonly R085_SQLInjectionPatternRule _rule=new();
    private async Task<bool> Seen(int sec,string uri="/",string? headers=null,
        string? userAgent=null,string? info=null)
        =>(await _rule.EvaluateAsync(NetworkBatch081085Context.Http(sec,uri,headers,userAgent,info))).Matched;

    [Fact] public async Task Quoted_Boolean_Tautology_With_Comment_Is_Detected()
    {
        Assert.True(await Seen(1,uri:"/?id=1'+OR+1=1--"));
    }
    [Fact] public async Task PercentEncoded_UnionSelect_Extraction_Pattern_Is_Detected()
    {
        Assert.True(await Seen(1,uri:"/?id=1%27%20UNION%20SELECT%20password%20FROM%20users--"));
    }
    [Fact] public async Task TimeDelay_Probe_Is_Detected_Without_Execution_Claim()
    {
        Assert.True(await Seen(1,uri:"/?id=1';WAITFOR DELAY '00:00:05'--"));
    }
    [Fact] public async Task Ordinary_SQL_Words_Benign_Equality_And_Info_Only_Are_Ignored()
    {
        Assert.False(await Seen(1,uri:"/docs?topic=select+union+from+sql"));
        Assert.False(await Seen(2,uri:"/?filter=1=1"));
        Assert.False(await Seen(3,info:"' OR 1=1--"));
        Assert.False(await Seen(4,uri:"/?q=union+select+example+from+manual"));
    }
    [Fact] public async Task Wrong_Transport_Missing_Method_And_Host_Conflict_Are_Rejected()
    {
        var r=NetworkBatch081085Context.Http(1,uri:"/?id=1'+OR+1=1--");
        r.Record.Protocol="UDP";r.Record.IsTcp=false;r.Record.IsUdp=true;
        Assert.False((await _rule.EvaluateAsync(r)).Matched);
        r=NetworkBatch081085Context.Http(2,uri:"/?id=1'+OR+1=1--");
        r.Record.HttpMethod=null;Assert.False((await _rule.EvaluateAsync(r)).Matched);
        r=NetworkBatch081085Context.Http(3,uri:"/?id=1'+OR+1=1--",
            headers:"Host: another.example.test\r\n\r\n");
        Assert.False((await _rule.EvaluateAsync(r)).Matched);
        r=NetworkBatch081085Context.Http(4,uri:"/?id=1'+OR+1=1--",
            headers:"Host: app.example.test\r\nHost: app.example.test\r\n\r\n");
        Assert.False((await _rule.EvaluateAsync(r)).Matched);
    }
    [Fact] public async Task Duplicate_Record_Is_Not_Replayed_But_New_Request_Is_Recognized()
    {
        var id=Guid.NewGuid();
        var r=NetworkBatch081085Context.Http(1,uri:"/?id=1'+OR+1=1--",id:id);
        Assert.True((await _rule.EvaluateAsync(r)).Matched);
        Assert.False((await _rule.EvaluateAsync(r)).Matched);
        Assert.True(await Seen(2,uri:"/?id=1'+OR+1=1--"));
    }
    [Fact] public async Task Cancellation_And_Sensitive_Query_Are_Redacted()
    {
        using var cts=new CancellationTokenSource();cts.Cancel();
        await Assert.ThrowsAnyAsync<OperationCanceledException>(async()=>
            await _rule.EvaluateAsync(NetworkBatch081085Context.Http(1),cts.Token));
        var r=NetworkBatch081085Context.Http(2,uri:"/?token=secret-85&id=1'+OR+1=1--");
        var e=Assert.Single((await _rule.EvaluateAsync(r)).Events);
        Assert.DoesNotContain("secret-85",e.Description);
        Assert.DoesNotContain("secret-85",e.Evidence);
        Assert.DoesNotContain("secret-85",e.Summary);
    }
}
