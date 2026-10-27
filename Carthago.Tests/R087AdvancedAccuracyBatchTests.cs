// SPDX-License-Identifier: MIT
using System;
using System.Threading;
using System.Threading.Tasks;
using Carthago.Engine.Rules.Payloads;
using Xunit;
namespace Carthago.Tests;
public sealed class R087AdvancedAccuracyBatchTests
{
    private readonly R087_WebshellUploadPatternRule _rule=new();
    private const string Form="Host: app.example.test\r\nContent-Type: multipart/form-data; boundary=abc123\r\n\r\n";
    private static Carthago.Engine.Rules.RuleEvaluationContext Upload(int t,string? service="SCRIPT_UPLOAD_OBSERVED",
        string? headers=Form,string method="POST",string? info=null)
    {
        var c=NetworkBatch081085Context.Http(t,"/upload",headers:headers,info:info);
        c.Record.HttpMethod=method;c.Record.ApplicationProtocol="HTTP";
        c.Record.ApplicationService=service;return c;
    }
    private async Task<bool> Seen(int t,string? svc="SCRIPT_UPLOAD_OBSERVED",string? headers=Form,string method="POST")
        =>(await _rule.EvaluateAsync(Upload(t,svc,headers,method))).Matched;
    [Fact] public async Task Classified_Multipart_Script_Upload_Matches()
    {Assert.True(await Seen(1));}
    [Fact] public async Task Put_And_Patch_Classified_Forms_Match()
    {Assert.True(await Seen(1,method:"PUT"));Assert.True(await Seen(2,method:"PATCH"));}
    [Fact] public async Task Ordinary_Images_And_Backup_Forms_Do_Not_Match()
    {
        for(int i=1;i<=6;i++)Assert.False(await Seen(i,svc:"ORDINARY_MULTIPART"));
    }
    [Fact] public async Task Keyword_In_Raw_Info_Is_Not_Parser_Evidence()
    {
        var c=Upload(1,service:null,info:"webshell.php filename=cmd.php system(");
        Assert.False((await _rule.EvaluateAsync(c)).Matched);
    }
    [Fact] public async Task Incomplete_Headers_ContentType_And_Transport_Are_Rejected()
    {
        Assert.False(await Seen(1,headers:null));
        Assert.False(await Seen(2,headers:"Host: app.example.test\r\nContent-Type: application/json\r\n\r\n"));
        Assert.False(await Seen(3,headers:"Host: app.example.test\r\nContent-Type: multipart/form-data; boundary=abc123\r\n"));
        var c=Upload(4);c.Record.IsUdp=true;Assert.False((await _rule.EvaluateAsync(c)).Matched);
    }
    [Fact] public async Task Record_Id_Replay_Is_Deduplicated_But_New_Correlated_Record_Can_Match()
    {
        var id=Guid.NewGuid();var c=Upload(1);c.Record.Id=id;
        Assert.True((await _rule.EvaluateAsync(c)).Matched);
        Assert.False((await _rule.EvaluateAsync(c)).Matched);
        Assert.True(await Seen(2));
    }
    [Fact] public async Task Cancellation_And_Raw_Multipart_Secrets_Do_Not_Leak()
    {
        using var cts=new CancellationTokenSource();cts.Cancel();
        await Assert.ThrowsAnyAsync<OperationCanceledException>(async()=>await _rule.EvaluateAsync(Upload(1),cts.Token));
        var c=Upload(2,info:"secret87");
        var e=Assert.Single((await _rule.EvaluateAsync(c)).Events);
        Assert.DoesNotContain("secret87",e.Description);Assert.DoesNotContain("secret87",e.Evidence);
    }
}
