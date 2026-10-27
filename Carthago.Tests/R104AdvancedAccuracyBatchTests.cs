// SPDX-License-Identifier: MIT
using System;
using System.IO;
using System.Threading;
using System.Threading.Tasks;
using Carthago.Engine.Rules.CloudSaas;
using Carthago.Services.Baseline;
using Xunit;
namespace Carthago.Tests;
public sealed class R104AdvancedAccuracyBatchTests
{
    private readonly R104_FirstTimeCloudStorageUploadRule _rule=new();
    private static async Task Scoped(Func<Task> action)
    {
        var dir=Path.Combine(Path.GetTempPath(),"r104-batch-"+Guid.NewGuid().ToString("N"));
        try{using(BaselineStore.UseScoped(new BaselineStore(new BaselineOptions{DirectoryPath=dir})))await action();}
        finally{if(Directory.Exists(dir))Directory.Delete(dir,true);}
    }
    [Fact] public async Task First_Observed_Provider_Upload_Emits_Baseline_Evidence()
    {
        await Scoped(async()=>{
            var c=NetworkBatch101105Context.Cloud(1,NetworkBatch101105Context.Source());
            var e=Assert.Single((await _rule.EvaluateAsync(c)).Events);
            Assert.Equal("R104",e.RuleId);
            Assert.Contains(e.StructuredEvidence!.Items,x=>x.Key=="baseline.reason"&&x.Value=="first seen");
        });
    }
    [Fact] public async Task Same_Source_Process_And_Provider_Do_Not_Become_First_Seen_Again()
    {
        await Scoped(async()=>{
            var src=NetworkBatch101105Context.Source();
            Assert.True((await _rule.EvaluateAsync(NetworkBatch101105Context.Cloud(1,src))).Matched);
            Assert.False((await _rule.EvaluateAsync(NetworkBatch101105Context.Cloud(2,src))).Matched);
        });
    }
    [Fact] public async Task Download_And_Small_Ordinary_Browser_Browsing_Are_NonEvidence()
    {
        var src=NetworkBatch101105Context.Source();
        Assert.False((await _rule.EvaluateAsync(NetworkBatch101105Context.Cloud(1,src,method:"GET",bytes:900000))).Matched);
        Assert.False((await _rule.EvaluateAsync(NetworkBatch101105Context.Cloud(2,src,bytes:50000,uri:"/home",process:"chrome.exe"))).Matched);
    }
    [Fact] public async Task Info_Only_Upload_Claim_Does_Not_Substitute_Parsed_Metadata()
    {
        var c=NetworkBatch101105Context.Cloud(1,NetworkBatch101105Context.Source(),bytes:50000,uri:"/home",process:"chrome.exe",info:"uploaded secret file");
        Assert.False((await _rule.EvaluateAsync(c)).Matched);
    }
    [Fact] public async Task Host_Sni_Mismatch_And_Contradictory_Transport_Are_Rejected()
    {
        var c=NetworkBatch101105Context.Cloud(1,NetworkBatch101105Context.Source());c.Record.Sni="evil.example";
        Assert.False((await _rule.EvaluateAsync(c)).Matched);
        c=NetworkBatch101105Context.Cloud(2,NetworkBatch101105Context.Source());c.Record.IsUdp=true;
        Assert.False((await _rule.EvaluateAsync(c)).Matched);
        c=NetworkBatch101105Context.Cloud(3,NetworkBatch101105Context.Source());c.Record.HttpRequestHeaders="Host: other.example\r\n";
        Assert.False((await _rule.EvaluateAsync(c)).Matched);
    }
    [Fact] public async Task Failed_Baseline_Persistence_Does_Not_Manufacture_FirstSeen()
    {
        var file=Path.GetTempFileName();
        try{
            using(BaselineStore.UseScoped(new BaselineStore(new BaselineOptions{DirectoryPath=file})))
            {
                var c=NetworkBatch101105Context.Cloud(1,NetworkBatch101105Context.Source());
                Assert.False((await _rule.EvaluateAsync(c)).Matched);
            }
        }finally{File.Delete(file);}
    }
    [Fact] public async Task Sensitive_Query_Is_Omitted_From_Event_And_Cancellation_Is_Honored()
    {
        using var cts=new CancellationTokenSource();cts.Cancel();
        await Assert.ThrowsAnyAsync<OperationCanceledException>(async()=>await _rule.EvaluateAsync(NetworkBatch101105Context.Cloud(1,NetworkBatch101105Context.Source()),cts.Token));
        await Scoped(async()=>{
            var c=NetworkBatch101105Context.Cloud(2,NetworkBatch101105Context.Source(),uri:"/upload?token=private104");
            var e=Assert.Single((await _rule.EvaluateAsync(c)).Events);
            Assert.DoesNotContain("private104",e.Description);
            Assert.DoesNotContain("private104",e.Evidence);
            Assert.DoesNotContain(e.StructuredEvidence!.Items,x=>x.Key=="http.uri");
        });
    }
}
