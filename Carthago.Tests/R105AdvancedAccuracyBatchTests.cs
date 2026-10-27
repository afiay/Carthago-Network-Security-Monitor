// SPDX-License-Identifier: MIT
using System;
using System.Threading;
using System.Threading.Tasks;
using Carthago.Engine.Rules.CloudSaas;
using Xunit;
namespace Carthago.Tests;
public sealed class R105AdvancedAccuracyBatchTests
{
    private readonly R105_LargeUploadToPersonalCloudProviderRule _rule=new();
    private async Task<bool> Hit(int t,string source,int bytes=3200000,string host="mega.nz",string method="POST",string uri="/upload",string process="curl.exe",string? info=null)
        =>(await _rule.EvaluateAsync(NetworkBatch101105Context.Cloud(t,source,host:host,method:method,bytes:bytes,uri:uri,process:process,info:info))).Matched;
    [Fact] public async Task Large_Personal_Cloud_Upload_Has_Concrete_Volume_Evidence()
    {
        var e=Assert.Single((await _rule.EvaluateAsync(NetworkBatch101105Context.Cloud(1,NetworkBatch101105Context.Source(),host:"mega.nz",bytes:3200000))).Events);
        Assert.Equal("R105",e.RuleId);
        Assert.Contains(e.StructuredEvidence!.Items,x=>x.Key=="cloud.totalUploadBytes");
    }
    [Fact] public async Task Three_Distinct_Medium_Uploads_Cross_The_Window_Threshold()
    {
        var src=NetworkBatch101105Context.Source();
        Assert.False(await Hit(1,src,bytes:2000000));
        Assert.False(await Hit(30,src,bytes:2000000));
        Assert.True(await Hit(60,src,bytes:2000000));
    }
    [Fact] public async Task Duplicate_Packet_Delivery_Cannot_Inflate_The_Byte_Window()
    {
        var src=NetworkBatch101105Context.Source();
        var c=NetworkBatch101105Context.Cloud(1,src,host:"mega.nz",bytes:2000000);
        for(var i=0;i<8;i++)Assert.False((await _rule.EvaluateAsync(c)).Matched);
        Assert.False(await Hit(30,src,bytes:2000000));
    }
    [Fact] public async Task Download_And_Small_Browser_Cloud_Use_Do_Not_Trigger()
    {
        var src=NetworkBatch101105Context.Source();
        Assert.False(await Hit(1,src,bytes:10000000,method:"GET"));
        Assert.False(await Hit(2,src,bytes:400000,host:"docs.google.com",process:"chrome.exe",uri:"/document/d/1/edit"));
    }
    [Fact] public async Task Packet_Info_Claim_Without_Real_Upload_Method_Is_Not_Evidence()
    {
        var src=NetworkBatch101105Context.Source();
        Assert.False(await Hit(1,src,bytes:10000000,method:"GET",uri:"/home",info:"large POST upload"));
    }
    [Fact] public async Task Conflicting_Sni_Host_And_Invalid_Network_Direction_Are_Rejected()
    {
        var c=NetworkBatch101105Context.Cloud(1,NetworkBatch101105Context.Source(),host:"mega.nz",bytes:3200000);
        c.Record.Sni="unrelated.example";
        Assert.False((await _rule.EvaluateAsync(c)).Matched);
        c=NetworkBatch101105Context.Cloud(2,NetworkBatch101105Context.Source(),host:"mega.nz",bytes:3200000);
        c.Record.IsTcp=false;
        Assert.False((await _rule.EvaluateAsync(c)).Matched);
        c=NetworkBatch101105Context.Cloud(3,"198.51.100.22",host:"mega.nz",bytes:3200000);
        Assert.False((await _rule.EvaluateAsync(c)).Matched);
    }
    [Fact] public async Task Sensitive_Uri_Parameters_Are_Omitted_And_Cancellation_Is_Enforced()
    {
        using var cts=new CancellationTokenSource();cts.Cancel();
        await Assert.ThrowsAnyAsync<OperationCanceledException>(async()=>await _rule.EvaluateAsync(NetworkBatch101105Context.Cloud(1,NetworkBatch101105Context.Source(),host:"mega.nz",bytes:3200000),cts.Token));
        var e=Assert.Single((await _rule.EvaluateAsync(NetworkBatch101105Context.Cloud(2,NetworkBatch101105Context.Source(),host:"mega.nz",bytes:3200000,uri:"/upload?token=private105"))).Events);
        Assert.DoesNotContain("private105",e.Description);
        Assert.DoesNotContain("private105",e.Evidence);
        Assert.DoesNotContain(e.StructuredEvidence!.Items,x=>x.Key=="http.uri");
    }
}
