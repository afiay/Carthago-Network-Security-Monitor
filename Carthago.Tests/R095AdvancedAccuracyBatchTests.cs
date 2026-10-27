// SPDX-License-Identifier: MIT
using System;
using System.IO;
using System.Threading;
using System.Threading.Tasks;
using Carthago.Engine.Rules.Dns;
using Carthago.Services.Baseline;
using Xunit;
namespace Carthago.Tests;
public sealed class R095AdvancedAccuracyBatchTests
{
    private readonly R095_NewlyObservedDomainWithHighEntropyRule _rule=new();
    private static string Novel()=> "zx9q8v7m6n5p4t3k2r1s0u9v.h7k6j5m4n3."+Guid.NewGuid().ToString("N")[..8]+".example";
    private async Task<bool> Seen(int t,string query,string? source="10.95.0.10",string? qtype="A",bool response=false)
        =>(await _rule.EvaluateAsync(NetworkBatch091095Context.Dns(t,query,source:source,qtype:qtype,response:response))).Matched;
    [Fact] public async Task First_Seen_Random_Looking_Domain_Matches_With_Isolated_Baseline()
    {
        var dir=Path.Combine(Path.GetTempPath(),"r095-advanced-"+Guid.NewGuid().ToString("N"));
        try{using(BaselineStore.UseScoped(new BaselineStore(new BaselineOptions{DirectoryPath=dir})))
            Assert.True(await Seen(1,Novel()));}
        finally{if(Directory.Exists(dir))Directory.Delete(dir,true);}
    }
    [Fact] public async Task Known_Benign_HumanReadable_And_Telemetry_Names_Are_Negative()
    {Assert.False(await Seen(1,"portal.example"));Assert.False(await Seen(2,"telemetry.microsoft.com")); }
    [Fact] public async Task Punycode_And_Invalid_Domain_Labels_Fail_Closed()
    {
        Assert.False(await Seen(1,"xn--d1acpjx3f.example"));
        Assert.False(await Seen(2,"a.."+Novel()));
        Assert.False(await Seen(3,"-invalid."+Novel()));
    }
    [Fact] public async Task Port53_And_Untrusted_Info_Without_Genuine_Dns_Question_Do_Not_Match()
    {
        var c=NetworkBatch091095Context.Dns(1,Novel());c.Record.DnsQname=null;c.Record.Info=Novel();
        Assert.False((await _rule.EvaluateAsync(c)).Matched);
        c=NetworkBatch091095Context.Dns(2,Novel());c.Record.ApplicationProtocol="HTTP";c.Record.Protocol="HTTP";
        Assert.False((await _rule.EvaluateAsync(c)).Matched);
    }
    [Fact] public async Task Responses_Missing_Source_And_Contradictory_L4_Are_Ignored()
    {
        Assert.False(await Seen(1,Novel(),response:true));
        Assert.False(await Seen(2,Novel(),source:null));
        var c=NetworkBatch091095Context.Dns(3,Novel());c.Record.IsTcp=true;
        Assert.False((await _rule.EvaluateAsync(c)).Matched);
    }
    [Fact] public async Task Repeated_Observed_Domain_Does_Not_Fabricate_Novelty()
    {
        var dir=Path.Combine(Path.GetTempPath(),"r095-known-"+Guid.NewGuid().ToString("N"));
        try{using(BaselineStore.UseScoped(new BaselineStore(new BaselineOptions{DirectoryPath=dir})))
        {var q=Novel();Assert.True(await Seen(1,q));Assert.False(await Seen(2,q));}}
        finally{if(Directory.Exists(dir))Directory.Delete(dir,true);}
    }
    [Fact] public async Task Cancellation_And_Invalid_Baseline_Storage_Fail_Closed()
    {
        using var cts=new CancellationTokenSource();cts.Cancel();
        await Assert.ThrowsAnyAsync<OperationCanceledException>(async()=>await _rule.EvaluateAsync(NetworkBatch091095Context.Dns(1,Novel()),cts.Token));
        var path=Path.GetTempFileName();
        try{using(BaselineStore.UseScoped(new BaselineStore(new BaselineOptions{DirectoryPath=path})))
            Assert.False(await Seen(2,Novel()));}
        finally{File.Delete(path);}
    }
}
