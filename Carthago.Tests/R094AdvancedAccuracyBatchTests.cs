// SPDX-License-Identifier: MIT
using System;
using System.IO;
using System.Threading;
using System.Threading.Tasks;
using Carthago.Engine.Rules.Dns;
using Carthago.Services.Baseline;
using Xunit;
namespace Carthago.Tests;
public sealed class R094AdvancedAccuracyBatchTests
{
    private const string Dga="x9q8v7m6n5p4t3k2rz.example";
    private readonly R094_DGALikeDomainQueryRule _rule=new();
    private async Task<bool> Seen(int t,string q=Dga,string? source="10.94.0.10",bool response=false,string? qtype="A",string protocol="DNS",string? info=null)
        =>(await _rule.EvaluateAsync(NetworkBatch091095Context.Dns(t,q,source:source,qtype:qtype,response:response,protocol:protocol,info:info))).Matched;
    [Fact] public async Task Strong_Attributable_Dga_Query_Triggers_In_Isolated_Baseline()
    {
        var dir=Path.Combine(Path.GetTempPath(),"r094-advanced-"+Guid.NewGuid().ToString("N"));
        try{using(BaselineStore.UseScoped(new BaselineStore(new BaselineOptions{DirectoryPath=dir})))
            Assert.True(await Seen(1));}
        finally{if(Directory.Exists(dir))Directory.Delete(dir,true);}
    }
    [Fact] public async Task Human_Readable_And_Known_Telemetry_Queries_Are_Excluded()
    {Assert.False(await Seen(1,"portal.example"));Assert.False(await Seen(2,"telemetry.microsoft.com")); }
    [Fact] public async Task Idn_Punycode_Root_Is_Not_Treated_As_Algorithmic()
    {Assert.False(await Seen(1,"xn--d1acpjx3f.example"));}
    [Fact] public async Task Invalid_Dns_Transport_And_Contradictory_Http_Do_Not_Match()
    {
        var c=NetworkBatch091095Context.Dns(1,Dga,protocol:"HTTP");c.Record.ApplicationProtocol="HTTP";
        Assert.False((await _rule.EvaluateAsync(c)).Matched);
        c=NetworkBatch091095Context.Dns(2,Dga);c.Record.HttpMethod="GET";
        Assert.False((await _rule.EvaluateAsync(c)).Matched);
        c=NetworkBatch091095Context.Dns(3,Dga);c.Record.IsTcp=true;
        Assert.False((await _rule.EvaluateAsync(c)).Matched);
    }
    [Fact] public async Task Responses_Invalid_Domain_Labels_And_Unsupported_Qtypes_Are_Rejected()
    {
        Assert.False(await Seen(1,response:true));
        Assert.False(await Seen(2,"a.."+Dga));
        Assert.False(await Seen(3,Dga,qtype:"BADTYPE"));
        Assert.False(await Seen(4,Dga,source:"not-an-ip"));
    }
    [Fact] public async Task Established_Dga_Baseline_Suppresses_Repetition()
    {
        var dir=Path.Combine(Path.GetTempPath(),"r094-repeated-"+Guid.NewGuid().ToString("N"));
        try{using(BaselineStore.UseScoped(new BaselineStore(new BaselineOptions{DirectoryPath=dir})))
        {Assert.True(await Seen(1));await Seen(2);await Seen(3);Assert.False(await Seen(4));}}
        finally{if(Directory.Exists(dir))Directory.Delete(dir,true);}
    }
    [Fact] public async Task Cancellation_And_Untrusted_Info_Are_Handled()
    {
        using var cts=new CancellationTokenSource();cts.Cancel();
        await Assert.ThrowsAnyAsync<OperationCanceledException>(async()=>await _rule.EvaluateAsync(NetworkBatch091095Context.Dns(1,Dga),cts.Token));
        Assert.False(await Seen(2,"humanreadable.example",info:"x9q8v7m6n5p4t3k2rz.example"));
    }
}
