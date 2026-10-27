// SPDX-License-Identifier: MIT
using System;
using System.Threading;
using System.Threading.Tasks;
using Carthago.Engine.Rules.Dns;
using Xunit;
namespace Carthago.Tests;

[Collection("R102 distinct TXT correlation")]
public sealed class R103AdvancedAccuracyBatchTests
{
    private readonly R103_DNSBeaconingWithStableIntervalRule _rule=new();
    private async Task<bool> Hit(int t,string q,string source="10.103.0.10")
        =>(await _rule.EvaluateAsync(NetworkBatch101105Context.Dns(t,q,source:source))).Matched;
    [Fact] public async Task Six_Independent_Stable_Intervals_Produce_Beacon_Candidate()
    {
        var q="poll."+NetworkBatch101105Context.Root();
        for(var i=0;i<5;i++)Assert.False(await Hit(i*30,q));
        var e=Assert.Single((await _rule.EvaluateAsync(NetworkBatch101105Context.Dns(150,q))).Events);
        Assert.Equal("R103",e.RuleId);
        Assert.Contains(e.StructuredEvidence!.Items,x=>x.Key=="count"&&x.Value=="6");
    }
    [Fact] public async Task Duplicate_Id_Cannot_Fill_A_Stable_Interval_Window()
    {
        var q="poll."+NetworkBatch101105Context.Root();
        var c=NetworkBatch101105Context.Dns(1,q);
        Assert.False((await _rule.EvaluateAsync(c)).Matched);
        for(var i=0;i<9;i++)Assert.False((await _rule.EvaluateAsync(c)).Matched);
        for(var i=1;i<=4;i++)Assert.False(await Hit(i*30,q));
        Assert.True(await Hit(150,q));
    }
    [Fact] public async Task Six_Rotating_Subdomains_Do_Not_Prove_Exact_Beacon_Reuse()
    {
        var root=NetworkBatch101105Context.Root();
        for(var i=0;i<6;i++)Assert.False(await Hit(i*30,"poll"+i+"."+root));
    }
    [Fact] public async Task High_Jitter_Intervals_Are_Not_Stable_Beacons()
    {
        var q="poll."+NetworkBatch101105Context.Root();
        foreach(var t in new[]{1,4,12,80,260,500})Assert.False(await Hit(t,q));
    }
    [Fact] public async Task Different_Sources_Cannot_Pool_Sample_Counts()
    {
        var q="poll."+NetworkBatch101105Context.Root();
        for(var i=0;i<3;i++)Assert.False(await Hit(i*30,q));
        for(var i=0;i<3;i++)Assert.False(await Hit(i*30,q,source:"10.103.0.11"));
    }
    [Fact] public async Task Response_And_Http_Contradiction_Cannot_Seed_Cadence()
    {
        var q="poll."+NetworkBatch101105Context.Root();
        var c=NetworkBatch101105Context.Dns(1,q,response:true);
        Assert.False((await _rule.EvaluateAsync(c)).Matched);
        c=NetworkBatch101105Context.Dns(2,q);c.Record.HttpMethod="GET";
        Assert.False((await _rule.EvaluateAsync(c)).Matched);
        Assert.False(await Hit(30,q));
    }
    [Fact] public async Task Cancellation_And_Keyword_Only_Info_Are_Excluded()
    {
        var q="poll."+NetworkBatch101105Context.Root();
        using var cts=new CancellationTokenSource();cts.Cancel();
        await Assert.ThrowsAnyAsync<OperationCanceledException>(async()=>await _rule.EvaluateAsync(NetworkBatch101105Context.Dns(1,q),cts.Token));
        var c=NetworkBatch101105Context.Dns(2,"short.example");c.Record.DnsQname=null;c.Record.Info=q;
        Assert.False((await _rule.EvaluateAsync(c)).Matched);
    }
}
