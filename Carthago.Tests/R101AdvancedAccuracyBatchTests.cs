// SPDX-License-Identifier: MIT
using System;
using System.Threading;
using System.Threading.Tasks;
using Carthago.Engine.Rules.Dns;
using Xunit;
namespace Carthago.Tests;
public sealed class R101AdvancedAccuracyBatchTests
{
    private readonly R101_DNSCNAMEChainAbuseRule _rule=new();
    private static string Chain(int count)
    {
        var names=new string[count+1];
        for(var i=0;i<names.Length;i++)names[i]="alias"+i+".example";
        return string.Join(" CNAME ",names);
    }
    private async Task<bool> Hit(int t,string answers,bool response=true,string? qname=null)
        =>(await _rule.EvaluateAsync(NetworkBatch101105Context.Dns(t,qname??"host."+NetworkBatch101105Context.Root(),response:response,answers:answers))).Matched;
    [Fact] public async Task Connected_FiveHop_Cname_Response_Produces_Chain_Evidence()
    {
        var e=Assert.Single((await _rule.EvaluateAsync(NetworkBatch101105Context.Dns(1,"host."+NetworkBatch101105Context.Root(),response:true,answers:Chain(5)))).Events);
        Assert.Equal("R101",e.RuleId);
        Assert.Contains(e.StructuredEvidence!.Items,x=>x.Key=="dns.cnameCount"&&x.Value=="5");
    }
    [Fact] public async Task Unrelated_Cname_Pairs_Cannot_Be_Summed_Into_A_Chain()
    {
        var a="a.example CNAME b.example c.example CNAME d.example e.example CNAME f.example";
        Assert.False(await Hit(1,a));
    }
    [Fact] public async Task Shallow_Cdn_Aliasing_Is_Not_Abuse()
    {
        Assert.False(await Hit(1,"a.example CNAME b.cloudfront.net CNAME c.akamaiedge.net CNAME d.cloudfront.net"));
    }
    [Fact] public async Task Circular_Or_Conflicting_Cname_Answers_Fail_Closed()
    {
        Assert.False(await Hit(1,"a.example CNAME b.example CNAME a.example CNAME b.example"));
        Assert.False(await Hit(2,"a.example CNAME b.example a.example CNAME c.example c.example CNAME d.example"));
    }
    [Fact] public async Task Query_Only_And_Missing_Answers_Are_Not_Response_Evidence()
    {
        Assert.False(await Hit(1,Chain(5),response:false));
        Assert.False(await Hit(2,""));
    }
    [Fact] public async Task Contradictory_Transport_And_Dns_Metadata_Cannot_Alert()
    {
        var c=NetworkBatch101105Context.Dns(1,"host."+NetworkBatch101105Context.Root(),response:true,answers:Chain(5));
        c.Record.HttpMethod="GET";
        Assert.False((await _rule.EvaluateAsync(c)).Matched);
        c=NetworkBatch101105Context.Dns(2,"host."+NetworkBatch101105Context.Root(),response:true,answers:Chain(5));
        c.Record.IsTcp=true;
        Assert.False((await _rule.EvaluateAsync(c)).Matched);
    }
    [Fact] public async Task Cancellation_And_Overlong_Answer_Field_Are_Fail_Closed()
    {
        using var cts=new CancellationTokenSource();cts.Cancel();
        await Assert.ThrowsAnyAsync<OperationCanceledException>(async()=>await _rule.EvaluateAsync(NetworkBatch101105Context.Dns(1,"x.example",response:true,answers:Chain(5)),cts.Token));
        Assert.False(await Hit(2,Chain(5)+new string('x',4100)));
    }
}
