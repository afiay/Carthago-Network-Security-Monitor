// SPDX-License-Identifier: MIT
using System;
using System.Threading;
using System.Threading.Tasks;
using Carthago.Engine.Rules.AssetInventory;
using Xunit;
namespace Carthago.Tests;
public sealed class R065AdvancedAccuracyBatchTests
{
    private readonly R065_FirstTimeASNForHostRule _rule=new();
    private async Task<bool> Seen(int s,string? asn,string src="10.61.0.10",string dst="8.8.8.8")
        => (await _rule.EvaluateAsync(AssetBatch061065Context.At(s,source:src,destination:dst,asn:asn))).Matched;
    private async Task Warm(){for(int i=1;i<=3;i++)Assert.False(await Seen(i,"AS"+(65000+i)));}
    [Fact] public async Task Ready_Baseline_And_Two_Sightings_Confirm_New_Asn(){using var scope=await AssetBatch061065Context.Ready();await Warm();Assert.False(await Seen(4,"AS65100"));Assert.True(await Seen(5,"65100"));}
    [Fact] public async Task Single_Novel_Asn_Does_Not_Match(){using var scope=await AssetBatch061065Context.Ready();await Warm();Assert.False(await Seen(4,"AS65100"));}
    [Fact] public async Task Invalid_Enrichment_And_Private_Destination_Cannot_Seed(){using var scope=await AssetBatch061065Context.Ready();Assert.False(await Seen(1,"AS0"));Assert.False(await Seen(2,"ASbad"));Assert.False(await Seen(3,"AS4294967296"));Assert.False(await Seen(4,"AS65001",dst:"10.61.0.20"));}
    [Fact] public async Task Duplicate_Timestamp_Does_Not_Confirm(){using var scope=await AssetBatch061065Context.Ready();await Warm();Assert.False(await Seen(4,"AS65100"));Assert.False(await Seen(4,"AS65100"));Assert.True(await Seen(5,"AS65100"));}
    [Fact] public async Task Unready_Baseline_Does_Not_Promote(){using var scope=AssetBatch061065Context.Unready();Assert.False(await Seen(0,"AS65100"));}
    [Fact] public async Task Different_Hosts_Have_Separate_Baselines(){using var scope=await AssetBatch061065Context.Ready();await Warm();Assert.False(await Seen(4,"AS65100",src:"10.61.0.11"));Assert.False(await Seen(5,"AS65100",src:"10.61.0.11"));}
    [Fact] public async Task Alert_Redacts_Asn_And_Organization(){using var scope=await AssetBatch061065Context.Ready();await Warm();Assert.False(await Seen(4,"AS65100"));var r=await _rule.EvaluateAsync(AssetBatch061065Context.At(5,asn:"AS65100",info:"secret-org"));var e=Assert.Single(r.Events);Assert.DoesNotContain("secret-org",e.Evidence);Assert.DoesNotContain("AS65100",e.Summary);}
    [Fact] public async Task Cancellation_Prevents_Baseline_Write(){using var scope=await AssetBatch061065Context.Ready();using var c=new CancellationTokenSource();c.Cancel();await Assert.ThrowsAnyAsync<OperationCanceledException>(async()=>await _rule.EvaluateAsync(AssetBatch061065Context.At(0,asn:"AS65100"),c.Token));}
}
