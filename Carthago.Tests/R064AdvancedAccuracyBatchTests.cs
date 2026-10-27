// SPDX-License-Identifier: MIT
using System;
using System.Threading;
using System.Threading.Tasks;
using Carthago.Engine.Rules.AssetInventory;
using Xunit;
namespace Carthago.Tests;
public sealed class R064AdvancedAccuracyBatchTests
{
    private readonly R064_FirstTimeDestinationForHostRule _rule=new();
    private async Task<bool> Seen(int s,string dst,string src="10.61.0.10")
        => (await _rule.EvaluateAsync(AssetBatch061065Context.At(s,source:src,destination:dst))).Matched;
    private async Task Warm(){for(int i=1;i<=8;i++)Assert.False(await Seen(i,"8.8.4."+i));}
    [Fact] public async Task Ready_Baseline_And_Two_Sightings_Confirm_Novel_Destination(){using var scope=await AssetBatch061065Context.Ready();await Warm();Assert.False(await Seen(9,"1.1.1.1"));Assert.True(await Seen(10,"1.1.1.1"));}
    [Fact] public async Task One_New_Destination_Is_Not_Enough(){using var scope=await AssetBatch061065Context.Ready();await Warm();Assert.False(await Seen(9,"1.1.1.1"));}
    [Fact] public async Task Duplicate_Timestamp_Cannot_Confirm(){using var scope=await AssetBatch061065Context.Ready();await Warm();Assert.False(await Seen(9,"1.1.1.1"));Assert.False(await Seen(9,"1.1.1.1"));Assert.True(await Seen(10,"1.1.1.1"));}
    [Fact] public async Task Unready_Baseline_Does_Not_Promote(){using var scope=AssetBatch061065Context.Unready();Assert.False(await Seen(0,"1.1.1.1"));}
    [Fact] public async Task Private_And_Documentation_Ips_Cannot_Seed(){using var scope=await AssetBatch061065Context.Ready();Assert.False(await Seen(0,"10.61.0.20"));Assert.False(await Seen(1,"203.0.113.4"));Assert.False(await Seen(2,"1.1.1.1"));}
    [Fact] public async Task Other_Hosts_Do_Not_Inherit_Baseline(){using var scope=await AssetBatch061065Context.Ready();await Warm();Assert.False(await Seen(9,"1.1.1.1","10.61.0.11"));Assert.False(await Seen(10,"1.1.1.1","10.61.0.11"));}
    [Fact] public async Task Alert_Does_Not_Expose_Untrusted_Payload(){using var scope=await AssetBatch061065Context.Ready();await Warm();Assert.False(await Seen(9,"1.1.1.1"));var r=await _rule.EvaluateAsync(AssetBatch061065Context.At(10,destination:"1.1.1.1",info:"secret-value"));var e=Assert.Single(r.Events);Assert.DoesNotContain("secret-value",e.Evidence);Assert.DoesNotContain("1.1.1.1",e.Summary);}
    [Fact] public async Task Cancellation_Prevents_Observation(){using var scope=await AssetBatch061065Context.Ready();using var c=new CancellationTokenSource();c.Cancel();await Assert.ThrowsAnyAsync<OperationCanceledException>(async()=>await _rule.EvaluateAsync(AssetBatch061065Context.At(0),c.Token));}
}
