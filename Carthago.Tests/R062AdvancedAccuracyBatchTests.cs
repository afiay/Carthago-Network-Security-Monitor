// SPDX-License-Identifier: MIT
using System;
using System.Threading;
using System.Threading.Tasks;
using Carthago.Engine.Rules.AssetInventory;
using Xunit;
namespace Carthago.Tests;
public sealed class R062AdvancedAccuracyBatchTests
{
    private readonly R062_NewServiceOpenedOnInternalHostRule _rule=new();
    private async Task<bool> Seen(int s,int port=443,string host="10.61.0.30",ushort flags=0x12)
        => (await _rule.EvaluateAsync(AssetBatch061065Context.At(s,source:host,destination:"10.61.0.10",
            sourcePort:port,destinationPort:50000,flags:flags))).Matched;
    [Fact] public async Task Second_Service_Port_With_Second_Reply_Matches(){Assert.False(await Seen(0));Assert.False(await Seen(1,8443));Assert.True(await Seen(2,8443));}
    [Fact] public async Task First_Service_Remains_Silent(){Assert.False(await Seen(0));Assert.False(await Seen(1));}
    [Fact] public async Task Client_Syn_Does_Not_Prove_Server_Reply(){Assert.False(await Seen(0,flags:2));Assert.False(await Seen(1,8443,flags:2));}
    [Fact] public async Task Replayed_Timestamp_Cannot_Confirm(){Assert.False(await Seen(0));Assert.False(await Seen(1,8443));Assert.False(await Seen(1,8443));Assert.True(await Seen(2,8443));}
    [Fact] public async Task Different_Hosts_Do_Not_Share_Service_History(){Assert.False(await Seen(0));Assert.False(await Seen(1,8443,host:"10.61.0.31"));Assert.False(await Seen(2,8443,host:"10.61.0.31"));}
    [Fact] public async Task Stale_Candidate_Needs_Fresh_Corroboration(){Assert.False(await Seen(0));Assert.False(await Seen(1,8443));Assert.False(await Seen(200,8443));Assert.True(await Seen(201,8443));}
    [Fact] public async Task Cancellation_Does_Not_Prime_State(){using var c=new CancellationTokenSource();c.Cancel();await Assert.ThrowsAnyAsync<OperationCanceledException>(async()=>await _rule.EvaluateAsync(AssetBatch061065Context.At(0),c.Token));Assert.False(await Seen(1));}
}
