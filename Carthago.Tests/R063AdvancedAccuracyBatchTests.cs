// SPDX-License-Identifier: MIT
using System;
using System.Threading;
using System.Threading.Tasks;
using Carthago.Engine.Rules.AssetInventory;
using Xunit;
namespace Carthago.Tests;
public sealed class R063AdvancedAccuracyBatchTests
{
    private readonly R063_WorkstationActingLikeServerRule _rule=new();
    private async Task<bool> Seen(int s,int client=1,string host="10.61.0.30",int port=8443,string? process=null)
        => (await _rule.EvaluateAsync(AssetBatch061065Context.At(s,source:"10.61.0."+client,
            destination:host,destinationPort:port,process:process))).Matched;
    [Fact] public async Task Five_Distinct_Internal_Peers_Confirm_FanIn(){for(int i=1;i<5;i++)Assert.False(await Seen(i,i));Assert.True(await Seen(5,5));}
    [Fact] public async Task Repeated_Client_Does_Not_Inflate_Distinct_Count(){for(int i=1;i<9;i++)Assert.False(await Seen(i,1));}
    [Fact] public async Task Different_Ports_Do_Not_Combine(){for(int i=1;i<5;i++)Assert.False(await Seen(i,i,port:443));Assert.False(await Seen(5,5));}
    [Fact] public async Task Public_And_LinkLocal_Destinations_Are_Excluded(){for(int i=1;i<7;i++){Assert.False(await Seen(i,i,host:"8.8.8.8"));Assert.False(await Seen(i+10,i,host:"169.254.169.254"));}}
    [Fact] public async Task Enriched_Known_Server_Process_Is_Excluded(){for(int i=1;i<7;i++)Assert.False(await Seen(i,i,process:"nginx"));}
    [Fact] public async Task Expired_Five_Minute_Window_Does_Not_Accumulate(){for(int i=1;i<5;i++)Assert.False(await Seen(i*400,i));Assert.False(await Seen(2000,5));}
    [Fact] public async Task Cancellation_Does_Not_Count_Source(){using var c=new CancellationTokenSource();c.Cancel();await Assert.ThrowsAnyAsync<OperationCanceledException>(async()=>await _rule.EvaluateAsync(AssetBatch061065Context.At(0),c.Token));Assert.False(await Seen(1));}
}
