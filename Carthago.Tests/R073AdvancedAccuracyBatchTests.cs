// SPDX-License-Identifier: MIT
using System;
using System.Threading;
using System.Threading.Tasks;
using Carthago.Engine.Rules.LateralMovement;
using Xunit;
namespace Carthago.Tests;
public sealed class R073AdvancedAccuracyBatchTests
{
    private readonly R073_RDPLateralMovementBurstRule _rule=new();
    private async Task<bool> Seen(int s,string dst="10.71.1.1",string src="10.71.0.10",int port=3389,ushort? flags=2,string protocol="TCP")
        => (await _rule.EvaluateAsync(NetworkBatch071075Context.Tcp(s,src,dst,port,flags,protocol))).Matched;
    [Fact] public async Task Five_Distinct_Internal_Rdp_Targets_Trigger_Once()
    {for(var i=1;i<5;i++)Assert.False(await Seen(i,dst:$"10.71.1.{i}"));Assert.True(await Seen(5,dst:"10.71.1.5"));Assert.False(await Seen(6,dst:"10.71.1.6"));}
    [Fact] public async Task Repeated_Authorized_Target_Does_Not_Inflate_Count()
    {for(var i=1;i<20;i++)Assert.False(await Seen(i));}
    [Fact] public async Task Wrong_Port_Protocol_And_SynAck_Are_Excluded()
    {for(var i=1;i<=7;i++){Assert.False(await Seen(i,dst:$"10.71.1.{i}",port:443));Assert.False(await Seen(i+10,dst:$"10.71.1.{i}",protocol:"UDP"));Assert.False(await Seen(i+20,dst:$"10.71.1.{i}",flags:0x12));}}
    [Fact] public async Task External_Destination_And_Same_Host_Are_Excluded()
    {for(var i=1;i<8;i++){Assert.False(await Seen(i,dst:"8.8.8.8"));Assert.False(await Seen(i+10,dst:"10.71.0.10"));}}
    [Fact] public async Task Initiator_Isolation_And_Duplicate_Timestamps()
    {for(var i=1;i<5;i++)Assert.False(await Seen(i,dst:$"10.71.1.{i}"));Assert.False(await Seen(4,dst:"10.71.1.5"));Assert.False(await Seen(5,dst:"10.71.1.5",src:"10.71.0.11"));Assert.True(await Seen(6,dst:"10.71.1.5"));}
    [Fact] public async Task Five_Minute_Window_Expires_And_Rearms()
    {for(var i=1;i<=5;i++)await Seen(i,dst:$"10.71.1.{i}");for(var i=1;i<5;i++)Assert.False(await Seen(700+i,dst:$"10.71.2.{i}"));Assert.True(await Seen(705,dst:"10.71.2.5"));}
    [Fact] public async Task Contradictory_Dns_Cancellation_And_Alert_Privacy()
    {var bad=NetworkBatch071075Context.Tcp(1);bad.Record.DnsQname="private.local";Assert.False((await _rule.EvaluateAsync(bad)).Matched);using var c=new CancellationTokenSource();c.Cancel();await Assert.ThrowsAnyAsync<OperationCanceledException>(async()=>await _rule.EvaluateAsync(NetworkBatch071075Context.Tcp(1),c.Token));for(var i=2;i<=5;i++)Assert.False(await Seen(i,dst:$"10.71.1.{i}"));var p=NetworkBatch071075Context.Tcp(6,destination:"10.71.1.6",info:"private-rdp-credential");var e=Assert.Single((await _rule.EvaluateAsync(p)).Events);Assert.DoesNotContain("private-rdp-credential",e.Description);Assert.DoesNotContain("private-rdp-credential",e.Evidence);}
}
