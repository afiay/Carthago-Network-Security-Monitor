// SPDX-License-Identifier: MIT
using System;
using System.Threading;
using System.Threading.Tasks;
using Carthago.Engine.Rules.LateralMovement;
using Xunit;
namespace Carthago.Tests;
public sealed class R074AdvancedAccuracyBatchTests
{
    private readonly R074_WinRMPowerShellRemotingSweepRule _rule=new();
    private async Task<bool> Seen(int s,string dst="10.71.1.1",string src="10.71.0.10",int port=5985,ushort? flags=2,string protocol="TCP")
        => (await _rule.EvaluateAsync(NetworkBatch071075Context.Tcp(s,src,dst,port,flags,protocol))).Matched;
    [Fact] public async Task Five_Distinct_WinRm_Http_Targets_Trigger()
    {for(var i=1;i<5;i++)Assert.False(await Seen(i,dst:$"10.71.1.{i}"));Assert.True(await Seen(5,dst:"10.71.1.5"));}
    [Fact] public async Task WinRm_Https_Port_5986_Is_Recognized()
    {for(var i=1;i<5;i++)Assert.False(await Seen(i,dst:$"10.71.1.{i}",port:5986));Assert.True(await Seen(5,dst:"10.71.1.5",port:5986));}
    [Fact] public async Task Port_5985_And_5986_Observations_Do_Not_Combine()
    {for(var i=1;i<4;i++)Assert.False(await Seen(i,dst:$"10.71.1.{i}"));for(var i=4;i<=6;i++)Assert.False(await Seen(i,dst:$"10.71.1.{i}",port:5986));}
    [Fact] public async Task Repeated_Target_Is_Not_A_Remoting_Sweep()
    {for(var i=1;i<25;i++)Assert.False(await Seen(i));}
    [Fact] public async Task Wrong_Port_SynAck_Udp_And_Text_Only_Evidence_Are_Rejected()
    {for(var i=1;i<8;i++){Assert.False(await Seen(i,dst:$"10.71.1.{i}",port:443));Assert.False(await Seen(i+10,dst:$"10.71.1.{i}",flags:0x12));Assert.False(await Seen(i+20,dst:$"10.71.1.{i}",protocol:"UDP"));}}
    [Fact] public async Task Source_Isolation_And_Expired_Window_Do_Not_Combine()
    {for(var i=1;i<5;i++)Assert.False(await Seen(i,dst:$"10.71.1.{i}"));Assert.False(await Seen(5,src:"10.71.0.11",dst:"10.71.1.5"));Assert.False(await Seen(700,dst:"10.71.1.5"));}
    [Fact] public async Task Duplicate_Cancellation_And_Privacy_Are_Enforced()
    {using var c=new CancellationTokenSource();c.Cancel();await Assert.ThrowsAnyAsync<OperationCanceledException>(async()=>await _rule.EvaluateAsync(NetworkBatch071075Context.Tcp(1,port:5985),c.Token));for(var i=2;i<=5;i++)Assert.False(await Seen(i,dst:$"10.71.1.{i}"));Assert.False(await Seen(5,dst:"10.71.1.6"));var p=NetworkBatch071075Context.Tcp(6,destination:"10.71.1.6",port:5985,info:"secret-winrm");var e=Assert.Single((await _rule.EvaluateAsync(p)).Events);Assert.DoesNotContain("secret-winrm",e.Description);Assert.DoesNotContain("secret-winrm",e.Evidence);}
}
