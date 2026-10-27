// SPDX-License-Identifier: MIT
using System;
using System.Threading;
using System.Threading.Tasks;
using Carthago.Engine.Rules.IPv6;
using Xunit;
namespace Carthago.Tests;
public sealed class R072AdvancedAccuracyBatchTests
{
    private readonly R072_SuspiciousMulticastDiscoveryBurstRule _rule=new();
    private async Task<bool> Seen(int s,string src="fe80::71",string dst="ff02::fb",int port=5353,string protocol="UDP")
        => (await _rule.EvaluateAsync(NetworkBatch071075Context.Multicast(s,src,dst,port,protocol))).Matched;
    [Fact] public async Task Twenty_Structured_Mdns_Observations_Trigger_Once()
    {for(var i=1;i<20;i++)Assert.False(await Seen(i));Assert.True(await Seen(20));Assert.False(await Seen(21));}
    [Fact] public async Task Nineteen_Legitimate_Observations_Are_Below_Threshold()
    {for(var i=1;i<20;i++)Assert.False(await Seen(i));}
    [Fact] public async Task Wrong_Group_Or_Transport_Is_Not_Multicast_Discovery()
    {for(var i=1;i<=25;i++)Assert.False(await Seen(i,dst:"ff02::1"));Assert.False(await Seen(26,protocol:"TCP"));}
    [Fact] public async Task Structured_Llmnr_And_Ssdp_Are_Recognized_Independently()
    {for(var i=1;i<20;i++)Assert.False(await Seen(i,dst:"ff02::1:3",port:5355));Assert.True(await Seen(20,dst:"ff02::1:3",port:5355));Assert.False(await Seen(21,dst:"ff02::c",port:1900));}
    [Fact] public async Task Duplicate_Timestamps_And_Source_Isolation()
    {for(var i=1;i<=18;i++)Assert.False(await Seen(i));Assert.False(await Seen(18));Assert.False(await Seen(17));Assert.False(await Seen(19,src:"fe80::72"));Assert.False(await Seen(20));Assert.True(await Seen(21));}
    [Fact] public async Task Old_Window_Expires_Before_New_Episode()
    {for(var i=1;i<20;i++)Assert.False(await Seen(i));Assert.False(await Seen(200));for(var i=201;i<=218;i++)Assert.False(await Seen(i));Assert.True(await Seen(219));}
    [Fact] public async Task Quic_Contradiction_Cancellation_And_Raw_Info_Redaction()
    {var bad=NetworkBatch071075Context.Multicast(1);bad.Record.IsQuic=true;Assert.False((await _rule.EvaluateAsync(bad)).Matched);using var c=new CancellationTokenSource();c.Cancel();await Assert.ThrowsAnyAsync<OperationCanceledException>(async()=>await _rule.EvaluateAsync(NetworkBatch071075Context.Multicast(1),c.Token));for(var i=2;i<=20;i++)Assert.False(await Seen(i));var p=NetworkBatch071075Context.Multicast(21,info:"private-discovery-token");var e=Assert.Single((await _rule.EvaluateAsync(p)).Events);Assert.DoesNotContain("private-discovery-token",e.Description);Assert.DoesNotContain("private-discovery-token",e.Evidence);}
}
