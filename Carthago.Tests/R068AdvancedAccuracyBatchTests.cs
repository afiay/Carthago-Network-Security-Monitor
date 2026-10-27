// SPDX-License-Identifier: MIT
using System;
using System.Threading;
using System.Threading.Tasks;
using Carthago.Engine.Rules.IPv6;
using Xunit;

namespace Carthago.Tests;

public sealed class R068AdvancedAccuracyBatchTests
{
    private readonly R068_IPv6NeighborDiscoverySweepRule _rule = new();
    private async Task<bool> Ns(int s, int target = 1, string source = "fe80::1",
        ushort? type = 0x8700, string? ttl = "255", string? destination = null)
        => (await _rule.EvaluateAsync(Ipv6Batch066070Context.Packet(s, source,
            destination ?? ("2001:db8::" + target.ToString("x")), icmp: type, ttl: ttl))).Matched;
    [Fact] public async Task Fifteen_Distinct_Unicast_Targets_Trigger_Once()
    { for(var i=1;i<15;i++) Assert.False(await Ns(i,i)); Assert.True(await Ns(15,15)); Assert.False(await Ns(16,16)); }
    [Fact] public async Task Fourteen_Distinct_Targets_Are_Insufficient()
    { for(var i=1;i<=14;i++) Assert.False(await Ns(i,i)); }
    [Fact] public async Task Repeated_Targets_Do_Not_Inflate_Distinct_Count()
    { for(var i=1;i<=30;i++) Assert.False(await Ns(i,1)); }
    [Fact] public async Task Multicast_Destination_Is_Not_An_Nd_Target()
    { for(var i=1;i<=18;i++) Assert.False(await Ns(i,i,destination:"ff02::1:ff00:1")); }
    [Fact] public async Task Invalid_Type_Hop_Limit_And_Endpoint_Are_Excluded()
    { Assert.False(await Ns(1,type:0x8800)); Assert.False(await Ns(2,ttl:"64")); Assert.False(await Ns(3,source:"::")); }
    [Fact] public async Task Distinct_Sources_Do_Not_Share_Threshold()
    { for(var i=1;i<=14;i++){Assert.False(await Ns(i,i)); Assert.False(await Ns(i+100,i,source:"fe80::2"));} }
    [Fact] public async Task Expired_Window_Does_Not_Accumulate_Targets()
    { for(var i=1;i<=15;i++) Assert.False(await Ns(i*400,i)); }
    [Fact] public async Task Duplicate_Timestamp_And_Out_Of_Order_Are_Rejected()
    { Assert.False(await Ns(1,1)); for(var i=2;i<=16;i++) Assert.False(await Ns(1,i)); Assert.False(await Ns(0,17)); }
    [Fact] public async Task Alert_Does_Not_Include_Packet_Info()
    { for(var i=1;i<15;i++) Assert.False(await Ns(i,i)); var r = await _rule.EvaluateAsync(Ipv6Batch066070Context.Packet(15, destination:"2001:db8::f", icmp:0x8700, info:"private-payload")); var e = Assert.Single(r.Events); Assert.DoesNotContain("private-payload",e.Evidence); }
    [Fact] public async Task Cancellation_Prevents_Observation()
    { using var cancel = new CancellationTokenSource(); cancel.Cancel(); await Assert.ThrowsAnyAsync<OperationCanceledException>(async () => await _rule.EvaluateAsync(Ipv6Batch066070Context.Packet(1, destination:"2001:db8::1", icmp:0x8700),cancel.Token)); }
}
