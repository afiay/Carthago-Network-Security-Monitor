// SPDX-License-Identifier: MIT
using System;
using System.Threading;
using System.Threading.Tasks;
using Carthago.Engine.Rules.IPv6;
using Xunit;

namespace Carthago.Tests;

public sealed class R067AdvancedAccuracyBatchTests
{
    private readonly R067_RogueIPv6RouterAdvertisementRule _rule = new();
    private async Task<bool> Ra(int s, string mac = "00:11:22:33:44:55",
        string source = "fe80::1", string destination = "ff02::1",
        ushort? type = 0x8600, string? ttl = "255")
        => (await _rule.EvaluateAsync(Ipv6Batch066070Context.Packet(s, source, destination,
            icmp: type, ttl: ttl, mac: mac))).Matched;
    [Fact] public async Task Ready_Router_Identity_Change_Requires_Two_Distinct_Claims()
    { using var scope = await AssetBatch061065Context.Ready(); Assert.False(await Ra(1)); Assert.False(await Ra(2, "00:11:22:33:44:66")); Assert.True(await Ra(3, "00:11:22:33:44:66")); }
    [Fact] public async Task Ordinary_Router_Advertisement_Is_Not_Rogue()
    { using var scope = await AssetBatch061065Context.Ready(); for(var i=1;i<=4;i++) Assert.False(await Ra(i)); }
    [Fact] public async Task Wrong_Icmp_Type_And_Hop_Limit_Fail_Closed()
    { using var scope = await AssetBatch061065Context.Ready(); Assert.False(await Ra(1, type: 0x8700)); Assert.False(await Ra(2, ttl: "64")); Assert.False(await Ra(3, ttl: null)); }
    [Fact] public async Task Global_Source_And_Wrong_Multicast_Are_Excluded()
    { using var scope = await AssetBatch061065Context.Ready(); Assert.False(await Ra(1, source: "2001:db8::1")); Assert.False(await Ra(2, destination: "ff02::2")); }
    [Fact] public async Task Invalid_And_Multicast_Mac_Cannot_Seed_Router_State()
    { using var scope = await AssetBatch061065Context.Ready(); Assert.False(await Ra(1, mac: "01:11:22:33:44:55")); Assert.False(await Ra(2, mac: "invalid")); }
    [Fact] public async Task Duplicate_And_Reordered_Observations_Do_Not_Confirm()
    { using var scope = await AssetBatch061065Context.Ready(); Assert.False(await Ra(1)); Assert.False(await Ra(2, "00:11:22:33:44:66")); Assert.False(await Ra(2, "00:11:22:33:44:66")); Assert.False(await Ra(1, "00:11:22:33:44:66")); Assert.True(await Ra(3, "00:11:22:33:44:66")); }
    [Fact] public async Task Unready_Baseline_Prevents_Router_Identity_Alert()
    { using var scope = AssetBatch061065Context.Unready(); Assert.False(await Ra(1)); Assert.False(await Ra(2, "00:11:22:33:44:66")); Assert.False(await Ra(3, "00:11:22:33:44:66")); }
    [Fact] public async Task Alert_Redacts_Router_Mac_And_Packet_Text()
    { using var scope = await AssetBatch061065Context.Ready(); Assert.False(await Ra(1)); Assert.False(await Ra(2, "00:11:22:33:44:66")); var result = await _rule.EvaluateAsync(Ipv6Batch066070Context.Packet(3, mac: "00:11:22:33:44:66", info: "sensitive-ra-payload")); var e = Assert.Single(result.Events); Assert.DoesNotContain("00:11:22", e.Evidence); Assert.DoesNotContain("sensitive-ra-payload", e.Description); }
    [Fact] public async Task Cancellation_Does_Not_Advance_Router_State()
    { using var scope = await AssetBatch061065Context.Ready(); using var cancel = new CancellationTokenSource(); cancel.Cancel(); await Assert.ThrowsAnyAsync<OperationCanceledException>(async () => await _rule.EvaluateAsync(Ipv6Batch066070Context.Packet(1), cancel.Token)); }
}
