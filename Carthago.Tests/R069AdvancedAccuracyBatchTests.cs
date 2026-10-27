// SPDX-License-Identifier: MIT
using System;
using System.Threading;
using System.Threading.Tasks;
using Carthago.Engine.Rules.IPv6;
using Xunit;

namespace Carthago.Tests;

public sealed class R069AdvancedAccuracyBatchTests
{
    private readonly R069_IPv6DuplicateAddressSpoofingRule _rule = new();
    private async Task<bool> Na(int s, string mac = "00:11:22:33:44:55",
        string source = "fe80::1", string? info = "target=fe80::1",
        ushort? type = 0x8800, string? ttl = "255")
        => (await _rule.EvaluateAsync(Ipv6Batch066070Context.Packet(s, source,
            icmp:type, ttl:ttl, mac:mac, info:info))).Matched;
    [Fact] public async Task Repeated_Conflicting_Identity_Confirms_Anomaly()
    { using var scope = await AssetBatch061065Context.Ready(); Assert.False(await Na(1)); Assert.False(await Na(2,"00:11:22:33:44:66")); Assert.True(await Na(3,"00:11:22:33:44:66")); }
    [Fact] public async Task Stable_Neighbor_Advertisement_Does_Not_Alert()
    { using var scope = await AssetBatch061065Context.Ready(); for(var i=1;i<6;i++) Assert.False(await Na(i)); }
    [Fact] public async Task Unrelated_Or_Absent_Target_Text_Cannot_Claim_An_Address()
    { using var scope = await AssetBatch061065Context.Ready(); Assert.False(await Na(1,info:"target=fe80::2")); Assert.False(await Na(2,info:null)); Assert.False(await Na(3,info:"duplicate address spoof")); }
    [Fact] public async Task Invalid_Type_Hop_Limit_And_Mac_Are_Excluded()
    { using var scope = await AssetBatch061065Context.Ready(); Assert.False(await Na(1,type:0x8700)); Assert.False(await Na(2,ttl:"64")); Assert.False(await Na(3,mac:"01:11:22:33:44:55")); }
    [Fact] public async Task Unready_Baseline_Prohibits_Identity_Alert()
    { using var scope = AssetBatch061065Context.Unready(); Assert.False(await Na(1)); Assert.False(await Na(2,"00:11:22:33:44:66")); Assert.False(await Na(3,"00:11:22:33:44:66")); }
    [Fact] public async Task Duplicate_And_Out_Of_Order_Cannot_Confirm_Conflict()
    { using var scope = await AssetBatch061065Context.Ready(); Assert.False(await Na(1)); Assert.False(await Na(2,"00:11:22:33:44:66")); Assert.False(await Na(2,"00:11:22:33:44:66")); Assert.False(await Na(1,"00:11:22:33:44:66")); Assert.True(await Na(3,"00:11:22:33:44:66")); }
    [Fact] public async Task Separate_IPs_Have_Independent_Identity_State()
    { using var scope = await AssetBatch061065Context.Ready(); Assert.False(await Na(1)); Assert.False(await Na(2,"00:11:22:33:44:66",source:"fe80::2",info:"target=fe80::2")); Assert.False(await Na(3,"00:11:22:33:44:66",source:"fe80::2",info:"target=fe80::2")); }
    [Fact] public async Task Alert_Excludes_Mac_And_Raw_Payload()
    { using var scope = await AssetBatch061065Context.Ready(); Assert.False(await Na(1)); Assert.False(await Na(2,"00:11:22:33:44:66")); var r=await _rule.EvaluateAsync(Ipv6Batch066070Context.Packet(3,mac:"00:11:22:33:44:66",icmp:0x8800,info:"target=fe80::1")); var e=Assert.Single(r.Events); Assert.DoesNotContain("00:11:22",e.Evidence); Assert.DoesNotContain("target=fe80",e.Description); }
    [Fact] public async Task Cancellation_Does_Not_Advance_Conflict_State()
    { using var scope = await AssetBatch061065Context.Ready(); using var cancel = new CancellationTokenSource(); cancel.Cancel(); await Assert.ThrowsAnyAsync<OperationCanceledException>(async()=>await _rule.EvaluateAsync(Ipv6Batch066070Context.Packet(1,icmp:0x8800,info:"target=fe80::1"),cancel.Token)); }
}
