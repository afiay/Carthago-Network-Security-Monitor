// SPDX-License-Identifier: MIT
using System;
using System.Threading;
using System.Threading.Tasks;
using Carthago.Engine.Rules.AssetInventory;
using Xunit;

namespace Carthago.Tests;

public sealed class R060AdvancedAccuracyBatchTests
{
    private readonly R060_SameIPUsedByMultipleMACsRule _rule = new();
    private async Task<bool> Seen(int second, string ip = "10.56.0.10",
        string mac = AssetBatch056060Context.MacA)
        => (await _rule.EvaluateAsync(AssetBatch056060Context.At(second, ip, mac))).Matched;

    [Fact] public async Task Repeated_Alternate_Mac_Claims_Confirm_Ip_Conflict()
    {
        Assert.False(await Seen(0));
        Assert.False(await Seen(1, mac: AssetBatch056060Context.MacB));
        var evt = Assert.Single((await _rule.EvaluateAsync(
            AssetBatch056060Context.At(2, mac: AssetBatch056060Context.MacB))).Events);
        Assert.Equal("R060", evt.RuleId);
        Assert.Equal("10.56.0.10", evt.SourceIp);
    }
    [Fact] public async Task Single_Mac_Claimant_Is_Benign()
    {
        Assert.False(await Seen(0));
        Assert.False(await Seen(1));
        Assert.False(await Seen(2));
    }
    [Fact] public async Task Single_Alternate_Mac_Cannot_Confirm_Conflict()
    {
        Assert.False(await Seen(0));
        Assert.False(await Seen(1, mac: AssetBatch056060Context.MacB));
    }
    [Fact] public async Task Baseline_Reassertion_Cancels_Unconfirmed_Mac()
    {
        Assert.False(await Seen(0));
        Assert.False(await Seen(1, mac: AssetBatch056060Context.MacB));
        Assert.False(await Seen(2));
        Assert.False(await Seen(3, mac: AssetBatch056060Context.MacB));
        Assert.True(await Seen(4, mac: AssetBatch056060Context.MacB));
    }
    [Fact] public async Task Duplicate_Timestamp_Does_Not_Confirm_New_Mac()
    {
        Assert.False(await Seen(0));
        Assert.False(await Seen(1, mac: AssetBatch056060Context.MacB));
        Assert.False(await Seen(1, mac: AssetBatch056060Context.MacB));
        Assert.True(await Seen(2, mac: AssetBatch056060Context.MacB));
    }
    [Fact] public async Task Separate_Ips_Cannot_Poison_One_Another()
    {
        Assert.False(await Seen(0));
        Assert.False(await Seen(0, ip: "10.56.0.20"));
        Assert.False(await Seen(1, mac: AssetBatch056060Context.MacB));
        Assert.False(await Seen(1, "10.56.0.20", AssetBatch056060Context.MacC));
        Assert.True(await Seen(2, mac: AssetBatch056060Context.MacB));
        Assert.True(await Seen(2, "10.56.0.20", AssetBatch056060Context.MacC));
    }
    [Fact] public async Task Contradictory_Arp_And_Multicast_Mac_Cannot_Seed_State()
    {
        var bad = AssetBatch056060Context.At(0,
            mac: AssetBatch056060Context.MacB,
            headerMac: AssetBatch056060Context.MacA);
        Assert.False((await _rule.EvaluateAsync(bad)).Matched);
        Assert.False(await Seen(0, mac: "01:11:22:33:44:55"));
        Assert.False(await Seen(1));
        Assert.False(await Seen(2, mac: AssetBatch056060Context.MacB));
        Assert.True(await Seen(3, mac: AssetBatch056060Context.MacB));
    }
    [Fact] public async Task Stale_Conflict_Does_Not_Immediately_Alert()
    {
        Assert.False(await Seen(0));
        Assert.False(await Seen(1, mac: AssetBatch056060Context.MacB));
        Assert.False(await Seen(1802, mac: AssetBatch056060Context.MacC));
        Assert.False(await Seen(1803, mac: AssetBatch056060Context.MacB));
        Assert.True(await Seen(1804, mac: AssetBatch056060Context.MacB));
    }
    [Fact] public async Task Mac_Values_Are_Redacted_And_No_Attack_Is_Asserted()
    {
        Assert.False(await Seen(0));
        Assert.False(await Seen(1, mac: AssetBatch056060Context.MacB));
        var evt = Assert.Single((await _rule.EvaluateAsync(
            AssetBatch056060Context.At(2, mac: AssetBatch056060Context.MacB))).Events);
        Assert.DoesNotContain(AssetBatch056060Context.MacA, evt.Evidence);
        Assert.DoesNotContain(AssetBatch056060Context.MacB, evt.Description);
        Assert.DoesNotContain("malicious", evt.Summary, StringComparison.OrdinalIgnoreCase);
    }
    [Fact] public async Task Cancellation_Prevents_Conflict_Observation()
    {
        using var cts = new CancellationTokenSource(); cts.Cancel();
        await Assert.ThrowsAnyAsync<OperationCanceledException>(async () =>
            await _rule.EvaluateAsync(AssetBatch056060Context.At(), cts.Token));
        Assert.False(await Seen(1));
    }
}
