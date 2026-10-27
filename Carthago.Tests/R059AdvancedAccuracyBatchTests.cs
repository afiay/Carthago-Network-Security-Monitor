// SPDX-License-Identifier: MIT
using System;
using System.Threading;
using System.Threading.Tasks;
using Carthago.Engine.Rules.AssetInventory;
using Xunit;

namespace Carthago.Tests;

public sealed class R059AdvancedAccuracyBatchTests
{
    private readonly R059_SameMACUsingMultipleIPsRule _rule = new();
    private async Task<bool> Seen(int second, string ip = "10.56.0.10",
        string mac = AssetBatch056060Context.MacA)
        => (await _rule.EvaluateAsync(AssetBatch056060Context.At(second, ip, mac))).Matched;

    [Fact] public async Task Two_Corroborated_Alternate_Ip_Claims_Confirm_Inventory_Conflict()
    {
        Assert.False(await Seen(0));
        Assert.False(await Seen(1, "10.56.0.11"));
        var evt = Assert.Single((await _rule.EvaluateAsync(
            AssetBatch056060Context.At(2, "10.56.0.11"))).Events);
        Assert.Equal("R059", evt.RuleId);
        Assert.Equal("10.56.0.11", evt.SourceIp);
        Assert.Equal(2, evt.Count);
    }
    [Fact] public async Task Repeated_Same_Ip_Is_Normal()
    {
        Assert.False(await Seen(0));
        Assert.False(await Seen(1));
        Assert.False(await Seen(2));
    }
    [Fact] public async Task Single_Alternate_Ip_Cannot_Confirm_A_Conflict()
    {
        Assert.False(await Seen(0));
        Assert.False(await Seen(1, "10.56.0.11"));
    }
    [Fact] public async Task Baseline_Reassertion_Cancels_Unconfirmed_Alternate()
    {
        Assert.False(await Seen(0));
        Assert.False(await Seen(1, "10.56.0.11"));
        Assert.False(await Seen(2));
        Assert.False(await Seen(3, "10.56.0.11"));
        Assert.True(await Seen(4, "10.56.0.11"));
    }
    [Fact] public async Task Duplicate_And_Out_Of_Order_Claims_Cannot_Confirm()
    {
        Assert.False(await Seen(0));
        Assert.False(await Seen(2, "10.56.0.11"));
        Assert.False(await Seen(2, "10.56.0.11"));
        Assert.False(await Seen(1, "10.56.0.11"));
        Assert.True(await Seen(3, "10.56.0.11"));
    }
    [Fact] public async Task Independent_Macs_Have_Separate_Ip_Histories()
    {
        Assert.False(await Seen(0));
        Assert.False(await Seen(0, "10.56.0.20", AssetBatch056060Context.MacB));
        Assert.False(await Seen(1, "10.56.0.11"));
        Assert.False(await Seen(1, "10.56.0.21", AssetBatch056060Context.MacB));
        Assert.True(await Seen(2, "10.56.0.11"));
        Assert.True(await Seen(2, "10.56.0.21", AssetBatch056060Context.MacB));
    }
    [Fact] public async Task Stale_Alternate_Requires_New_Corroboration()
    {
        Assert.False(await Seen(0));
        Assert.False(await Seen(1, "10.56.0.11"));
        Assert.False(await Seen(200, "10.56.0.11"));
        Assert.True(await Seen(201, "10.56.0.11"));
    }
    [Fact] public async Task Untrusted_Public_Ip_And_Contradictory_Arp_Are_Excluded()
    {
        Assert.False(await Seen(0, "8.8.8.8"));
        var bad = AssetBatch056060Context.At(0, ip: "10.56.0.11",
            info: "ARP reply 10.56.0.99 is-at 02:11:22:33:44:55");
        Assert.False((await _rule.EvaluateAsync(bad)).Matched);
        Assert.False(await Seen(1));
        Assert.False(await Seen(2, "10.56.0.11"));
        Assert.True(await Seen(3, "10.56.0.11"));
    }
    [Fact] public async Task Alert_Does_Not_Expose_Hardware_Identifiers()
    {
        Assert.False(await Seen(0));
        Assert.False(await Seen(1, "10.56.0.11"));
        var evt = Assert.Single((await _rule.EvaluateAsync(
            AssetBatch056060Context.At(2, "10.56.0.11"))).Events);
        Assert.DoesNotContain(AssetBatch056060Context.MacA, evt.Description);
        Assert.DoesNotContain(AssetBatch056060Context.MacA, evt.Evidence);
    }
    [Fact] public async Task Cancellation_Does_Not_Seed_State()
    {
        using var cts = new CancellationTokenSource(); cts.Cancel();
        await Assert.ThrowsAnyAsync<OperationCanceledException>(async () =>
            await _rule.EvaluateAsync(AssetBatch056060Context.At(), cts.Token));
        Assert.False(await Seen(1));
    }
}
