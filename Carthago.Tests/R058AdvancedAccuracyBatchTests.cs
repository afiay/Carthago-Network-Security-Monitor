// SPDX-License-Identifier: MIT
using System;
using System.Threading;
using System.Threading.Tasks;
using Carthago.Engine.Rules.AssetInventory;
using Xunit;

namespace Carthago.Tests;

public sealed class R058AdvancedAccuracyBatchTests
{
    private readonly R058_NewMACVendorSeenRule _rule = new();
    private async Task<bool> Seen(int second, string mac)
        => (await _rule.EvaluateAsync(AssetBatch056060Context.At(second, mac: mac))).Matched;

    [Fact] public async Task New_Global_Oui_After_Initial_Baseline_Needs_Two_Claims()
    {
        Assert.False(await Seen(0, AssetBatch056060Context.VendorA));
        Assert.False(await Seen(1, AssetBatch056060Context.VendorB));
        var evt = Assert.Single((await _rule.EvaluateAsync(AssetBatch056060Context.At(2,
            mac: AssetBatch056060Context.VendorB))).Events);
        Assert.Equal("R058", evt.RuleId);
        Assert.Contains("prefix", evt.Summary);
    }
    [Fact] public async Task First_Baseline_Oui_Is_Not_A_Novel_Vendor_Incident()
    {
        Assert.False(await Seen(0, AssetBatch056060Context.VendorA));
        Assert.False(await Seen(1, AssetBatch056060Context.VendorA));
    }
    [Fact] public async Task Multiple_Macs_With_Same_Oui_Are_Not_Distinct_Vendors()
    {
        Assert.False(await Seen(0, AssetBatch056060Context.VendorA));
        Assert.False(await Seen(1, AssetBatch056060Context.VendorB));
        Assert.True(await Seen(2, AssetBatch056060Context.VendorB2));
        Assert.False(await Seen(3, AssetBatch056060Context.VendorB));
    }
    [Fact] public async Task Locally_Administered_Macs_Cannot_Claim_A_Vendor_Oui()
    {
        Assert.False(await Seen(0, AssetBatch056060Context.MacA));
        Assert.False(await Seen(1, AssetBatch056060Context.MacA));
        Assert.False(await Seen(2, AssetBatch056060Context.VendorA));
        Assert.False(await Seen(3, AssetBatch056060Context.VendorA));
    }
    [Fact] public async Task Duplicate_Timestamps_Do_Not_Confirm_New_Oui()
    {
        Assert.False(await Seen(0, AssetBatch056060Context.VendorA));
        Assert.False(await Seen(1, AssetBatch056060Context.VendorB));
        Assert.False(await Seen(1, AssetBatch056060Context.VendorB));
        Assert.True(await Seen(2, AssetBatch056060Context.VendorB));
    }
    [Fact] public async Task Contradictory_Claim_Does_Not_Seed_New_Oui()
    {
        Assert.False(await Seen(0, AssetBatch056060Context.VendorA));
        var bad = AssetBatch056060Context.At(1, mac: AssetBatch056060Context.VendorB,
            headerMac: AssetBatch056060Context.VendorA);
        Assert.False((await _rule.EvaluateAsync(bad)).Matched);
        Assert.False(await Seen(2, AssetBatch056060Context.VendorB));
        Assert.True(await Seen(3, AssetBatch056060Context.VendorB));
    }
    [Fact] public async Task Alert_Redacts_Both_Full_Mac_And_Oui()
    {
        Assert.False(await Seen(0, AssetBatch056060Context.VendorA));
        Assert.False(await Seen(1, AssetBatch056060Context.VendorB));
        var evt = Assert.Single((await _rule.EvaluateAsync(AssetBatch056060Context.At(2,
            mac: AssetBatch056060Context.VendorB))).Events);
        Assert.DoesNotContain(AssetBatch056060Context.VendorB, evt.Description);
        Assert.DoesNotContain("04:33:44", evt.Evidence);
    }
    [Fact] public async Task Non_Arp_And_Malformed_Mac_Are_Not_Vendor_Evidence()
    {
        Assert.False((await _rule.EvaluateAsync(AssetBatch056060Context.At(0,
            mac: "00:ZZ:22:33:44:55"))).Matched);
        Assert.False((await _rule.EvaluateAsync(AssetBatch056060Context.At(0,
            mac: AssetBatch056060Context.VendorA, protocol: "TCP"))).Matched);
    }
    [Fact] public async Task Expired_Novelty_Requires_Two_Fresh_Claims()
    {
        Assert.False(await Seen(0, AssetBatch056060Context.VendorA));
        Assert.False(await Seen(1, AssetBatch056060Context.VendorB));
        Assert.False(await Seen(200, AssetBatch056060Context.VendorB));
        Assert.True(await Seen(201, AssetBatch056060Context.VendorB));
    }
    [Fact] public async Task Cancellation_Prevents_Vendor_Observation()
    {
        using var cts = new CancellationTokenSource(); cts.Cancel();
        await Assert.ThrowsAnyAsync<OperationCanceledException>(async () =>
            await _rule.EvaluateAsync(AssetBatch056060Context.At(0,
                mac: AssetBatch056060Context.VendorA), cts.Token));
        Assert.False(await Seen(1, AssetBatch056060Context.VendorA));
    }
}
