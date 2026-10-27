// SPDX-License-Identifier: MIT
using System;
using System.Threading;
using System.Threading.Tasks;
using Carthago.Engine.Rules.AssetInventory;
using Xunit;

namespace Carthago.Tests;

public sealed class R057AdvancedAccuracyBatchTests
{
    private readonly R057_NewDeviceAppearedOnNetworkRule _rule = new();
    private async Task<bool> Seen(int seconds, string mac = AssetBatch056060Context.MacA,
        string ip = "10.56.0.10")
        => (await _rule.EvaluateAsync(AssetBatch056060Context.At(seconds, ip, mac))).Matched;

    [Fact] public async Task Two_Distinct_Local_Arp_Claims_Confirm_First_Observed_Device()
    {
        Assert.False(await Seen(0));
        var evt = Assert.Single((await _rule.EvaluateAsync(AssetBatch056060Context.At(1))).Events);
        Assert.Equal("R057", evt.RuleId);
        Assert.Equal("10.56.0.10", evt.SourceIp);
        Assert.Equal(2, evt.Count);
    }
    [Fact] public async Task Single_Claim_Does_Not_Prove_A_New_Device()
    {
        Assert.False(await Seen(0));
    }
    [Fact] public async Task Same_Timestamp_Replays_Do_Not_Confirm()
    {
        Assert.False(await Seen(0));
        Assert.False(await Seen(0));
        Assert.True(await Seen(1));
    }
    [Fact] public async Task Contradictory_Ethernet_Header_Cannot_Prime_State()
    {
        var bad = AssetBatch056060Context.At(0, headerMac: AssetBatch056060Context.MacB);
        Assert.False((await _rule.EvaluateAsync(bad)).Matched);
        Assert.False(await Seen(1));
        Assert.True(await Seen(2));
    }
    [Fact] public async Task Non_Arp_Traffic_And_Public_Addresses_Cannot_Prime_State()
    {
        Assert.False((await _rule.EvaluateAsync(AssetBatch056060Context.At(0,
            protocol: "TCP"))).Matched);
        Assert.False((await _rule.EvaluateAsync(AssetBatch056060Context.At(0,
            ip: "8.8.8.8"))).Matched);
        Assert.False(await Seen(1));
        Assert.True(await Seen(2));
    }
    [Fact] public async Task Idle_Device_Requires_Fresh_Confirmation()
    {
        Assert.False(await Seen(0));
        Assert.False(await Seen(1801));
        Assert.True(await Seen(1802));
    }
    [Fact] public async Task Independent_Devices_Are_Not_Conflated()
    {
        Assert.False(await Seen(0));
        Assert.False(await Seen(0, AssetBatch056060Context.MacB));
        Assert.True(await Seen(1));
        Assert.True(await Seen(1, AssetBatch056060Context.MacB));
    }
    [Fact] public async Task Mac_Identifiers_Are_Not_Exposed_In_Alerts()
    {
        Assert.False(await Seen(0));
        var evt = Assert.Single((await _rule.EvaluateAsync(AssetBatch056060Context.At(1))).Events);
        Assert.DoesNotContain(AssetBatch056060Context.MacA, evt.Description);
        Assert.DoesNotContain(AssetBatch056060Context.MacA, evt.Evidence);
        Assert.DoesNotContain("unauthorized", evt.Summary, StringComparison.OrdinalIgnoreCase);
    }
    [Fact] public async Task Cancellation_Does_Not_Update_Inventory()
    {
        using var cts = new CancellationTokenSource(); cts.Cancel();
        await Assert.ThrowsAnyAsync<OperationCanceledException>(async () =>
            await _rule.EvaluateAsync(AssetBatch056060Context.At(), cts.Token));
        Assert.False(await Seen(1));
    }
}
