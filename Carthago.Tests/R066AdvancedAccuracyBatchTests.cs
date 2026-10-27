// SPDX-License-Identifier: MIT
using System;
using System.Threading;
using System.Threading.Tasks;
using Carthago.Engine.Rules.AssetInventory;
using Xunit;

namespace Carthago.Tests;

public sealed class R066AdvancedAccuracyBatchTests
{
    private readonly R066_FirstTimeCountryForHostRule _rule = new();
    private async Task<bool> Seen(int s, string? country, string source = "10.66.0.10",
        string destination = "8.8.8.8", string? whois = null)
        => (await _rule.EvaluateAsync(Ipv6Batch066070Context.Country(s, country, source, destination, whois))).Matched;
    private async Task Warm()
    {
        Assert.False(await Seen(1, "SE"));
        Assert.False(await Seen(2, "NO"));
        Assert.False(await Seen(3, "FI"));
    }

    [Fact] public async Task Ready_Baseline_Requires_Two_Observations_Of_New_Country()
    { using var scope = await AssetBatch061065Context.Ready(); await Warm(); Assert.False(await Seen(4, "DE")); Assert.True(await Seen(5, "de")); }
    [Fact] public async Task First_Country_And_Single_Novel_Country_Do_Not_Alert()
    { using var scope = await AssetBatch061065Context.Ready(); await Warm(); Assert.False(await Seen(4, "DE")); }
    [Fact] public async Task Unknown_And_Malformed_Country_Do_Not_Seed_Baseline()
    { using var scope = await AssetBatch061065Context.Ready(); foreach(var x in new[] { "ZZ", "EU", "Germany", "1A", "" }) Assert.False(await Seen(1, x)); }
    [Fact] public async Task Contradictory_Geo_And_Whois_Are_Rejected()
    { using var scope = await AssetBatch061065Context.Ready(); await Warm(); Assert.False(await Seen(4, "DE", whois: "FR")); Assert.False(await Seen(5, "DE", whois: "FR")); }
    [Fact] public async Task Private_Destination_Does_Not_Seed_Novelty()
    { using var scope = await AssetBatch061065Context.Ready(); await Warm(); Assert.False(await Seen(4, "DE", destination: "10.66.0.50")); Assert.False(await Seen(5, "DE", destination: "10.66.0.50")); }
    [Fact] public async Task Duplicate_And_Out_Of_Order_Timestamps_Do_Not_Confirm()
    { using var scope = await AssetBatch061065Context.Ready(); await Warm(); Assert.False(await Seen(4, "DE")); Assert.False(await Seen(4, "DE")); Assert.False(await Seen(2, "DE")); Assert.True(await Seen(5, "DE")); }
    [Fact] public async Task Host_State_Isolated_And_Unready_Baseline_Fails_Closed()
    { using var scope = AssetBatch061065Context.Unready(); Assert.False(await Seen(1, "SE")); Assert.False(await Seen(2, "NO")); Assert.False(await Seen(3, "FI")); Assert.False(await Seen(4, "DE")); Assert.False(await Seen(5, "DE")); }
    [Fact] public async Task Alert_Does_Not_Expose_Country_Or_Raw_Info()
    { using var scope = await AssetBatch061065Context.Ready(); await Warm(); Assert.False(await Seen(4, "DE")); var result = await _rule.EvaluateAsync(Ipv6Batch066070Context.Country(5, "DE", info: "private-payload")); var e = Assert.Single(result.Events); Assert.DoesNotContain("DE", e.Summary); Assert.DoesNotContain("private-payload", e.Evidence); }
    [Fact] public async Task Cancelled_Observation_Does_Not_Write_Baseline()
    { using var scope = await AssetBatch061065Context.Ready(); using var cancel = new CancellationTokenSource(); cancel.Cancel(); await Assert.ThrowsAnyAsync<OperationCanceledException>(async () => await _rule.EvaluateAsync(Ipv6Batch066070Context.Country(1, "SE"), cancel.Token)); }
}
