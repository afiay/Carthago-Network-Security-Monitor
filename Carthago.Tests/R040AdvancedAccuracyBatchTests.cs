// SPDX-License-Identifier: MIT
using System;
using System.Threading.Tasks;
using Carthago.Engine.Rules;
using Carthago.Engine.Rules.Existing;
using Carthago.Models;
using Carthago.Services;
using Xunit;
namespace Carthago.Tests;

[Collection("Legacy rules R011-R015 isolated")]
public sealed class R040AdvancedAccuracyBatchTests : IDisposable
{
    private readonly R040_LongLivedLowThroughputEncryptedSessionRule _rule = new();
    private static readonly DateTime T0 = new(2026, 10, 27, 6, 0, 0, DateTimeKind.Utc);
    public R040AdvancedAccuracyBatchTests() => RuleEngine.ResetRuntimeStateForReplay();
    public void Dispose() => RuleEngine.ResetRuntimeStateForReplay();
    private async Task<RuleEvaluationResult> See(TrafficRecord r, int seconds = 0)
        => await _rule.EvaluateAsync(new RuleEvaluationContext(r, Sensitivity.Balanced, T0.AddSeconds(seconds)));

    private static TrafficRecord Encrypted(string src = "10.40.0.2", string dst = "8.8.8.8", int bytes = 150)
        => new() { Source = src, Destination = dst, Protocol = "TLS", DestinationPort = 443, Length = bytes };

    [Fact] public async Task Twelve_Sparse_Encrypted_Observations_Across_Fifteen_Minutes_Match()
    {
        for (int i = 0; i < 11; i++) Assert.False((await See(Encrypted(), i * 90)).Matched);
        var e = Assert.Single((await See(Encrypted(), 11 * 90)).Events);
        Assert.Equal("R040", e.RuleId); Assert.Equal(12, e.Count);
        Assert.Equal(990, e.WindowSeconds);
    }

    [Fact] public async Task Eleven_Observations_Without_Full_Minimum_Count_Do_Not_Match()
    {
        for (int i = 0; i < 11; i++) Assert.False((await See(Encrypted(), i * 90)).Matched);
    }

    [Fact] public async Task High_Throughput_Encrypted_Transfers_Are_Not_Low_And_Slow()
    {
        for (int i = 0; i < 12; i++) Assert.False((await See(Encrypted(bytes: 60_000), i * 90)).Matched);
    }

    [Fact] public async Task Tcp_Port_443_Without_Encrypted_Evidence_Is_Not_Sufficient()
    {
        for (int i = 0; i < 12; i++)
        {
            var r = Encrypted(); r.Protocol = "TCP";
            Assert.False((await See(r, i * 90)).Matched);
        }
    }

    [Fact] public async Task Idle_Gap_Resets_The_Lifetime_And_Observation_Count()
    {
        for (int i = 0; i < 6; i++) Assert.False((await See(Encrypted(), i * 90)).Matched);
        for (int i = 0; i < 6; i++) Assert.False((await See(Encrypted(), 1000 + i * 90)).Matched);
    }

    [Fact] public async Task Different_Sources_And_Destinations_Never_Combine_Flows()
    {
        for (int i = 0; i < 6; i++)
        {
            Assert.False((await See(Encrypted(), i * 90)).Matched);
            Assert.False((await See(Encrypted(src: "10.40.0.3"), i * 90)).Matched);
            Assert.False((await See(Encrypted(dst: "9.9.9.9"), i * 90)).Matched);
        }
        for (int i = 6; i < 11; i++) Assert.False((await See(Encrypted(), i * 90)).Matched);
        Assert.Equal(12, Assert.Single((await See(Encrypted(), 990)).Events).Count);
    }

    [Fact] public async Task Duplicates_And_Out_Of_Order_Timestamps_Do_Not_Age_A_Flow()
    {
        for (int i = 0; i < 20; i++) Assert.False((await See(Encrypted(), 0)).Matched);
        Assert.False((await See(Encrypted(), -1)).Matched);
        for (int i = 1; i < 11; i++) Assert.False((await See(Encrypted(), i * 90)).Matched);
        Assert.True((await See(Encrypted(), 990)).Matched);
    }

    [Fact] public async Task Invalid_Private_And_Documentation_Endpoints_Are_Not_Public_C2()
    {
        var bad = new[] { Encrypted(src: "bad"), Encrypted(dst: "10.40.0.3"),
            Encrypted(dst: "203.0.113.7"), Encrypted(src: "8.8.4.4"),
            Encrypted(bytes: 0) };
        foreach (var r in bad)
            for (int i = 0; i < 12; i++) Assert.False((await See(r, i * 90)).Matched);
    }
}
