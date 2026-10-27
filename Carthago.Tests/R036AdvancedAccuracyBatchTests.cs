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
public sealed class R036AdvancedAccuracyBatchTests : IDisposable
{
    private readonly R036_HeavyEgressToSingleExternalHostRule _rule = new();
    private static readonly DateTime T0 = new(2026, 10, 27, 6, 0, 0, DateTimeKind.Utc);
    public R036AdvancedAccuracyBatchTests() => RuleEngine.ResetRuntimeStateForReplay();
    public void Dispose() => RuleEngine.ResetRuntimeStateForReplay();
    private async Task<RuleEvaluationResult> See(TrafficRecord r, int seconds = 0)
        => await _rule.EvaluateAsync(new RuleEvaluationContext(r, Sensitivity.Balanced, T0.AddSeconds(seconds)));

    private static TrafficRecord Packet(string src = "10.36.0.2", string dst = "8.8.8.8", int bytes = 2_100_000)
        => new() { Source = src, Destination = dst, Protocol = "TLS", DestinationPort = 443, Length = bytes };

    [Fact] public async Task Ten_Observed_Outbound_Packets_Reach_Existing_Twenty_Megabyte_Threshold()
    {
        for (int i = 0; i < 9; i++) Assert.False((await See(Packet(), i)).Matched);
        var e = Assert.Single((await See(Packet(), 9)).Events);
        Assert.Equal("R036", e.RuleId); Assert.Equal(21_000_000, e.Count);
        Assert.Equal(120, e.WindowSeconds); Assert.Equal("10.36.0.2", e.SourceIp);
    }

    [Fact] public async Task Large_But_Subthreshold_Authorized_Transfer_Is_Not_Enough()
    {
        for (int i = 0; i < 9; i++) Assert.False((await See(Packet(), i)).Matched);
        Assert.False((await See(Packet(dst: "9.9.9.9"), 9)).Matched);
    }

    [Fact] public async Task Private_Documentation_And_Invalid_Destinations_Cannot_Seed_Exfiltration()
    {
        foreach (string dst in new[] { "10.36.1.3", "192.0.2.1", "203.0.113.7", "127.0.0.1", "bad" })
            for (int i = 0; i < 12; i++) Assert.False((await See(Packet(dst: dst), i)).Matched);
        Assert.False((await See(Packet(src: "bad"), 20)).Matched);
        Assert.False((await See(Packet(src: "8.8.4.4"), 21)).Matched);
        Assert.False((await See(Packet(bytes: 0), 22)).Matched);
    }

    [Fact] public async Task Different_Source_And_Destination_Pairs_Do_Not_Aggregate()
    {
        for (int i = 0; i < 9; i++)
        {
            Assert.False((await See(Packet(), i)).Matched);
            Assert.False((await See(Packet(src: "10.36.0.3"), i)).Matched);
            Assert.False((await See(Packet(dst: "9.9.9.9"), i)).Matched);
        }
        Assert.Equal(21_000_000, Assert.Single((await See(Packet(), 9)).Events).Count);
    }

    [Fact] public async Task Expired_Window_And_Out_Of_Order_Records_Do_Not_Complete_A_Transfer()
    {
        for (int i = 0; i < 9; i++) Assert.False((await See(Packet(), i)).Matched);
        Assert.False((await See(Packet(), 130)).Matched);
        Assert.False((await See(Packet(), 2)).Matched);
    }

    [Fact] public async Task Indistinguishable_Duplicate_Timestamps_Do_Not_Inflate_Bytes()
    {
        for (int i = 0; i < 30; i++) Assert.False((await See(Packet(), 0)).Matched);
        for (int i = 1; i < 9; i++) Assert.False((await See(Packet(), i)).Matched);
        Assert.Equal(21_000_000, Assert.Single((await See(Packet(), 9)).Events).Count);
    }

    [Fact] public async Task Suppressed_Completed_Window_Cannot_Prime_Next_Transfer()
    {
        for (int i = 0; i < 10; i++) await See(Packet(), i);
        for (int i = 10; i < 19; i++) Assert.False((await See(Packet(), i)).Matched);
        Assert.True((await See(Packet(), 19)).Suppressed);
        Assert.False((await See(Packet(), 20)).Matched);
    }

    [Fact] public async Task Very_Large_Single_Observation_Clamps_The_Alert_Count()
    {
        var e = Assert.Single((await See(Packet(bytes: int.MaxValue))).Events);
        Assert.Equal(int.MaxValue, e.Count);
    }
}
