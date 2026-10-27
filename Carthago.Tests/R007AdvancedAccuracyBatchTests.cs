// SPDX-License-Identifier: MIT
using System;
using System.Threading.Tasks;
using Carthago.Engine.Rules;
using Carthago.Engine.Rules.Existing;
using Carthago.Models;
using Carthago.Services;
using Xunit;

namespace Carthago.Tests;

/// <summary>R007: periodicity, evidence isolation and temporal integrity.</summary>
[Collection("Legacy rules R006-R010 isolated")]
public sealed class R007AdvancedAccuracyBatchTests : IDisposable
{
    private readonly R007_C2BeaconingRule _rule = new();
    private static readonly DateTime T0 = new(2026, 10, 27, 2, 0, 0, DateTimeKind.Utc);
    public R007AdvancedAccuracyBatchTests() => RuleEngine.ResetRuntimeStateForReplay();
    public void Dispose() => RuleEngine.ResetRuntimeStateForReplay();

    private static TrafficRecord Packet(string source = "10.207.0.1",
        string? destination = "8.8.8.8", int port = 443,
        int length = 120, string? protocol = "TCP")
        => new() { Source = source, Destination = destination, DestinationPort = port,
            Protocol = protocol, Length = length };

    private async Task<RuleEvaluationResult> See(TrafficRecord record, int second)
        => await _rule.EvaluateAsync(new RuleEvaluationContext(
            record, Sensitivity.Balanced, T0.AddSeconds(second)));

    [Fact]
    public async Task Perfect_Fifteen_Second_Cadence_Is_Recognized_After_Configured_Six_Samples()
    {
        for (int i = 0; i < 5; i++)
            Assert.False((await See(Packet(), i * 15)).Matched);
        var hit = await See(Packet(), 75);
        var evt = Assert.Single(hit.Events);
        Assert.Equal("R007", evt.RuleId);
        Assert.Equal(6, evt.Count);
        Assert.Equal(75, evt.WindowSeconds);
        Assert.Equal("8.8.8.8", evt.DestinationIp);
    }

    [Fact]
    public async Task Five_Perfect_Samples_Are_Not_Sufficient_Despite_Long_Observation()
    {
        foreach (var second in new[] { 0, 20, 40, 60, 80 })
            Assert.False((await See(Packet(), second)).Matched);
        Assert.Equal(6, Assert.Single((await See(Packet(), 100)).Events).Count);
    }

    [Fact]
    public async Task Irregular_Bursty_Intervals_Are_Not_Declared_Periodic()
    {
        foreach (var second in new[] { 0, 1, 3, 7, 15, 31, 63, 127 })
            Assert.False((await See(Packet(), second)).Matched);
    }

    [Fact]
    public async Task Regular_Bulk_Transfers_Are_Not_Small_Payload_Beacons()
    {
        for (int i = 0; i < 10; i++)
            Assert.False((await See(Packet(length: 5000), i * 15)).Matched);
    }

    [Fact]
    public async Task Private_Documentation_And_Unknown_Destinations_Cannot_Prime_Public_Cadence()
    {
        foreach (var destination in new string?[] { null, "10.1.1.1", "198.51.100.9", "example.invalid" })
            for (int i = 0; i < 6; i++)
                Assert.False((await See(Packet(destination: destination), i * 15)).Matched);
        for (int i = 0; i < 5; i++)
            Assert.False((await See(Packet(), i * 15)).Matched);
        Assert.Equal(6, Assert.Single((await See(Packet(), 75)).Events).Count);
    }

    [Fact]
    public async Task Independent_Service_Ports_Do_Not_Combine_Their_Cadence()
    {
        for (int i = 0; i < 5; i++)
        {
            Assert.False((await See(Packet(port: 443), i * 15)).Matched);
            Assert.False((await See(Packet(port: 8443), i * 15)).Matched);
        }
        var first = await See(Packet(port: 443), 75);
        Assert.Equal(443, Assert.Single(first.Events).DestinationPort);
        var second = await See(Packet(port: 8443), 75);
        Assert.Equal(8443, Assert.Single(second.Events).DestinationPort);
    }

    [Fact]
    public async Task Future_Dated_Sample_Does_Not_Preload_Current_Beacon_Window()
    {
        Assert.False((await See(Packet(), 1000)).Matched);
        for (int i = 0; i < 5; i++)
            Assert.False((await See(Packet(), i * 15)).Matched);
        Assert.Equal(6, Assert.Single((await See(Packet(), 75)).Events).Count);
    }

    [Fact]
    public async Task Empty_Or_Unattributed_Records_Do_Not_Become_Beacon_Samples()
    {
        var noSource = Packet(); noSource.Source = null;
        var noProtocol = Packet(protocol: null);
        var noBytes = Packet(length: 0);
        var noPort = Packet(); noPort.DestinationPort = null;
        var invalidPort = Packet(); invalidPort.DestinationPort = 65536;
        foreach (var record in new[] { noSource, noProtocol, noBytes, noPort, invalidPort })
            Assert.False((await See(record, 0)).Matched);
        for (int i = 0; i < 5; i++)
            Assert.False((await See(Packet(), i * 15)).Matched);
        Assert.True((await See(Packet(), 75)).Matched);
    }
}
