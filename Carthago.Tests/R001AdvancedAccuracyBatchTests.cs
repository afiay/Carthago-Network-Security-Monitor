// SPDX-License-Identifier: MIT
using System;
using System.Threading.Tasks;
using Carthago.Engine.Rules;
using Carthago.Engine.Rules.Existing;
using Carthago.Models;
using Carthago.Services;
using Xunit;

namespace Carthago.Tests;

/// <summary>R001 batch gate: five advanced multi-observation boundary scenarios.</summary>
[Collection("Legacy rules R001-R005 isolated")]
public sealed class R001AdvancedAccuracyBatchTests : IDisposable
{
    private readonly R001_PortScanRule _rule = new();
    private static readonly DateTime Origin = new(2026, 10, 26, 10, 0, 0, DateTimeKind.Utc);
    public R001AdvancedAccuracyBatchTests() => RuleEngine.ResetRuntimeStateForReplay();
    public void Dispose() => RuleEngine.ResetRuntimeStateForReplay();

    private static TrafficRecord Tcp(int port, string flags = "SYN",
        string source = "10.251.1.1", string dest = "10.251.2.1")
        => new() { Source = source, Destination = dest, DestinationPort = port,
            Protocol = "TCP", Flags = flags, Length = 60 };

    private async Task<RuleEvaluationResult> See(TrafficRecord record, int second)
        => await _rule.EvaluateAsync(new RuleEvaluationContext(
            record, Sensitivity.Balanced, Origin.AddSeconds(second)));

    [Fact]
    public async Task Eight_Configured_Unique_Syn_Ports_Detect_Exactly_One_Attributed_Scan()
    {
        // The checked-in rules.json explicitly sets PortScanThreshold=8.
        // The detector must not alert at its lower built-in fallback of five.
        for (var i = 0; i < 7; i++)
            Assert.False((await See(Tcp(27000 + i), i)).Matched);
        var hit = await See(Tcp(27007), 7);
        Assert.True(hit.Matched);
        var evt = Assert.Single(hit.Events);
        Assert.Equal("R001", evt.RuleId);
        Assert.Equal(8, evt.Count);
        Assert.Equal("10.251.1.1", evt.SourceIp);
        Assert.Equal("10.251.2.1", evt.DestinationIp);
        Assert.Equal(27007, evt.DestinationPort);
    }

    [Fact]
    public async Task Future_Dated_Packet_Cannot_Preload_A_Current_Scan_Window()
    {
        Assert.False((await See(Tcp(28000), 500)).Matched);
        for (var i = 0; i < 7; i++)
            Assert.False((await See(Tcp(28001 + i), i)).Matched);
        var result = await See(Tcp(28008), 7);
        Assert.True(result.Matched);
        Assert.Equal(8, Assert.Single(result.Events).Count);
    }

    [Fact]
    public async Task Tcp_Retries_And_Noninitial_Flags_Are_Not_Unique_Probe_Ports()
    {
        for (var i = 0; i < 12; i++)
        {
            Assert.False((await See(Tcp(29000, "SYN"), i)).Matched);
            Assert.False((await See(Tcp(29001 + i, "ACK"), i)).Matched);
            Assert.False((await See(Tcp(29100 + i, "SYN,ACK"), i)).Matched);
        }
        for (var i = 0; i < 6; i++)
            Assert.False((await See(Tcp(29002 + i), 14 + i)).Matched);
        var hit = await See(Tcp(29008), 20);
        Assert.True(hit.Matched);
        Assert.Equal(8, Assert.Single(hit.Events).Count);
    }

    [Fact]
    public async Task Invalid_Ports_Cannot_Become_Scan_Observations_Or_Prime_State()
    {
        foreach (var port in new[] { int.MinValue, -1, 0, 65536, int.MaxValue })
            Assert.False((await See(Tcp(port), 0)).Matched);
        for (var i = 0; i < 4; i++)
            Assert.False((await See(Tcp(30000 + i), i + 1)).Matched);
        for (var i = 4; i < 7; i++)
            Assert.False((await See(Tcp(30000 + i), i + 1)).Matched);
        var hit = await See(Tcp(30007), 8);
        Assert.True(hit.Matched);
        Assert.Equal(8, Assert.Single(hit.Events).Count);
    }

    [Fact]
    public async Task Per_Source_Destination_Isolation_Holds_Across_Interleaved_Probes()
    {
        for (var i = 0; i < 4; i++)
        {
            Assert.False((await See(Tcp(31000 + i, source: "10.251.1.9", dest: "10.251.2.9"), i)).Matched);
            Assert.False((await See(Tcp(31000 + i, source: "10.251.1.9", dest: "10.251.2.10"), i)).Matched);
            Assert.False((await See(Tcp(31000 + i, source: "10.251.1.10", dest: "10.251.2.9"), i)).Matched);
        }
        for (var i = 4; i < 7; i++)
            Assert.False((await See(Tcp(31000 + i, source: "10.251.1.9", dest: "10.251.2.9"), i)).Matched);
        var result = await See(Tcp(31007, source: "10.251.1.9", dest: "10.251.2.9"), 7);
        Assert.True(result.Matched);
        Assert.Equal("10.251.1.9", Assert.Single(result.Events).SourceIp);
        Assert.Equal(8, result.Events[0].Count);
    }
}
