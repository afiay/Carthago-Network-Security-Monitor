// SPDX-License-Identifier: MIT
using System;
using System.Threading.Tasks;
using Carthago.Engine.Rules;
using Carthago.Engine.Rules.Existing;
using Carthago.Models;
using Carthago.Services;
using Xunit;

namespace Carthago.Tests;

[Collection("Legacy rules R001-R005 isolated")]
public sealed class R002Tests : IDisposable
{
    private static readonly DateTime T0 = new(2026, 10, 26, 10, 0, 0, DateTimeKind.Utc);
    private readonly R002_FloodDosRule _rule = new();

    public R002Tests() => RuleEngine.ResetRuntimeStateForReplay();
    public void Dispose() => RuleEngine.ResetRuntimeStateForReplay();

    private static TrafficRecord Packet(string src, string dst, int bytes, string flags)
        => new()
        {
            Source = src, Destination = dst, SourcePort = 54500,
            DestinationPort = 443, Protocol = "TCP", Flags = flags,
            Length = bytes
        };

    private async Task<RuleEvaluationResult> Evaluate(TrafficRecord record, int milliseconds)
        => await _rule.EvaluateAsync(new RuleEvaluationContext(
            record, Sensitivity.Balanced, T0.AddMilliseconds(milliseconds)));

    [Fact]
    public async Task Dense_Syn_And_Byte_Burst_Produces_Exactly_One_Attributed_R002()
    {
        for (var i = 0; i < 4; i++)
            Assert.False((await Evaluate(Packet("10.242.0.1", "10.242.1.1", 270000, "SYN"), i * 100)).Matched);

        var result = await Evaluate(Packet("10.242.0.1", "10.242.1.1", 270000, "SYN"), 400);
        Assert.True(result.Matched);
        var evt = Assert.Single(result.Events);
        Assert.Equal("R002", evt.RuleId);
        Assert.Equal("10.242.0.1", evt.SourceIp);
        Assert.Equal("10.242.1.1", evt.DestinationIp);
        Assert.Equal(5, evt.Count);
        Assert.Equal(10, evt.WindowSeconds);
    }

    [Fact]
    public async Task Balanced_Syn_And_Ack_During_High_Throughput_Is_Not_A_Syn_Flood()
    {
        for (var i = 0; i < 8; i++)
        {
            Assert.False((await Evaluate(Packet("10.242.0.2", "10.242.1.2", 180000, "SYN"), i * 200)).Matched);
            Assert.False((await Evaluate(Packet("10.242.0.2", "10.242.1.2", 180000, "ACK"), i * 200 + 30)).Matched);
        }
    }

    [Fact]
    public async Task Small_Packets_Do_Not_Breach_The_Byte_Evidence_Gate()
    {
        for (var i = 0; i < 16; i++)
            Assert.False((await Evaluate(Packet("10.242.0.3", "10.242.1.3", 60, "SYN"), i * 50)).Matched);
    }

    [Fact]
    public async Task Bursts_Against_Different_Destinations_Are_Not_A_Single_Host_DoS()
    {
        for (var i = 0; i < 8; i++)
        {
            // Scanning many destinations is not the same as exhausting one
            // destination service; R001/R017 cover scans separately.
            Assert.False((await Evaluate(Packet("10.242.0.4", "10.242.1." + (20 + i), 270000, "SYN"), i * 50)).Matched);
        }
    }

    [Fact]
    public async Task Separate_Sources_Do_Not_Combine_Into_One_Source_Flood()
    {
        for (var i = 0; i < 4; i++)
        {
            Assert.False((await Evaluate(Packet("10.242.0." + (20 + i), "10.242.1.5", 270000, "SYN"), i * 50)).Matched);
        }
    }

    [Fact]
    public async Task Stale_Syn_Burst_Cannot_Contribute_To_New_Packet_Window()
    {
        for (var i = 0; i < 4; i++)
            Assert.False((await Evaluate(Packet("10.242.0.6", "10.242.1.6", 270000, "SYN"), i * 100)).Matched);

        // Previous burst is older than 10 seconds. Only one new packet
        // exists in the current observation window.
        Assert.False((await Evaluate(Packet("10.242.0.6", "10.242.1.6", 270000, "SYN"), 25000)).Matched);
    }
}
