// SPDX-License-Identifier: MIT
using System;
using System.Linq;
using System.Threading.Tasks;
using Carthago.Engine.Rules;
using Carthago.Engine.Rules.Existing;
using Carthago.Models;
using Carthago.Services;
using Xunit;

namespace Carthago.Tests;

// Legacy R001-R005 share RuleEngine mutable traffic windows. Never run these
// test classes concurrently with each other or concurrent replay benchmarks.
[CollectionDefinition("Legacy rules R001-R005 isolated", DisableParallelization = true)]
public sealed class LegacyR001ToR005IsolatedCollection { }

[Collection("Legacy rules R001-R005 isolated")]
public sealed class R001Tests : IDisposable
{
    private static readonly DateTime T0 = new(2026, 10, 26, 10, 0, 0, DateTimeKind.Utc);
    private readonly R001_PortScanRule _rule = new();

    public R001Tests() => RuleEngine.ResetRuntimeStateForReplay();
    public void Dispose() => RuleEngine.ResetRuntimeStateForReplay();

    private static TrafficRecord Packet(string src, string dst, int port, string flags = "SYN", string protocol = "TCP")
        => new()
        {
            Source = src, Destination = dst,
            SourcePort = 54000, DestinationPort = port,
            Protocol = protocol, Flags = flags, Length = 60
        };

    private async Task<RuleEvaluationResult> Evaluate(TrafficRecord record, int second)
        => await _rule.EvaluateAsync(new RuleEvaluationContext(
            record, Sensitivity.Balanced, T0.AddSeconds(second)));

    [Fact]
    public async Task Configured_Distinct_TCP_SYN_Threshold_Triggers_One_Attributed_Scan()
    {
        RuleEvaluationResult? matched = null;
        for (var i = 0; i < 16; i++)
        {
            var observed = await Evaluate(Packet("10.240.1.1", "10.240.2.1", 3000 + i), i);
            if (i < 4) Assert.False(observed.Matched);
            if (!observed.Matched || observed.Events.Count == 0) continue;
            matched = observed;
            break;
        }

        Assert.NotNull(matched);
        var evt = Assert.Single(matched!.Events);
        Assert.Equal("R001", evt.RuleId);
        Assert.InRange(evt.Count, 5, 16);
        Assert.Equal("10.240.1.1", evt.SourceIp);
        Assert.Equal("10.240.2.1", evt.DestinationIp);
        Assert.InRange(evt.WindowSeconds, 10, 60);
    }

    [Fact]
    public async Task Regular_ACK_And_SYN_ACK_Traffic_Cannot_Prime_Scan_Counters()
    {
        for (var i = 0; i < 12; i++)
        {
            var flags = i % 2 == 0 ? "ACK" : "SYN,ACK";
            Assert.False((await Evaluate(Packet("10.240.1.2", "10.240.2.2", 4000 + i, flags), i)).Matched);
        }

        Assert.False((await Evaluate(Packet("10.240.1.2", "10.240.2.2", 4012), 14)).Matched);
    }

    [Fact]
    public async Task Tcp_Retransmissions_To_The_Same_Port_Are_Not_Five_Distinct_Ports()
    {
        for (var i = 0; i < 12; i++)
            Assert.False((await Evaluate(Packet("10.240.1.3", "10.240.2.3", 22), i)).Matched);

        Assert.False((await Evaluate(Packet("10.240.1.3", "10.240.2.3", 443), 13)).Matched);
    }

    [Fact]
    public async Task Different_Destinations_And_Sources_Cannot_Be_Merged_Into_A_Scan()
    {
        for (var i = 0; i < 4; i++)
        {
            Assert.False((await Evaluate(Packet("10.240.1.4", "10.240.2.4", 5000 + i), i)).Matched);
            Assert.False((await Evaluate(Packet("10.240.1.4", "10.240.2.5", 5000 + i), i)).Matched);
            Assert.False((await Evaluate(Packet("10.240.1.5", "10.240.2.4", 5000 + i), i)).Matched);
        }

        RuleEvaluationResult? result = null;
        for (var i = 4; i < 16; i++)
        {
            var observed = await Evaluate(Packet("10.240.1.4", "10.240.2.4", 5000 + i), i + 1);
            if (!observed.Matched || observed.Events.Count == 0) continue;
            result = observed;
            break;
        }
        Assert.NotNull(result);
        Assert.InRange(Assert.Single(result!.Events).Count, 5, 16);
    }

    [Fact]
    public async Task Expired_Port_Observations_Never_Contribute_To_Later_Scan_Burst()
    {
        for (var i = 0; i < 4; i++)
            Assert.False((await Evaluate(Packet("10.240.1.6", "10.240.2.6", 6000 + i), i)).Matched);

        Assert.False((await Evaluate(Packet("10.240.1.6", "10.240.2.6", 6004), 40)).Matched);
        RuleEvaluationResult? burst = null;
        for (var i = 0; i < 16; i++)
        {
            var observed = await Evaluate(Packet("10.240.1.6", "10.240.2.6", 6100 + i), 41 + i);
            if (!observed.Matched || observed.Events.Count == 0) continue;
            burst = observed;
            break;
        }
        Assert.NotNull(burst);
        Assert.InRange(Assert.Single(burst!.Events).Count, 5, 16);
    }

    [Fact]
    public async Task Udp_NonSyn_And_Missing_Endpoint_Telemetry_Do_Not_Look_Like_Tcp_Port_Scans()
    {
        for (var i = 0; i < 12; i++)
        {
            Assert.False((await Evaluate(Packet("10.240.1.7", "10.240.2.7", 7000 + i, "SYN", "UDP"), i)).Matched);
            Assert.False((await Evaluate(Packet("10.240.1.7", "10.240.2.7", 7000 + i, "ACK"), i)).Matched);
        }
        Assert.False((await Evaluate(new TrafficRecord
        {
            Protocol = "TCP", Source = "10.240.1.7", Destination = null,
            DestinationPort = 9000, Flags = "SYN"
        }, 20)).Matched);
    }
}
