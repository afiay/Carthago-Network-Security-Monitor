// SPDX-License-Identifier: MIT
using System;
using System.Threading.Tasks;
using Carthago.Engine.Rules;
using Carthago.Engine.Rules.Existing;
using Carthago.Models;
using Carthago.Services;
using Xunit;

namespace Carthago.Tests;

/// <summary>R017: per-source, port and transport internal host sweep observations.</summary>
[Collection("Legacy rules R011-R015 isolated")]
public sealed class R017AdvancedAccuracyBatchTests : IDisposable
{
    private readonly R017_InternalHostSweepRule _rule = new();
    private static readonly DateTime T0 = new(2026, 10, 27, 3, 0, 0, DateTimeKind.Utc);
    public R017AdvancedAccuracyBatchTests() => RuleEngine.ResetRuntimeStateForReplay();
    public void Dispose() => RuleEngine.ResetRuntimeStateForReplay();

    private static TrafficRecord Probe(int host = 10, string source = "10.17.0.2",
        int port = 445, string protocol = "TCP", string flags = "SYN")
        => new() { Source = source, Destination = "10.17.1." + host,
            Protocol = protocol, DestinationPort = port, Flags = flags, Length = 64 };

    private async Task<RuleEvaluationResult> See(TrafficRecord r, int second = 0)
        => await _rule.EvaluateAsync(new RuleEvaluationContext(r, Sensitivity.Balanced, T0.AddSeconds(second)));

    [Fact]
    public async Task Ten_Distinct_Internal_Tcp_Syn_Targets_Produce_One_Sweep_Candidate()
    {
        for (int i = 0; i < 9; i++)
            Assert.False((await See(Probe(10 + i), i)).Matched);
        var evt = Assert.Single((await See(Probe(19), 9)).Events);
        Assert.Equal("R017", evt.RuleId);
        Assert.Equal("10.17.0.2", evt.SourceIp);
        Assert.Equal(10, evt.Count);
        Assert.Equal(30, evt.WindowSeconds);
        Assert.Equal(SeverityLevel.High, evt.Severity);
    }

    [Fact]
    public async Task Retransmissions_To_One_Host_Do_Not_Count_As_Ten_Destinations()
    {
        for (int i = 0; i < 25; i++)
            Assert.False((await See(Probe(), i)).Matched);
        for (int i = 0; i < 8; i++)
            Assert.False((await See(Probe(11 + i), 25 + i)).Matched);
        Assert.Equal(10, Assert.Single((await See(Probe(19), 33)).Events).Count);
    }

    [Fact]
    public async Task Tcp_Ack_SynAck_Rst_And_Icmp_Cannot_Seed_The_Sweep()
    {
        foreach (var flags in new[] { "ACK", "SYN,ACK", "RST", "FIN", "" })
            for (int i = 0; i < 15; i++)
                Assert.False((await See(Probe(10 + i, flags: flags), i)).Matched);
        var icmp = Probe(); icmp.Protocol = "ICMP";
        Assert.False((await See(icmp)).Matched);
        for (int i = 0; i < 9; i++)
            Assert.False((await See(Probe(10 + i), i)).Matched);
        Assert.True((await See(Probe(19), 9)).Matched);
    }

    [Fact]
    public async Task Tcp_Numeric_Syn_Flag_Is_Recognized_But_Numeric_SynAck_Is_Not()
    {
        for (int i = 0; i < 10; i++)
        {
            var synAck = Probe(10 + i); synAck.TcpFlags = 0x12;
            Assert.False((await See(synAck, i)).Matched);
        }
        for (int i = 0; i < 9; i++)
        {
            var syn = Probe(10 + i, flags: ""); syn.TcpFlags = 0x02;
            Assert.False((await See(syn, i)).Matched);
        }
        var last = Probe(19, flags: ""); last.TcpFlags = 0x02;
        Assert.True((await See(last, 9)).Matched);
    }

    [Fact]
    public async Task Separate_Sources_Ports_And_Transports_Do_Not_Combine()
    {
        for (int i = 0; i < 9; i++)
        {
            Assert.False((await See(Probe(10 + i), i)).Matched);
            Assert.False((await See(Probe(10 + i, source: "10.17.0.3"), i)).Matched);
            Assert.False((await See(Probe(10 + i, port: 3389), i)).Matched);
            Assert.False((await See(Probe(10 + i, protocol: "UDP", flags: ""), i)).Matched);
        }
        Assert.Equal(10, Assert.Single((await See(Probe(19), 9)).Events).Count);
    }

    [Fact]
    public async Task Future_And_Expired_Observations_Cannot_Complete_A_Current_Window()
    {
        Assert.False((await See(Probe(99), 1000)).Matched);
        for (int i = 0; i < 9; i++)
            Assert.False((await See(Probe(10 + i), i)).Matched);
        Assert.Equal(10, Assert.Single((await See(Probe(19), 9)).Events).Count);

        RuleEngine.ResetRuntimeStateForReplay();
        for (int i = 0; i < 9; i++)
            Assert.False((await See(Probe(10 + i), i)).Matched);
        Assert.False((await See(Probe(19), 100)).Matched);
        for (int i = 0; i < 8; i++)
            Assert.False((await See(Probe(20 + i), 100 + i)).Matched);
        Assert.Equal(10, Assert.Single((await See(Probe(28), 109)).Events).Count);
    }

    [Fact]
    public async Task Invalid_External_Same_Host_And_Invalid_Port_Are_Not_Sweep_Evidence()
    {
        var external = Probe(); external.Destination = "8.8.8.8";
        var badSource = Probe(); badSource.Source = "8.8.8.8";
        var same = Probe(); same.Destination = same.Source;
        var invalidPort = Probe(port: 65536);
        var missing = Probe(); missing.Destination = null;
        var zero = Probe(); zero.Length = 0;
        foreach (var r in new[] { external, badSource, same, invalidPort, missing, zero })
            Assert.False((await See(r)).Matched);
    }

    [Fact]
    public async Task Suppressed_Second_Window_Does_Not_Emit_An_Event()
    {
        for (int i = 0; i < 10; i++) await See(Probe(10 + i), i);
        for (int i = 0; i < 9; i++)
            Assert.False((await See(Probe(30 + i), 10 + i)).Matched);
        var repeat = await See(Probe(39), 19);
        Assert.True(repeat.Suppressed);
        Assert.Empty(repeat.Events);
    }
}
