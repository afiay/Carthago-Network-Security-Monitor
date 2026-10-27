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
public sealed class R030AdvancedAccuracyBatchTests : IDisposable
{
    private readonly R030_InternalAdminLateralSweepRule _rule = new();
    private static readonly DateTime T0 = new(2026, 10, 27, 4, 0, 0, DateTimeKind.Utc);
    public R030AdvancedAccuracyBatchTests() => RuleEngine.ResetRuntimeStateForReplay();
    public void Dispose() => RuleEngine.ResetRuntimeStateForReplay();
    private async Task<RuleEvaluationResult> See(TrafficRecord r, int sec = 0)
        => await _rule.EvaluateAsync(new RuleEvaluationContext(r, Sensitivity.Balanced, T0.AddSeconds(sec)));
    private static TrafficRecord Probe(int host = 10, string src = "10.30.0.2",
        int port = 22, string protocol = "TCP", string flags = "SYN")
        => new() { Source = src, Destination = "10.30.1." + host,
            DestinationPort = port, Protocol = protocol, Flags = flags, Length = 72 };
    [Fact] public async Task Eight_Distinct_Private_Admin_Connections_Produce_Sweep()
    {
        for (int i = 0; i < 7; i++) Assert.False((await See(Probe(10+i), i)).Matched);
        var e = Assert.Single((await See(Probe(17), 7)).Events);
        Assert.Equal("R030", e.RuleId); Assert.Equal("10.30.0.2", e.SourceIp);
        Assert.Equal(8, e.Count); Assert.Equal(60, e.WindowSeconds);
        Assert.Equal(SeverityLevel.High, e.Severity);
    }

    [Fact] public async Task Retransmissions_To_Same_Target_Do_Not_Inflate_Distinct_Count()
    {
        for (int i = 0; i < 30; i++) Assert.False((await See(Probe(), i)).Matched);
        for (int i = 0; i < 6; i++) Assert.False((await See(Probe(11+i), 30+i)).Matched);
        Assert.Equal(8, Assert.Single((await See(Probe(17), 36)).Events).Count);
    }

    [Fact] public async Task Separate_Sources_And_Admin_Ports_Do_Not_Combine()
    {
        for (int i = 0; i < 7; i++)
        {
            Assert.False((await See(Probe(10+i), i)).Matched);
            Assert.False((await See(Probe(10+i, src: "10.30.0.3"), i)).Matched);
            Assert.False((await See(Probe(10+i, port: 3389), i)).Matched);
        }
        Assert.Equal(8, Assert.Single((await See(Probe(17), 7)).Events).Count);
    }

    [Fact] public async Task Reverse_Flags_Udp_And_Numeric_SynAck_Are_Not_Lateral_Probes()
    {
        foreach (var flags in new[] { "ACK", "SYN,ACK", "RST", "FIN", "" })
            for (int i = 0; i < 8; i++) Assert.False((await See(Probe(10+i, flags: flags), i)).Matched);
        for (int i = 0; i < 8; i++)
            Assert.False((await See(Probe(10+i, protocol: "UDP"), i)).Matched);
        var r = Probe(); r.TcpFlags = 0x12; Assert.False((await See(r)).Matched);
    }

    [Fact] public async Task Invalid_External_Same_Host_And_Empty_Evidence_Do_Not_Seed_State()
    {
        var external = Probe(); external.Destination = "8.8.8.8";
        var same = Probe(); same.Destination = same.Source;
        var docs = Probe(); docs.Destination = "192.0.2.1";
        var bad = Probe(); bad.Source = "bad";
        var empty = Probe(); empty.Length = 0;
        foreach (var r in new[] { external, same, docs, bad, empty })
            Assert.False((await See(r)).Matched);
        for (int i = 0; i < 7; i++) Assert.False((await See(Probe(10+i), i)).Matched);
        Assert.True((await See(Probe(17), 7)).Matched);
    }

    [Fact] public async Task Future_And_Stale_Observations_Do_Not_Complete_Current_Window()
    {
        Assert.False((await See(Probe(99), 500)).Matched);
        for (int i = 0; i < 7; i++) Assert.False((await See(Probe(10+i), i)).Matched);
        Assert.True((await See(Probe(17), 7)).Matched);
        RuleEngine.ResetRuntimeStateForReplay();
        for (int i = 0; i < 7; i++) Assert.False((await See(Probe(10+i), i)).Matched);
        Assert.False((await See(Probe(17), 100)).Matched);
    }

    [Fact] public async Task Mail_Auth_And_Invalid_Ports_Are_Not_Lateral_Admin_Sweep()
    {
        foreach (int p in new[] { 25, 110, 143, 465, 993, 995, 65536 })
            for (int i = 0; i < 8; i++)
                Assert.False((await See(Probe(10+i, port: p), i)).Matched);
    }

    [Fact] public async Task Numeric_Syn_Qualifies_But_Numeric_SynAck_Does_Not()
    {
        for (int i = 0; i < 8; i++)
        {
            var r = Probe(10+i, flags: ""); r.TcpFlags = 0x12;
            Assert.False((await See(r, i)).Matched);
        }
        for (int i = 0; i < 7; i++)
        {
            var r = Probe(10+i, flags: ""); r.TcpFlags = 0x02;
            Assert.False((await See(r, i)).Matched);
        }
        var last = Probe(17, flags: ""); last.TcpFlags = 0x02;
        Assert.True((await See(last, 7)).Matched);
    }

    [Fact] public async Task Suppressed_Completed_Window_Is_Cleared_Before_Next_Fresh_Sweep()
    {
        for (int i = 0; i < 8; i++) await See(Probe(10+i), i);
        for (int i = 0; i < 7; i++) Assert.False((await See(Probe(20+i), 8+i)).Matched);
        var suppressed = await See(Probe(27), 15);
        Assert.True(suppressed.Suppressed); Assert.Empty(suppressed.Events);
        for (int i = 0; i < 7; i++) Assert.False((await See(Probe(30+i), 100+i)).Matched);
        Assert.Equal(8, Assert.Single((await See(Probe(37), 107)).Events).Count);
    }
}
