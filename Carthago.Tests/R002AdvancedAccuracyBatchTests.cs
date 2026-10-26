// SPDX-License-Identifier: MIT
using System;
using System.Threading.Tasks;
using Carthago.Engine.Rules;
using Carthago.Engine.Rules.Existing;
using Carthago.Models;
using Carthago.Services;
using Xunit;

namespace Carthago.Tests;

/// <summary>R002 batch gate: five independent flood false-positive boundaries.</summary>
[Collection("Legacy rules R001-R005 isolated")]
public sealed class R002AdvancedAccuracyBatchTests : IDisposable
{
    private readonly R002_FloodDosRule _rule = new();
    private static readonly DateTime Origin = new(2026, 10, 26, 11, 0, 0, DateTimeKind.Utc);
    public R002AdvancedAccuracyBatchTests() => RuleEngine.ResetRuntimeStateForReplay();
    public void Dispose() => RuleEngine.ResetRuntimeStateForReplay();

    private static TrafficRecord Packet(int port = 443, int bytes = 270000,
        string flags = "SYN", string source = "10.252.1.1",
        string destination = "10.252.2.1", string protocol = "TCP")
        => new() { Source = source, Destination = destination,
            DestinationPort = port, Protocol = protocol, Flags = flags,
            Length = bytes };

    private async Task<RuleEvaluationResult> See(TrafficRecord record, int ms)
        => await _rule.EvaluateAsync(new RuleEvaluationContext(
            record, Sensitivity.Balanced, Origin.AddMilliseconds(ms)));

    [Fact]
    public async Task Parallel_Independent_Destination_Services_Never_Combine_Into_One_Flood()
    {
        for (var i = 0; i < 4; i++)
        {
            Assert.False((await See(Packet(443), i * 100)).Matched);
            Assert.False((await See(Packet(8443), i * 100 + 50)).Matched);
        }
        var observed = await See(Packet(443), 500);
        Assert.True(observed.Matched);
        Assert.Equal(443, Assert.Single(observed.Events).DestinationPort);
    }

    [Fact]
    public async Task Four_Independent_Sources_To_Same_Service_Cannot_Create_Single_Source_Flood()
    {
        for (var i = 0; i < 4; i++)
        for (var j = 0; j < 4; j++)
            Assert.False((await See(Packet(source: "10.252.1." + (10 + i)), j * 150 + i)).Matched);
    }

    [Fact]
    public async Task Large_Balanced_Syn_Ack_Traffic_Is_Not_Evidence_Of_Syn_Flood()
    {
        for (var i = 0; i < 8; i++)
        {
            Assert.False((await See(Packet(flags: "SYN"), i * 140)).Matched);
            Assert.False((await See(Packet(flags: "ACK"), i * 140 + 40)).Matched);
        }
    }

    [Fact]
    public async Task Insufficient_Syn_Bytes_Never_Cross_Flood_Gate_Even_With_Many_Packets()
    {
        for (var i = 0; i < 30; i++)
            Assert.False((await See(Packet(bytes: 64), i * 100)).Matched);
    }

    [Fact]
    public async Task Invalid_Transport_And_Missing_Ports_Cannot_Preload_Flood_State()
    {
        foreach (var port in new[] { -1, 0, 65536 })
            Assert.False((await See(Packet(port), 1)).Matched);
        for (var i = 0; i < 5; i++)
            Assert.False((await See(Packet(protocol: "UDP"), 20 + i)).Matched);

        for (var i = 0; i < 4; i++)
            Assert.False((await See(Packet(), 100 + i * 100)).Matched);
        Assert.True((await See(Packet(), 700)).Matched);
    }

    [Fact]
    public async Task Future_Dated_Packets_Cannot_Preload_A_Current_Flood_Window()
    {
        for (var i = 0; i < 4; i++)
            Assert.False((await See(Packet(), 100_000 + i * 100)).Matched);

        for (var i = 0; i < 4; i++)
            Assert.False((await See(Packet(), i * 100)).Matched);

        var currentFifth = await See(Packet(), 400);
        Assert.True(currentFifth.Matched);
        Assert.Equal(5, Assert.Single(currentFifth.Events).Count);
    }

    [Fact]
    public async Task Future_Packets_Inside_The_Same_Time_Bucket_Are_Not_Present_Evidence()
    {
        // All timestamps belong to the same 100 ms bucket. A bucket's
        // start time alone cannot establish that its contents are current.
        for (var ms = 95; ms < 99; ms++)
            Assert.False((await See(Packet(), ms)).Matched);
        for (var ms = 0; ms < 4; ms++)
            Assert.False((await See(Packet(), ms)).Matched);

        var hit = await See(Packet(), 4);
        Assert.True(hit.Matched);
        Assert.Equal(5, Assert.Single(hit.Events).Count);
    }

    [Fact]
    public async Task Historical_Bytes_Cannot_Convert_A_Low_Byte_Current_Window_Into_A_Flood()
    {
        // A continuous trickle prevents the old aggregate's idle-gap reset,
        // yet no 10-second window contains enough bytes for an alert.
        foreach (var second in new[] { 0, 4, 8, 12 })
            Assert.False((await See(Packet(bytes: 270_000), second * 1000)).Matched);

        for (var second = 13; second <= 17; second++)
            Assert.False((await See(Packet(bytes: 64), second * 1000)).Matched);
    }
}
