// SPDX-License-Identifier: MIT
using System;
using System.Threading.Tasks;
using Carthago.Engine.Rules;
using Carthago.Engine.Rules.Expansion;
using Carthago.Models;
using Xunit;

namespace Carthago.Tests;
public sealed class R259AdvancedAccuracyBatchTests
{
    private static TrafficRecord Sample() => NetworkBatch256260Context.Sample(259);
    private static RuleEvaluationContext At(TrafficRecord r, double seconds = 0)
        => NetworkBatch256260Context.At(r, seconds);
    private static async Task<bool> Hit(TrafficRecord r)
        => (await new R259_TcpResetStormRule().EvaluateAsync(At(r))).Matched;
    private static async Task<bool> Burst(R259_TcpResetStormRule rule, int count)
    {
        bool hit = false;
        for (var i = 0; i < count; i++) hit = (await rule.EvaluateAsync(At(Sample(), i))).Matched;
        return hit;
    }
    [Fact] public async Task Ten_Typed_Rst_Packets_Match()
        => Assert.True(await Burst(new R259_TcpResetStormRule(), 10));
    [Fact] public async Task Nine_Are_Below_Threshold()
        => Assert.False(await Burst(new R259_TcpResetStormRule(), 9));
    [Fact] public async Task Syn_Without_Rst_Is_Benign() {
        var r = Sample(); r.TcpFlags = 0x02; Assert.False(await Hit(r));
    }
    [Fact] public async Task Info_Spoof_Does_Not_Supply_Rst_Flag() {
        var r = Sample(); r.TcpFlags = null; r.Info = "TCP RST storm";
        Assert.False(await Hit(r));
    }
    [Fact] public async Task Icmp_Contradiction_Is_Rejected() {
        var r = Sample(); r.IcmpTypeCode = 0x0303; Assert.False(await Hit(r));
    }
    [Fact] public async Task Syn_Rst_Contradiction_Is_Rejected() {
        var r = Sample(); r.TcpFlags = 0x06; Assert.False(await Hit(r));
    }
    [Fact] public async Task Duplicate_Packet_Id_Does_Not_Inflate_Window() {
        var rule = new R259_TcpResetStormRule(); var r = Sample();
        for (var i = 0; i < 11; i++) Assert.False((await rule.EvaluateAsync(At(r, i))).Matched);
    }
    [Fact] public async Task Out_Of_Order_Packets_Are_Rejected() {
        var rule = new R259_TcpResetStormRule();
        Assert.False((await rule.EvaluateAsync(At(Sample(), 30))).Matched);
        for (var i = 1; i < 10; i++) Assert.False((await rule.EvaluateAsync(At(Sample(), i))).Matched);
    }
    [Fact] public async Task Destination_Port_Isolation_Is_Preserved() {
        var rule = new R259_TcpResetStormRule();
        for (var i = 0; i < 16; i++) {
            var r = Sample(); if (i % 2 == 0) r.DestinationPort = 8443;
            Assert.False((await rule.EvaluateAsync(At(r, i))).Matched);
        }
    }
    [Fact] public async Task Packet_Info_Secret_Is_Redacted() {
        var rule = new R259_TcpResetStormRule();
        RuleEvaluationResult result = RuleEvaluationResult.NoMatch("R259");
        for (var i = 0; i < 10; i++) {
            var r = Sample(); r.Info = "token=secret-marker";
            result = await rule.EvaluateAsync(At(r, i));
        }
        Assert.DoesNotContain("secret-marker", Assert.Single(result.Events).Evidence ?? "", StringComparison.Ordinal);
    }
    [Fact] public async Task Contradictory_Http_Metadata_Is_Rejected() {
        var r = Sample(); r.HttpMethod = "GET"; Assert.False(await Hit(r));
    }
    [Fact] public void Original_Alert_Confidence_And_Threshold_Remain() {
        var p = new R259_TcpResetStormRule().PrecisionProfile;
        Assert.Equal(75, p.MinimumConfidence); Assert.Equal(10, p.Threshold);
        Assert.Equal(RuleRuntimeMode.Alert, p.DefaultMode);
    }
}
