// SPDX-License-Identifier: MIT
using System;
using System.Threading.Tasks;
using Carthago.Engine.Rules;
using Carthago.Engine.Rules.Expansion;
using Carthago.Models;
using Carthago.Services;
using Xunit;

namespace Carthago.Tests;

public sealed class R272AdvancedAccuracyBatchTests
{
    private static TrafficRecord Sample() => NetworkBatch271275Context.Sample();
    private static async Task<bool> Hit(TrafficRecord r, double seconds = 0)
        => (await new R272_MultiSignalRuleStackSurgeFromHostRule()
            .EvaluateAsync(NetworkBatch271275Context.At(r, seconds))).Matched;
    [Fact] public async Task Packet_Info_Claiming_Three_Alerts_Is_Not_Correlation() {
        var r = Sample(); r.Info = "multi-signal rule stack surge three detections";
        Assert.False(await Hit(r));
    }
    [Fact] public async Task Three_Different_Packets_Are_Not_Three_Rule_Families() {
        var r = Sample(); var rule = new R272_MultiSignalRuleStackSurgeFromHostRule();
        for (var i = 0; i < 3; i++)
            Assert.False((await rule.EvaluateAsync(NetworkBatch271275Context.At(
                NetworkBatch271275Context.Copy(r), i))).Matched);
    }
    [Fact] public async Task Three_Different_Destinations_Are_Not_Alert_Correlation() {
        var r = Sample();
        for (var i = 0; i < 3; i++) {
            r.Destination = $"10.61.0.{i + 10}";
            Assert.False(await Hit(NetworkBatch271275Context.Copy(r), i));
        }
    }
    [Fact] public async Task Duplicate_Replay_Cannot_Create_Stack() {
        var r = Sample(); Assert.False(await Hit(r)); Assert.False(await Hit(r, 1));
    }
    [Fact] public async Task Out_Of_Order_Packets_Cannot_Create_Stack() {
        var r = Sample(); Assert.False(await Hit(r, 10)); Assert.False(await Hit(r, 2));
    }
    [Fact] public async Task Process_Name_Claim_Is_Not_Emitted_Rule_Event() {
        var r = Sample(); r.ProcessName = "R003_R016_R271.exe"; Assert.False(await Hit(r));
    }
    [Fact] public async Task Host_Missing_Cannot_Create_Correlation() {
        var r = Sample(); r.Source = null; Assert.False(await Hit(r));
    }
    [Fact] public async Task Protocol_Contradiction_Is_Not_Correlation() {
        var r = Sample(); r.IsUdp = true; Assert.False(await Hit(r));
    }
    [Fact] public async Task Reputation_And_Feed_Text_Are_Not_Three_Alerts() {
        var r = Sample(); r.Info = "R003 R016 R271 all matched";
        Assert.False(await Hit(r));
    }
    [Fact] public async Task Synthetic_Alert_Count_In_Http_Uri_Is_Not_Trusted() {
        var r = Sample(); r.HttpUri = "/alerts?rules=R003,R016,R271";
        Assert.False(await Hit(r));
    }
    [Fact] public void High_Confidence_Mode_And_Threshold_Preserved() {
        var p = new R272_MultiSignalRuleStackSurgeFromHostRule().PrecisionProfile;
        Assert.Equal(82, p.MinimumConfidence); Assert.Equal(3, p.Threshold);
        Assert.Equal(RuleRuntimeMode.Alert, p.DefaultMode);
    }
}
