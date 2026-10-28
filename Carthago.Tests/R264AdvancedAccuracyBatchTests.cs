// SPDX-License-Identifier: MIT
using System;
using System.Threading.Tasks;
using Carthago.Engine.Rules;
using Carthago.Engine.Rules.Expansion;
using Carthago.Models;
using Xunit;

namespace Carthago.Tests;
public sealed class R264AdvancedAccuracyBatchTests
{
    private static TrafficRecord Sample() => NetworkBatch261265Context.Sample(264);
    private static RuleEvaluationContext At(TrafficRecord r, double seconds = 0)
        => NetworkBatch261265Context.At(r, seconds);
    private static async Task<bool> Hit(TrafficRecord r)
        => (await new R264_TorDirectoryOrGuardConnectionRule().EvaluateAsync(At(r))).Matched;
    [Fact] public async Task Exact_Tor_Process_With_External_Tcp_Egress_Matches()
        => Assert.True(await Hit(Sample()));
    [Fact] public async Task Tor_Port_Without_Process_Is_Not_Guard_Proof() {
        var r = Sample(); r.ProcessName = null; r.DestinationPort = 9001;
        Assert.False(await Hit(r));
    }
    [Fact] public async Task Tor_Project_Website_Without_Process_Is_Benign() {
        var r = Sample(); r.ProcessName = null; r.Sni = "www.torproject.org";
        Assert.False(await Hit(r));
    }
    [Fact] public async Task Packet_Info_Spoof_Is_Rejected() {
        var r = Sample(); r.ProcessName = null; r.Info = "Tor guard directory";
        Assert.False(await Hit(r));
    }
    [Fact] public async Task Process_Substring_Spoof_Is_Rejected() {
        var r = Sample(); r.ProcessName = "not-tor.exe"; Assert.False(await Hit(r));
    }
    [Fact] public async Task Internal_Destination_Is_Rejected() {
        var r = Sample(); r.Destination = "10.61.0.20"; Assert.False(await Hit(r));
    }
    [Fact] public async Task Udp_Contradiction_Is_Rejected() {
        var r = Sample(); r.IsUdp = true; Assert.False(await Hit(r));
    }
    [Fact] public async Task Raw_Process_Path_And_Info_Are_Redacted() {
        var r = Sample(); r.ProcessName = @"C:\private\tor.exe"; r.Info = "secret-marker";
        var evt = Assert.Single((await new R264_TorDirectoryOrGuardConnectionRule().EvaluateAsync(At(r))).Events);
        Assert.DoesNotContain("secret-marker", evt.Evidence ?? "", StringComparison.Ordinal);
        Assert.DoesNotContain("C:\\private", evt.Evidence ?? "", StringComparison.Ordinal);
    }
    [Fact] public void Original_Confidence_Threshold_And_Mode_Are_Preserved() {
        var p = new R264_TorDirectoryOrGuardConnectionRule().PrecisionProfile;
        Assert.Equal(82, p.MinimumConfidence);
        Assert.Equal(1, p.Threshold);
        Assert.Equal(RuleRuntimeMode.Alert, p.DefaultMode);
    }
}
