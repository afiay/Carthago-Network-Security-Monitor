// SPDX-License-Identifier: MIT
using System;
using System.Threading.Tasks;
using Carthago.Engine.Rules;
using Carthago.Engine.Rules.Expansion;
using Carthago.Models;
using Xunit;

namespace Carthago.Tests;
public sealed class R263AdvancedAccuracyBatchTests
{
    private static TrafficRecord Sample() => NetworkBatch261265Context.Sample(263);
    private static RuleEvaluationContext At(TrafficRecord r, double seconds = 0)
        => NetworkBatch261265Context.At(r, seconds);
    private static async Task<bool> Hit(TrafficRecord r)
        => (await new R263_UserSpaceProxyProcessEgressRule().EvaluateAsync(At(r))).Matched;
    [Fact] public async Task Exact_Proxy_Process_With_External_Tcp_Egress_Matches()
        => Assert.True(await Hit(Sample()));
    [Fact] public async Task Process_Substring_Spoof_Is_Rejected() {
        var r = Sample(); r.ProcessName = "notngrok.exe"; Assert.False(await Hit(r));
    }
    [Fact] public async Task Info_Spoof_Without_Process_Is_Rejected() {
        var r = Sample(); r.ProcessName = null; r.Info = "ngrok proxy started";
        Assert.False(await Hit(r));
    }
    [Fact] public async Task Internal_Destination_Is_Rejected() {
        var r = Sample(); r.Destination = "10.61.0.20"; Assert.False(await Hit(r));
    }
    [Fact] public async Task Udp_Contradiction_Is_Rejected() {
        var r = Sample(); r.IsUdp = true; Assert.False(await Hit(r));
    }
    [Fact] public async Task Missing_Process_Attribution_Is_Rejected() {
        var r = Sample(); r.ProcessName = null; Assert.False(await Hit(r));
    }
    [Fact] public async Task Windows_Process_Path_Normalizes_To_Exact_Basename() {
        var r = Sample(); r.ProcessName = @"C:\Tools\ngrok.exe"; Assert.True(await Hit(r));
    }
    [Fact] public async Task Raw_Process_Path_And_Info_Are_Redacted() {
        var r = Sample(); r.ProcessName = @"C:\secret\ngrok.exe"; r.Info = "secret-marker";
        var evt = Assert.Single((await new R263_UserSpaceProxyProcessEgressRule().EvaluateAsync(At(r))).Events);
        Assert.DoesNotContain("secret-marker", evt.Evidence ?? "", StringComparison.Ordinal);
        Assert.DoesNotContain("C:\\secret", evt.Evidence ?? "", StringComparison.Ordinal);
    }
    [Fact] public void Original_Confidence_Threshold_And_Mode_Are_Preserved() {
        var p = new R263_UserSpaceProxyProcessEgressRule().PrecisionProfile;
        Assert.Equal(75, p.MinimumConfidence);
        Assert.Equal(1, p.Threshold);
        Assert.Equal(RuleRuntimeMode.Alert, p.DefaultMode);
    }
}
