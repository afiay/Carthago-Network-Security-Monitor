// SPDX-License-Identifier: MIT
using System;
using System.Threading.Tasks;
using Carthago.Engine.Rules;
using Carthago.Engine.Rules.Expansion;
using Carthago.Models;
using Xunit;

namespace Carthago.Tests;
public sealed class R267AdvancedAccuracyBatchTests
{
    private static TrafficRecord Sample() => NetworkBatch266270Context.Sample(267);
    private static RuleEvaluationContext At(TrafficRecord r, double s = 0) => NetworkBatch266270Context.At(r, s);
    private static async Task<bool> Hit(R267_SuspiciousProcessNameNetworkEgressRule rule, TrafficRecord r, double s = 0)
        => (await rule.EvaluateAsync(At(r, s))).Matched;
    [Fact] public async Task Exact_Masquerade_Basename_With_External_Tcp_Matches() =>
        Assert.True(await Hit(new(), Sample()));
    [Fact] public async Task Real_Svchost_Is_Not_Masquerade() {
        var r = Sample(); r.ProcessName = "svchost.exe"; Assert.False(await Hit(new(), r));
    }
    [Fact] public async Task Prefix_Or_Substring_Spoof_Is_Rejected() {
        var r = Sample(); r.ProcessName = "not-scvhost.exe"; Assert.False(await Hit(new(), r));
    }
    [Fact] public async Task Packet_Info_Only_Is_Rejected() {
        var r = Sample(); r.ProcessName = null; r.Info = "scvhost.exe"; Assert.False(await Hit(new(), r));
    }
    [Fact] public async Task Missing_Process_Pid_Is_Rejected() {
        var r = Sample(); r.ProcessId = 0; Assert.False(await Hit(new(), r));
    }
    [Fact] public async Task Internal_Traffic_Is_Rejected() {
        var r = Sample(); r.Destination = "10.61.0.20"; Assert.False(await Hit(new(), r));
    }
    [Fact] public async Task Contradictory_Udp_Is_Rejected() {
        var r = Sample(); r.IsUdp = true; Assert.False(await Hit(new(), r));
    }
    [Fact] public async Task Duplicate_Id_Is_Rejected() {
        var rule = new R267_SuspiciousProcessNameNetworkEgressRule(); var r = Sample();
        Assert.True(await Hit(rule, r)); Assert.False(await Hit(rule, r, 1));
    }
    [Fact] public async Task Out_Of_Order_Packet_Is_Rejected() {
        var rule = new R267_SuspiciousProcessNameNetworkEgressRule(); var r = Sample();
        Assert.True(await Hit(rule, r, 10)); Assert.False(await Hit(rule, NetworkBatch266270Context.Copy(r), 9));
    }
    [Fact] public async Task Windows_Path_Normalizes_Exact_Basename() {
        var r = Sample(); r.ProcessName = @"C:\Windows\Temp\scvhost.exe"; Assert.True(await Hit(new(), r));
    }
    [Fact] public async Task Sensitive_Path_And_Info_Are_Redacted() {
        var r = Sample(); r.ProcessName = @"C:\secret-marker\scvhost.exe"; r.Info = "secret-marker";
        var evt = Assert.Single((await new R267_SuspiciousProcessNameNetworkEgressRule().EvaluateAsync(At(r))).Events);
        Assert.DoesNotContain("secret-marker", evt.Evidence ?? "", StringComparison.Ordinal);
    }
    [Fact] public void Confidence_Mode_And_Threshold_Unchanged() {
        var p = new R267_SuspiciousProcessNameNetworkEgressRule().PrecisionProfile;
        Assert.Equal(82, p.MinimumConfidence); Assert.Equal(1, p.Threshold);
        Assert.Equal(RuleRuntimeMode.Alert, p.DefaultMode);
    }
}
