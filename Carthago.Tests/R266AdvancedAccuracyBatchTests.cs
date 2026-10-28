// SPDX-License-Identifier: MIT
using System;
using System.Threading.Tasks;
using Carthago.Engine.Rules;
using Carthago.Engine.Rules.Expansion;
using Carthago.Models;
using Xunit;

namespace Carthago.Tests;
public sealed class R266AdvancedAccuracyBatchTests
{
    private static TrafficRecord Sample() => NetworkBatch266270Context.Sample(266);
    private static RuleEvaluationContext At(TrafficRecord r, double s = 0) => NetworkBatch266270Context.At(r, s);
    private static async Task<bool> Hit(R266_NewProcessInitiatingNetworkEgressRule rule, TrafficRecord r, double s = 0)
        => (await rule.EvaluateAsync(At(r, s))).Matched;
    [Fact] public async Task First_Observed_Process_Pid_Egress_Is_Candidate() =>
        Assert.True(await Hit(new R266_NewProcessInitiatingNetworkEgressRule(), Sample()));
    [Fact] public async Task Same_Process_Pid_Second_Packet_Is_Not_New() {
        var rule = new R266_NewProcessInitiatingNetworkEgressRule(); var r = Sample();
        Assert.True(await Hit(rule, r)); Assert.False(await Hit(rule, NetworkBatch266270Context.Copy(r), 1));
    }
    [Fact] public async Task Different_Pid_Is_Independent_First_Observation() {
        var rule = new R266_NewProcessInitiatingNetworkEgressRule(); var r = Sample();
        Assert.True(await Hit(rule, r)); var other = NetworkBatch266270Context.Copy(r);
        other.ProcessId = 4101; Assert.True(await Hit(rule, other, 1));
    }
    [Fact] public async Task Packet_Info_Cannot_Invent_Process() {
        var r = Sample(); r.ProcessName = null; r.Info = "new process started"; Assert.False(await Hit(new(), r));
    }
    [Fact] public async Task Process_Without_Pid_Is_Unattributed() {
        var r = Sample(); r.ProcessId = 0; Assert.False(await Hit(new(), r));
    }
    [Fact] public async Task Common_Browser_Is_Not_A_Novelty_Alert() {
        var r = Sample(); r.ProcessName = "chrome.exe"; Assert.False(await Hit(new(), r));
    }
    [Fact] public async Task Internal_Destination_Is_Not_External_Egress() {
        var r = Sample(); r.Destination = "10.61.0.11"; Assert.False(await Hit(new(), r));
    }
    [Fact] public async Task Udp_Contradiction_Is_Rejected() {
        var r = Sample(); r.IsUdp = true; Assert.False(await Hit(new(), r));
    }
    [Fact] public async Task Invalid_Process_Basename_Is_Rejected() {
        var r = Sample(); r.ProcessName = "bad process ?.exe"; Assert.False(await Hit(new(), r));
    }
    [Fact] public async Task Replayed_Packet_Id_Is_Not_Another_First_Observation() {
        var rule = new R266_NewProcessInitiatingNetworkEgressRule(); var r = Sample();
        Assert.True(await Hit(rule, r)); Assert.False(await Hit(rule, r, 5));
    }
    [Fact] public async Task Raw_Path_And_Info_Do_Not_Leak_In_Evidence() {
        var r = Sample(); r.ProcessName = @"C:\secret-marker\rarerunner.exe"; r.Info = "secret-marker";
        var result = await new R266_NewProcessInitiatingNetworkEgressRule().EvaluateAsync(At(r));
        var evt = Assert.Single(result.Events);
        Assert.DoesNotContain("secret-marker", evt.Evidence ?? "", StringComparison.Ordinal);
    }
    [Fact] public void Confidence_Mode_And_Threshold_Unchanged() {
        var p = new R266_NewProcessInitiatingNetworkEgressRule().PrecisionProfile;
        Assert.Equal(75, p.MinimumConfidence); Assert.Equal(1, p.Threshold);
        Assert.Equal(RuleRuntimeMode.Alert, p.DefaultMode);
    }
}
