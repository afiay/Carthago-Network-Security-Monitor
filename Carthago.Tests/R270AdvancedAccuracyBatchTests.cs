// SPDX-License-Identifier: MIT
using System;
using System.Threading.Tasks;
using Carthago.Engine.Rules;
using Carthago.Engine.Rules.Expansion;
using Carthago.Models;
using Xunit;

namespace Carthago.Tests;
public sealed class R270AdvancedAccuracyBatchTests
{
    private static TrafficRecord Sample() => NetworkBatch266270Context.Sample(270);
    private static RuleEvaluationContext At(TrafficRecord r) => NetworkBatch266270Context.At(r);
    private static async Task<bool> Hit(TrafficRecord r) =>
        (await new R270_DetectionPipelineTamperingIndicatorRule().EvaluateAsync(At(r))).Matched;
    [Fact] public async Task Packet_Info_Cannot_Attest_Pipeline_Tampering() =>
        Assert.False(await Hit(Sample()));
    [Fact] public async Task Fake_Process_Name_Does_Not_Prove_Tampering() {
        var r = Sample(); r.ProcessName = "carthago-pipeline-killer.exe"; Assert.False(await Hit(r));
    }
    [Fact] public async Task Http_Path_Label_Does_Not_Prove_Tampering() {
        var r = Sample(); r.ApplicationProtocol = "HTTP"; r.HttpMethod = "POST";
        r.HttpHost = "example.net"; r.HttpUri = "/sensor/disable"; Assert.False(await Hit(r));
    }
    [Fact] public async Task Dns_Label_Does_Not_Prove_Tampering() {
        var r = Sample(); r.DnsQname = "pipeline-stopped.example.net"; Assert.False(await Hit(r));
    }
    [Fact] public async Task Tcp_Flags_Do_Not_Prove_Pipeline_Control_Change() {
        var r = Sample(); r.TcpFlags = 0x04; Assert.False(await Hit(r));
    }
    [Fact] public async Task Journal_Deleted_Text_Is_Not_Trusted_Control_Plane_Evidence() {
        var r = Sample(); r.Info = "journal deleted rule engine disabled";
        Assert.False(await Hit(r));
    }
    [Fact] public async Task Process_And_Packet_Description_Corroboration_Still_Not_Trusted() {
        var r = Sample(); r.ProcessName = "powershell.exe"; r.ProcessId = 4100;
        r.Info = "sensor stopped outbox disabled"; Assert.False(await Hit(r));
    }
    [Fact] public async Task Empty_Telemetry_Fails_Closed() {
        var r = Sample(); r.Source = null; r.Destination = null; r.Info = null;
        Assert.False(await Hit(r));
    }
    [Fact] public async Task Contradictory_Protocol_Still_Fails_Closed() {
        var r = Sample(); r.IsUdp = true; r.IsTcp = true; Assert.False(await Hit(r));
    }
    [Fact] public void Critical_Floor_Mode_And_Threshold_Are_Unchanged() {
        var p = new R270_DetectionPipelineTamperingIndicatorRule().PrecisionProfile;
        Assert.Equal(88, p.MinimumConfidence); Assert.Equal(1, p.Threshold);
        Assert.Equal(RuleRuntimeMode.Alert, p.DefaultMode);
    }
}
