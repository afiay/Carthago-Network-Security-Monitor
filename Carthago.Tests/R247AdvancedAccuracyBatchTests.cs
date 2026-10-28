// SPDX-License-Identifier: MIT
using System;
using System.Threading.Tasks;
using Carthago.Engine.Rules;
using Carthago.Engine.Rules.Expansion;
using Carthago.Models;
using Xunit;

namespace Carthago.Tests;
public sealed class R247AdvancedAccuracyBatchTests
{
    private static TrafficRecord Sample() => NetworkBatch246250Context.Sample(247);
    private static RuleEvaluationContext At(TrafficRecord r, double seconds = 0)
        => NetworkBatch246250Context.At(r, seconds);
    private static async Task<bool> Hit(TrafficRecord r)
        => (await new R247_SshScpHighVolumeEgressRule().EvaluateAsync(At(r))).Matched;

    // Realistic 65,535-byte packet records: 2,401 unique observations cross
    // 150 MiB. This is packet-byte contract evidence, not TCP delivered bytes.
    private static async Task Seed(R247_SshScpHighVolumeEgressRule rule, int count,
        string source = "10.247.0.10", double start = 0)
    {
        for (var i = 0; i < count; i++) {
            var r = Sample(); r.Source = source;
            await rule.EvaluateAsync(At(r, start + i / 1000.0));
        }
    }
    [Fact] public async Task Distinct_Observed_Packet_Bytes_Reach_Threshold() {
        var rule = new R247_SshScpHighVolumeEgressRule();
        await Seed(rule, 2400);
        Assert.True((await rule.EvaluateAsync(At(Sample(), 3))).Matched);
    }
    [Fact] public async Task Below_Threshold_Is_Benign() {
        var rule = new R247_SshScpHighVolumeEgressRule();
        await Seed(rule, 2400);
        var r = Sample(); r.Length = 1000;
        Assert.False((await rule.EvaluateAsync(At(r, 3))).Matched);
    }
    [Fact] public async Task Port_Only_Without_File_Transfer_Process_Is_Not_Enough() {
        var r = Sample(); r.ProcessName = null; r.Info = "scp 500MB upload";
        Assert.False(await Hit(r));
    }
    [Fact] public async Task Approved_Backup_Process_Is_Suppressed() {
        var r = Sample(); r.ProcessName = "veeamagent.exe"; Assert.False(await Hit(r));
    }
    [Fact] public async Task Tls_Contradiction_Is_Rejected() {
        var r = Sample(); r.TlsVersion = "TLS1.3"; Assert.False(await Hit(r));
    }
    [Fact] public async Task Duplicate_Id_Does_Not_Inflate_Window() {
        var rule = new R247_SshScpHighVolumeEgressRule();
        await Seed(rule, 2399);
        var r = Sample();
        Assert.False((await rule.EvaluateAsync(At(r, 3))).Matched);
        Assert.False((await rule.EvaluateAsync(At(r, 3.1))).Matched);
        Assert.True((await rule.EvaluateAsync(At(Sample(), 3.2))).Matched);
    }
    [Fact] public async Task Out_Of_Order_Packet_Does_Not_Inflate_Window() {
        var rule = new R247_SshScpHighVolumeEgressRule();
        await Seed(rule, 2400);
        Assert.False((await rule.EvaluateAsync(At(Sample(), 1))).Matched);
        Assert.True((await rule.EvaluateAsync(At(Sample(), 3))).Matched);
    }
    [Fact] public async Task Independent_Sources_Do_Not_Share_Bytes() {
        var rule = new R247_SshScpHighVolumeEgressRule();
        await Seed(rule, 2400);
        var other = Sample(); other.Source = "10.247.0.20";
        Assert.False((await rule.EvaluateAsync(At(other, 3))).Matched);
        Assert.True((await rule.EvaluateAsync(At(Sample(), 3.1))).Matched);
    }
    [Fact] public async Task Expired_Observations_Do_Not_Accumulate() {
        var rule = new R247_SshScpHighVolumeEgressRule();
        await Seed(rule, 2400);
        Assert.False((await rule.EvaluateAsync(At(Sample(), 1260))).Matched);
    }
    [Fact] public void Original_Alert_Mode_And_Confidence_Are_Preserved() {
        var p = new R247_SshScpHighVolumeEgressRule().PrecisionProfile;
        Assert.Equal(82, p.MinimumConfidence); Assert.Equal(RuleRuntimeMode.Alert, p.DefaultMode);
    }

}
