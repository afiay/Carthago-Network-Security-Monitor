// SPDX-License-Identifier: MIT
using System;
using System.Threading.Tasks;
using Carthago.Engine.Rules;
using Carthago.Engine.Rules.Expansion;
using Carthago.Models;
using Xunit;

namespace Carthago.Tests;
public sealed class R260AdvancedAccuracyBatchTests
{
    private static TrafficRecord Sample() => NetworkBatch256260Context.Sample(260);
    private static RuleEvaluationContext At(TrafficRecord r, double seconds = 0)
        => NetworkBatch256260Context.At(r, seconds);
    private static async Task<bool> Hit(TrafficRecord r)
        => (await new R260_RareTcpOptionFingerprintRule().EvaluateAsync(At(r))).Matched;
    [Fact] public async Task Changed_Syn_Ja4t_After_First_Observation_Matches() {
        var rule = new R260_RareTcpOptionFingerprintRule();
        Assert.False((await rule.EvaluateAsync(At(Sample()))).Matched);
        var changed = Sample(); changed.Ja4T = "t13d_2_2_2";
        Assert.True((await rule.EvaluateAsync(At(changed, 1))).Matched);
    }
    [Fact] public async Task First_Observation_Is_Not_Rarity_Proof()
        => Assert.False(await Hit(Sample()));
    [Fact] public async Task Repeated_Same_Fingerprint_Is_Benign() {
        var rule = new R260_RareTcpOptionFingerprintRule();
        Assert.False((await rule.EvaluateAsync(At(Sample()))).Matched);
        Assert.False((await rule.EvaluateAsync(At(Sample(), 1))).Matched);
    }
    [Fact] public async Task Info_Spoof_Cannot_Supply_Ja4t() {
        var r = Sample(); r.Ja4T = null; r.Info = "rare tcp option t13d_1_1_1";
        Assert.False(await Hit(r));
    }
    [Fact] public async Task Non_Syn_Packet_Is_Rejected() {
        var r = Sample(); r.TcpFlags = 0x10; Assert.False(await Hit(r));
    }
    [Fact] public async Task Syn_Rst_Contradiction_Is_Rejected() {
        var r = Sample(); r.TcpFlags = 0x06; Assert.False(await Hit(r));
    }
    [Fact] public async Task Malformed_Fingerprint_Is_Rejected() {
        var r = Sample(); r.Ja4T = "secret/path with spaces"; Assert.False(await Hit(r));
    }
    [Fact] public async Task Duplicate_And_Out_Of_Order_Are_Rejected() {
        var rule = new R260_RareTcpOptionFingerprintRule(); var first = Sample();
        Assert.False((await rule.EvaluateAsync(At(first, 20))).Matched);
        first.Ja4T = "t13d_2_2_2";
        Assert.False((await rule.EvaluateAsync(At(first, 21))).Matched);
        var older = Sample(); older.Ja4T = "t13d_2_2_2";
        Assert.False((await rule.EvaluateAsync(At(older, 1))).Matched);
    }
    [Fact] public async Task Source_Isolation_Prevents_False_Change() {
        var rule = new R260_RareTcpOptionFingerprintRule();
        Assert.False((await rule.EvaluateAsync(At(Sample()))).Matched);
        var second = Sample(); second.Source = "10.60.0.11"; second.Ja4T = "t13d_2_2_2";
        Assert.False((await rule.EvaluateAsync(At(second, 1))).Matched);
    }
    [Fact] public async Task Raw_Fingerprint_And_Info_Are_Not_In_Evidence() {
        var rule = new R260_RareTcpOptionFingerprintRule();
        Assert.False((await rule.EvaluateAsync(At(Sample()))).Matched);
        var second = Sample(); second.Ja4T = "t13d_2_2_2"; second.Info = "secret-marker";
        var result = await rule.EvaluateAsync(At(second, 1));
        var evt = Assert.Single(result.Events);
        Assert.DoesNotContain("secret-marker", evt.Evidence ?? "", StringComparison.Ordinal);
        Assert.DoesNotContain("t13d_2_2_2", evt.Evidence ?? "", StringComparison.Ordinal);
    }
    [Fact] public async Task Contradictory_Tls_Metadata_Is_Rejected() {
        var r = Sample(); r.TlsVersion = "TLS1.3"; Assert.False(await Hit(r));
    }
    [Fact] public void Original_Alert_Confidence_And_Threshold_Remain() {
        var p = new R260_RareTcpOptionFingerprintRule().PrecisionProfile;
        Assert.Equal(75, p.MinimumConfidence); Assert.Equal(1, p.Threshold);
        Assert.Equal(RuleRuntimeMode.Alert, p.DefaultMode);
    }
}
