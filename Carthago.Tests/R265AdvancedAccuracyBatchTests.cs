// SPDX-License-Identifier: MIT
using System;
using System.Threading.Tasks;
using Carthago.Engine.Rules;
using Carthago.Engine.Rules.Expansion;
using Carthago.Models;
using Xunit;

namespace Carthago.Tests;
public sealed class R265AdvancedAccuracyBatchTests
{
    private static TrafficRecord Sample() => NetworkBatch261265Context.Sample(265);
    private static RuleEvaluationContext At(TrafficRecord r, double seconds = 0)
        => NetworkBatch261265Context.At(r, seconds);
    private static async Task<bool> Hit(TrafficRecord r)
        => (await new R265_PublicVpnProxyDomainContactRule().EvaluateAsync(At(r))).Matched;
    [Fact] public async Task Exact_Tls_Provider_Sni_Matches()
        => Assert.True(await Hit(Sample()));
    [Fact] public async Task Packet_Info_Spoof_Is_Rejected() {
        var r = Sample(); r.Sni = null; r.Info = "nordvpn.com vpn";
        Assert.False(await Hit(r));
    }
    [Fact] public async Task Suffix_Impersonation_Is_Rejected() {
        var r = Sample(); r.Sni = "nordvpn.com.evil.example"; Assert.False(await Hit(r));
    }
    [Fact] public async Task Missing_Tls_Provenance_Is_Rejected() {
        var r = Sample(); r.TlsVersion = null; Assert.False(await Hit(r));
    }
    [Fact] public async Task Dns_Query_Alone_Does_Not_Prove_Connection() {
        var r = Sample(); r.Sni = null; r.TlsVersion = null; r.DnsQname = "nordvpn.com";
        Assert.False(await Hit(r));
    }
    [Fact] public async Task Internal_Destination_Is_Rejected() {
        var r = Sample(); r.Destination = "10.61.0.20"; Assert.False(await Hit(r));
    }
    [Fact] public async Task Udp_Contradiction_Is_Rejected() {
        var r = Sample(); r.IsUdp = true; Assert.False(await Hit(r));
    }
    [Fact] public async Task Unknown_Provider_Is_Benign() {
        var r = Sample(); r.Sni = "updates.example.com"; Assert.False(await Hit(r));
    }
    [Fact] public async Task Info_Is_Not_Emitted_In_Matched_Evidence() {
        var r = Sample(); r.Info = "secret-marker";
        var evt = Assert.Single((await new R265_PublicVpnProxyDomainContactRule().EvaluateAsync(At(r))).Events);
        Assert.DoesNotContain("secret-marker", evt.Evidence ?? "", StringComparison.Ordinal);
    }
    [Fact] public void Original_Confidence_Threshold_And_Mode_Are_Preserved() {
        var p = new R265_PublicVpnProxyDomainContactRule().PrecisionProfile;
        Assert.Equal(75, p.MinimumConfidence);
        Assert.Equal(1, p.Threshold);
        Assert.Equal(RuleRuntimeMode.Alert, p.DefaultMode);
    }
}
