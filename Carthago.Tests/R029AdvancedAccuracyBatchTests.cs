// SPDX-License-Identifier: MIT
using System;
using System.Threading.Tasks;
using Carthago.Engine.Rules;
using Carthago.Engine.Rules.Existing;
using Carthago.Models;
using Carthago.Services;
using Xunit;
namespace Carthago.Tests;

[Collection("Legacy rules R011-R015 isolated")]
public sealed class R029AdvancedAccuracyBatchTests : IDisposable
{
    private readonly R029_QuicAnomalyRule _rule = new();
    private static readonly DateTime T0 = new(2026, 10, 27, 4, 0, 0, DateTimeKind.Utc);
    public R029AdvancedAccuracyBatchTests() => RuleEngine.ResetRuntimeStateForReplay();
    public void Dispose() => RuleEngine.ResetRuntimeStateForReplay();
    private async Task<RuleEvaluationResult> See(TrafficRecord r, int sec = 0)
        => await _rule.EvaluateAsync(new RuleEvaluationContext(r, Sensitivity.Balanced, T0.AddSeconds(sec)));
    private static TrafficRecord Quic(string src = "10.29.0.2", string dst = "8.8.8.8",
        int port = 8443, string protocol = "UDP")
        => new() { Source = src, Destination = dst, DestinationPort = port,
            Protocol = protocol, IsQuic = true, QuicVersion = "1", Length = 120 };
    [Fact] public async Task Observed_Nonstandard_Quic_Without_Alpn_Is_Attributed()
    {
        var e = Assert.Single((await See(Quic())).Events);
        Assert.Equal("R029", e.RuleId); Assert.Equal("10.29.0.2", e.SourceIp);
        Assert.Equal(8443, e.DestinationPort); Assert.Equal(SeverityLevel.Low, e.Severity);
    }

    [Fact] public async Task Standard_Dns_Ntp_Ports_And_Observed_Alpn_Are_Excluded()
    {
        foreach (int p in new[] { 53, 123, 443 })
            Assert.False((await See(Quic(port: p))).Matched);
        var alpn = Quic(); alpn.QuicAlpn = "h3";
        Assert.False((await See(alpn)).Matched);
    }

    [Fact] public async Task Uncorroborated_Quic_Metadata_Is_Not_Observation()
    {
        var r = Quic(); r.IsQuic = false;
        Assert.False((await See(r)).Matched);
        r.QuicAlpn = "h3"; Assert.False((await See(r)).Matched);
        var parsed = Quic(protocol: "QUIC"); parsed.IsQuic = false;
        Assert.Equal("R029", Assert.Single((await See(parsed)).Events).RuleId);
    }

    [Fact] public async Task Tcp_And_Invalid_Endpoints_Are_Excluded()
    {
        Assert.False((await See(Quic(protocol: "TCP"))).Matched);
        foreach (var dst in new[] { "10.0.0.1", "127.0.0.1", "192.0.2.1", "bad" })
            Assert.False((await See(Quic(dst: dst))).Matched);
        foreach (var src in new[] { "8.8.8.8", "127.0.0.1", "bad" })
            Assert.False((await See(Quic(src: src))).Matched);
    }

    [Fact] public async Task Invalid_Ports_And_Empty_Packets_Are_Not_Anomalies()
    {
        foreach (int p in new[] { 0, 65536 })
            Assert.False((await See(Quic(port: p))).Matched);
        var r = Quic(); r.Length = 0; Assert.False((await See(r)).Matched);
    }

    [Fact] public async Task Per_Flow_Debounce_Blocks_Fourth_But_Not_Unrelated_Destination()
    {
        Assert.True((await See(Quic(), 0)).Matched);
        Assert.True((await See(Quic(), 1)).Suppressed);
        Assert.True((await See(Quic(), 2)).Suppressed);
        Assert.False((await See(Quic(), 3)).Matched);
        Assert.Equal("9.9.9.9", Assert.Single((await See(Quic(dst: "9.9.9.9"), 3)).Events).DestinationIp);
    }

    [Fact] public async Task Expired_Debounce_And_Cooldown_Allow_New_Observation()
    {
        Assert.True((await See(Quic(), 0)).Matched);
        Assert.True((await See(Quic(), 1)).Suppressed);
        Assert.Equal("R029", Assert.Single((await See(Quic(), 120)).Events).RuleId);
    }

    [Fact] public async Task Duplicate_Timestamps_Do_Not_Consume_Budget_Or_Leak_Info()
    {
        var r = Quic(); r.Info = "SECRET QUIC payload";
        var e = Assert.Single((await See(r, 0)).Events);
        Assert.DoesNotContain("SECRET", e.Description);
        for (int i = 0; i < 8; i++) Assert.True((await See(r, 0)).Suppressed);
        Assert.True((await See(r, 1)).Suppressed);
    }
}
