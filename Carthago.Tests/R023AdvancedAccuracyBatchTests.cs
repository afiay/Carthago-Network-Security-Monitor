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
public sealed class R023AdvancedAccuracyBatchTests : IDisposable
{
    private readonly R023_TlsToPublicIpWithoutSniRule _rule = new();
    private static readonly DateTime T0 = new(2026, 10, 27, 0, 0, 0, DateTimeKind.Utc);
    public R023AdvancedAccuracyBatchTests() => RuleEngine.ResetRuntimeStateForReplay();
    public void Dispose() => RuleEngine.ResetRuntimeStateForReplay();
    private async Task<RuleEvaluationResult> See(TrafficRecord record, int second = 0)
        => await _rule.EvaluateAsync(new RuleEvaluationContext(record, Sensitivity.Balanced, T0.AddSeconds(second)));

    private static TrafficRecord Tls(string dst = "8.8.8.8", string src = "10.23.0.2", int port = 443)
        => new() { Protocol = "TCP", TlsVersion = "TLS1.3", Source = src,
            Destination = dst, DestinationPort = port, Length = 96 };


    [Fact] public async Task Three_Observed_NoSni_Tls_Connections_Produce_One_Attributed_Candidate()
    {
        Assert.False((await See(Tls(), 0)).Matched);
        Assert.False((await See(Tls(), 1)).Matched);
        var evt = Assert.Single((await See(Tls(), 2)).Events);
        Assert.Equal("R023", evt.RuleId);
        Assert.Equal("10.23.0.2", evt.SourceIp);
        Assert.Equal("8.8.8.8", evt.DestinationIp);
        Assert.Equal(3, evt.Count);
    }
    [Fact] public async Task Port443_Without_Tls_Handshake_Evidence_Does_Not_Qualify()
    {
        var r = Tls(); r.TlsVersion = null;
        for (int i = 0; i < 5; i++) Assert.False((await See(r, i)).Matched);
        Assert.False((await See(Tls(), 6)).Matched);
    }
    [Fact] public async Task Hostname_Sni_Excludes_But_Ip_Literal_Sni_Remains_A_Candidate()
    {
        var named = Tls(); named.Sni = "example.org";
        for (int i = 0; i < 5; i++) Assert.False((await See(named, i)).Matched);
        var literal = Tls(); literal.Sni = "8.8.8.8";
        Assert.False((await See(literal, 10)).Matched);
        Assert.False((await See(literal, 11)).Matched);
        Assert.True((await See(literal, 12)).Matched);
    }
    [Fact] public async Task Nonpublic_Destinations_And_Unattributed_Sources_Are_Rejected()
    {
        foreach (var dst in new[] { "10.0.0.2", "127.0.0.1", "192.0.2.1", "203.0.113.1", "bad" })
            for (int i = 0; i < 4; i++) Assert.False((await See(Tls(dst: dst), i)).Matched);
        for (int i = 0; i < 4; i++) Assert.False((await See(Tls(src: "not-ip"), i)).Matched);
    }
    [Fact] public async Task Duplicated_Capture_Timestamps_Cannot_Satisfy_Persistence()
    {
        for (int i = 0; i < 10; i++) Assert.False((await See(Tls(), 0)).Matched);
        Assert.False((await See(Tls(), 1)).Matched);
        Assert.True((await See(Tls(), 2)).Matched);
    }
    [Fact] public async Task Port_And_Destination_State_Are_Independent()
    {
        await See(Tls(), 0); await See(Tls(), 1);
        await See(Tls(port: 8443), 0); await See(Tls(port: 8443), 1);
        await See(Tls(dst: "9.9.9.9"), 0); await See(Tls(dst: "9.9.9.9"), 1);
        Assert.Equal(8443, Assert.Single((await See(Tls(port: 8443), 2)).Events).DestinationPort);
        Assert.Equal("9.9.9.9", Assert.Single((await See(Tls(dst: "9.9.9.9"), 2)).Events).DestinationIp);
    }
    [Fact] public async Task Quic_Is_Not_Classic_Tls_NoSni_Evidence()
    {
        var r = Tls(); r.IsQuic = true;
        for (int i = 0; i < 4; i++) Assert.False((await See(r, i)).Matched);
    }

}
