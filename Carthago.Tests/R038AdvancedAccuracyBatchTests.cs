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
public sealed class R038AdvancedAccuracyBatchTests : IDisposable
{
    private readonly R038_EncryptedDnsBootstrapRule _rule = new();
    private static readonly DateTime T0 = new(2026, 10, 27, 6, 0, 0, DateTimeKind.Utc);
    public R038AdvancedAccuracyBatchTests() => RuleEngine.ResetRuntimeStateForReplay();
    public void Dispose() => RuleEngine.ResetRuntimeStateForReplay();
    private async Task<RuleEvaluationResult> See(TrafficRecord r, int seconds = 0)
        => await _rule.EvaluateAsync(new RuleEvaluationContext(r, Sensitivity.Balanced, T0.AddSeconds(seconds)));

    private static TrafficRecord Doh(string src = "10.38.0.2", string uri = "/dns-query?dns=AbCdEfGh1234")
        => new() { Source = src, Destination = "8.8.8.8", Protocol = "HTTPS", DestinationPort = 443,
            HttpMethod = "GET", HttpUri = uri, Length = 210 };
    private static TrafficRecord Quic(string src = "10.38.0.2")
        => new() { Source = src, Destination = "9.9.9.9", Protocol = "QUIC", IsQuic = true,
            DestinationPort = 443, Sni = "p8r4x9t2m6q1v7z5.example.net", Length = 200 };

    [Fact] public async Task Ten_Structured_Doh_And_Three_High_Entropy_Quic_Observations_Correlate()
    {
        for (int i = 0; i < 10; i++) Assert.False((await See(Doh(), i)).Matched);
        for (int i = 0; i < 2; i++) Assert.False((await See(Quic(), 10 + i)).Matched);
        var e = Assert.Single((await See(Quic(), 12)).Events);
        Assert.Equal("R038", e.RuleId); Assert.Equal(23, e.Count);
        Assert.Equal(300, e.WindowSeconds);
    }

    [Fact] public async Task Dns_Over_Https_Alone_Is_Not_Corroborated_Bootstrap()
    {
        for (int i = 0; i < 12; i++) Assert.False((await See(Doh(), i)).Matched);
    }

    [Fact] public async Task Quic_Alone_Is_Not_Corroborated_Bootstrap()
    {
        for (int i = 0; i < 12; i++) Assert.False((await See(Quic(), i)).Matched);
    }

    [Fact] public async Task Different_Clients_Cannot_Join_Separate_Hypotheses()
    {
        for (int i = 0; i < 10; i++) Assert.False((await See(Doh(), i)).Matched);
        for (int i = 10; i < 13; i++) Assert.False((await See(Quic(src: "10.38.0.3"), i)).Matched);
        for (int i = 13; i < 15; i++) Assert.False((await See(Quic(), i)).Matched);
        Assert.True((await See(Quic(), 15)).Matched);
    }

    [Fact] public async Task Prose_Header_And_Invalid_Doh_Method_Cannot_Seed_Correlation()
    {
        for (int i = 0; i < 12; i++)
        {
            var r = Doh(); r.HttpMethod = null; r.HttpUri = null;
            r.Info = "GET /dns-query?dns=AbCdEfGh1234 HTTP/1.1";
            Assert.False((await See(r, i)).Matched);
            r = Doh(uri: "/health?dns=AbCdEfGh1234");
            Assert.False((await See(r, i)).Matched);
            r = Doh(); r.HttpMethod = "POST"; r.HttpRequestHeaders = "Content-Type: application/json";
            Assert.False((await See(r, i)).Matched);
        }
        for (int i = 13; i < 16; i++) Assert.False((await See(Quic(), i)).Matched);
    }

    [Fact] public async Task Duplicate_Timestamps_And_Expired_Corroboration_Are_Excluded()
    {
        for (int i = 0; i < 20; i++) Assert.False((await See(Doh(), 0)).Matched);
        for (int i = 1; i < 4; i++) Assert.False((await See(Quic(), i)).Matched);
        RuleEngine.ResetRuntimeStateForReplay();
        for (int i = 0; i < 10; i++) Assert.False((await See(Doh(), i)).Matched);
        for (int i = 500; i < 503; i++) Assert.False((await See(Quic(), i)).Matched);
    }

    [Fact] public async Task Contradictory_Transport_Invalid_Endpoints_And_Ports_Do_Not_Seed()
    {
        var a = Doh(); a.DestinationPort = 80;
        var b = Doh(); b.Source = "bad";
        var c = Doh(); c.Destination = "192.0.2.1";
        var d = Quic(); d.IsQuic = false; d.Protocol = "HTTP";
        var e = Quic(); e.Sni = "a.example.net";
        var f = Quic(); f.Length = 0;
        foreach (var r in new[] { a, b, c, d, e, f })
            for (int i = 0; i < 12; i++) Assert.False((await See(r, i)).Matched);
    }

    [Fact] public async Task Suppressed_Bootstrap_Clears_Both_Windows()
    {
        for (int i = 0; i < 10; i++) await See(Doh(), i);
        for (int i = 10; i < 13; i++) await See(Quic(), i);
        for (int i = 13; i < 23; i++) Assert.False((await See(Doh(), i)).Matched);
        for (int i = 23; i < 25; i++) Assert.False((await See(Quic(), i)).Matched);
        Assert.True((await See(Quic(), 25)).Suppressed);
        Assert.False((await See(Doh(), 26)).Matched);
    }
}
