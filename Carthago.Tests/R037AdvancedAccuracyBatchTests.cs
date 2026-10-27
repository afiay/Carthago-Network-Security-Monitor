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
public sealed class R037AdvancedAccuracyBatchTests : IDisposable
{
    private readonly R037_Ja4DriftPerSniRule _rule = new();
    private static readonly DateTime T0 = new(2026, 10, 27, 6, 0, 0, DateTimeKind.Utc);
    public R037AdvancedAccuracyBatchTests() => RuleEngine.ResetRuntimeStateForReplay();
    public void Dispose() => RuleEngine.ResetRuntimeStateForReplay();
    private async Task<RuleEvaluationResult> See(TrafficRecord r, int seconds = 0)
        => await _rule.EvaluateAsync(new RuleEvaluationContext(r, Sensitivity.Balanced, T0.AddSeconds(seconds)));

    private static TrafficRecord Tls(string fp = "fingerprintA001", string sni = "rare.example.org",
        string src = "10.37.0.2", string dst = "8.8.8.8")
        => new() { Source = src, Destination = dst, Protocol = "TLS", DestinationPort = 443,
            Sni = sni, Ja4 = fp, Length = 220 };
    private static readonly string[] Fps = { "fingerprintA001", "fingerprintB002",
        "fingerprintC003", "fingerprintA001", "fingerprintB002" };

    [Fact] public async Task Three_Distinct_Fingerprints_Across_Five_Handshakes_Match()
    {
        for (int i = 0; i < 4; i++) Assert.False((await See(Tls(Fps[i]), i)).Matched);
        var e = Assert.Single((await See(Tls(Fps[4]), 4)).Events);
        Assert.Equal("R037", e.RuleId); Assert.Equal(3, e.Count);
        Assert.Equal(3600, e.WindowSeconds);
        Assert.DoesNotContain("rare.example.org", e.Description);
        Assert.DoesNotContain("fingerprint", e.Description, StringComparison.OrdinalIgnoreCase);
    }

    [Fact] public async Task Port_443_Without_Observed_Tls_Does_Not_Manufacture_Drift()
    {
        for (int i = 0; i < 5; i++)
        {
            var r = Tls(Fps[i]); r.Protocol = "TCP";
            Assert.False((await See(r, i)).Matched);
        }
    }

    [Fact] public async Task Missing_Or_Malformed_Sni_Fingerprint_And_Endpoints_Are_Rejected()
    {
        foreach (var sni in new[] { "", "not-a-domain", "127.0.0.1", "secret\n.example.org" })
            Assert.False((await See(Tls(sni: sni))).Matched);
        foreach (var fp in new[] { "", "bad fp", "bad\nfp", new string('x', 129) })
            Assert.False((await See(Tls(fp: fp))).Matched);
        Assert.False((await See(Tls(src: "bad"))).Matched);
        Assert.False((await See(Tls(dst: "192.0.2.1"))).Matched);
        var empty = Tls(); empty.Length = 0;
        Assert.False((await See(empty)).Matched);
    }

    [Fact] public async Task Different_Sni_Keys_Never_Aggregate_Fingerprints()
    {
        for (int i = 0; i < 4; i++) Assert.False((await See(Tls(Fps[i]), i)).Matched);
        Assert.False((await See(Tls(Fps[4], sni: "other.example.org"), 4)).Matched);
    }

    [Fact] public async Task Duplicate_Timestamp_Fingerprint_Pairs_Do_Not_Inflate_Observations()
    {
        for (int i = 0; i < 20; i++) Assert.False((await See(Tls(), 0)).Matched);
        for (int i = 1; i < 4; i++) Assert.False((await See(Tls(Fps[i]), i)).Matched);
        Assert.Equal(3, Assert.Single((await See(Tls(Fps[4]), 4)).Events).Count);
    }

    [Fact] public async Task Old_Fingerprints_Expire_Before_Drift_Is_Calculated()
    {
        for (int i = 0; i < 3; i++) Assert.False((await See(Tls(Fps[i]), i)).Matched);
        Assert.False((await See(Tls(Fps[3]), 4000)).Matched);
        Assert.False((await See(Tls(Fps[4]), 4001)).Matched);
        Assert.False((await See(Tls(Fps[2]), 200)).Matched);
    }

    [Fact] public async Task Popular_Sni_Over_Fifty_Observations_Is_Not_Labeled_Rare()
    {
        for (int i = 0; i < 51; i++) Assert.False((await See(Tls(), i)).Matched);
        Assert.False((await See(Tls(Fps[1]), 51)).Matched);
        Assert.False((await See(Tls(Fps[2]), 52)).Matched);
    }
}
