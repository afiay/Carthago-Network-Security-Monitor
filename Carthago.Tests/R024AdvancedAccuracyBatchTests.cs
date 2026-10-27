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
public sealed class R024AdvancedAccuracyBatchTests : IDisposable
{
    private readonly R024_RareNovelTlsFingerprintRule _rule = new();
    private static readonly DateTime T0 = new(2026, 10, 27, 0, 0, 0, DateTimeKind.Utc);
    public R024AdvancedAccuracyBatchTests() => RuleEngine.ResetRuntimeStateForReplay();
    public void Dispose() => RuleEngine.ResetRuntimeStateForReplay();
    private async Task<RuleEvaluationResult> See(TrafficRecord record, int second = 0)
        => await _rule.EvaluateAsync(new RuleEvaluationContext(record, Sensitivity.Balanced, T0.AddSeconds(second)));

    private static TrafficRecord Tls(string fp = "t13d1516h2_8daaf6152771_b186095e22b6", string src = "10.24.0.2", string dst = "8.8.8.8")
        => new() { Protocol = "TLS", TlsVersion = "TLS1.3", Source = src,
            Destination = dst, DestinationPort = 443, Length = 140, Ja4 = fp };


    [Fact] public async Task First_Observed_Tls_Fingerprint_Is_Attributed_Without_Leaking_Value()
    {
        var evt = Assert.Single((await See(Tls())).Events);
        Assert.Equal("R024", evt.RuleId);
        Assert.Equal(1, evt.Count);
        Assert.DoesNotContain("t13d1516h2_", evt.Description);
        Assert.Equal("10.24.0.2", evt.SourceIp);
    }
    [Fact] public async Task Missing_And_Whitespace_Fingerprints_Are_Not_Evidence()
    {
        var missing = Tls(); missing.Ja4 = null; missing.Ja3 = null;
        Assert.False((await See(missing)).Matched);
        foreach (var fp in new[] { "bad value", "bad\nvalue", new string('x', 129) })
            Assert.False((await See(Tls(fp))).Matched);
    }
    [Fact] public async Task Arbitrary_NonTls_Record_With_Fingerprint_Field_Is_Rejected()
    {
        var r = Tls(); r.Protocol = "HTTP"; r.TlsVersion = null;
        Assert.False((await See(r)).Matched);
        r.Protocol = "UDP"; Assert.False((await See(r)).Matched);
    }
    [Fact] public async Task Novelty_Decays_After_Three_Observations_Across_Distinct_Sources()
    {
        for (int i = 0; i < 3; i++)
        {
            var evt = Assert.Single((await See(Tls(src: $"10.24.0.{i+2}"), i)).Events);
            Assert.Equal(i + 1, evt.Count);
        }
        Assert.False((await See(Tls(src: "10.24.0.5"), 4)).Matched);
    }
    [Fact] public async Task Malformed_Records_Cannot_Poison_First_Seen_Count()
    {
        var invalid = Tls(src: "not-ip");
        var empty = Tls(); empty.Length = 0;
        var quic = Tls(); quic.IsQuic = true;
        foreach (var r in new[] { invalid, empty, quic }) Assert.False((await See(r)).Matched);
        Assert.Equal(1, Assert.Single((await See(Tls(), 1)).Events).Count);
    }
    [Fact] public async Task Same_Fingerprint_Different_Peer_Tracks_Global_Rarity()
    {
        Assert.Equal(1, Assert.Single((await See(Tls(), 0)).Events).Count);
        var second = Assert.Single((await See(Tls(src: "10.24.0.9", dst: "9.9.9.9"), 1)).Events);
        Assert.Equal(2, second.Count);
        Assert.Equal(SeverityLevel.Low, second.Severity);
    }

}
