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
public sealed class R049AdvancedAccuracyBatchTests : IDisposable
{
    private readonly R049_SuspiciousSniShapeRule _rule = new();
    private static readonly DateTime T0 = new(2026, 10, 27, 8, 0, 0, DateTimeKind.Utc);
    public R049AdvancedAccuracyBatchTests() => RuleEngine.ResetRuntimeStateForReplay();
    public void Dispose() => RuleEngine.ResetRuntimeStateForReplay();
    private async Task<RuleEvaluationResult> See(TrafficRecord r, int sec = 0)
        => await _rule.EvaluateAsync(new RuleEvaluationContext(r, Sensitivity.Balanced, T0.AddSeconds(sec)));
    private static TrafficRecord Tls(string sni = "verylongsubdomainwithmanylettersanddigits123456.example.org")
        => new() { Source = "10.49.0.2", Destination = "8.8.8.8", Protocol = "TLS",
            DestinationPort = 443, Sni = sni, Length = 240 };

    [Fact] public async Task Long_Tls_Sni_Matches_Without_Leaking_Hostname()
    {
        var e = Assert.Single((await See(Tls())).Events);
        Assert.Equal("R049", e.RuleId);
        Assert.DoesNotContain("verylongsubdomain", e.Description);
    }
    [Fact] public async Task Single_Label_Tls_Sni_Retains_Legacy_Heuristic()
    {
        Assert.True((await See(Tls("unqualified"))).Matched);
    }
    [Fact] public async Task Normal_Short_Sni_Does_Not_Match()
    {
        Assert.False((await See(Tls("www.example.com"))).Matched);
    }
    [Fact] public async Task Tcp443_And_Http_Metadata_Are_Not_Tls_Handshake()
    {
        var r = Tls(); r.Protocol = "TCP"; Assert.False((await See(r)).Matched);
        r = Tls(); r.Protocol = "HTTP"; Assert.False((await See(r)).Matched);
        r = Tls(); r.IsQuic = true; Assert.False((await See(r)).Matched);
    }
    [Fact] public async Task Invalid_And_Contradictory_Sni_Excluded()
    {
        Assert.False((await See(Tls("bad\r\nHost: evil.example"))).Matched);
        Assert.False((await See(Tls("8.8.8.8"))).Matched);
        Assert.False((await See(Tls(new string('a', 254)))).Matched);
    }
    [Fact] public async Task Private_Destination_And_Zero_Length_Excluded()
    {
        var r = Tls(); r.Destination = "192.168.1.4"; Assert.False((await See(r)).Matched);
        r = Tls(); r.Length = 0; Assert.False((await See(r)).Matched);
        r = Tls(); r.Source = "bad"; Assert.False((await See(r)).Matched);
    }
    [Fact] public async Task Duplicate_Alert_Is_Suppressed()
    {
        Assert.True((await See(Tls())).Matched);
        Assert.True((await See(Tls(), 1)).Suppressed);
    }
}