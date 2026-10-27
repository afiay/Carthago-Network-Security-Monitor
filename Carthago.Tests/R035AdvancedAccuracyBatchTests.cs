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
public sealed class R035AdvancedAccuracyBatchTests : IDisposable
{
    private readonly R035_RareSshClientFingerprintRule _rule = new();
    private static readonly DateTime T0 = new(2026, 10, 27, 5, 0, 0, DateTimeKind.Utc);
    public R035AdvancedAccuracyBatchTests() => RuleEngine.ResetRuntimeStateForReplay();
    public void Dispose() => RuleEngine.ResetRuntimeStateForReplay();
    private async Task<RuleEvaluationResult> See(TrafficRecord r, int sec = 0)
        => await _rule.EvaluateAsync(new RuleEvaluationContext(r, Sensitivity.Balanced, T0.AddSeconds(sec)));

    private static TrafficRecord Ssh(string fp = "ssh-ja4-fingerprint-001", string src = "10.35.0.2", string dst = "8.8.8.8")
        => new() { Source = src, Destination = dst, Protocol = "SSH", DestinationPort = 22,
            Ja4SSH = fp, Length = 180 };
    [Fact] public async Task First_Observed_Ssh_Fingerprint_Is_Attributed_Without_Value_Leak()
    {
        var e = Assert.Single((await See(Ssh())).Events);
        Assert.Equal("R035", e.RuleId); Assert.Equal(1, e.Count);
        Assert.DoesNotContain("ssh-ja4-fingerprint-001", e.Description);
    }
    [Fact] public async Task NonSsh_Fingerprint_Field_Cannot_Manufacture_Rarity()
    {
        var r = Ssh(); r.Protocol = "HTTP";
        Assert.False((await See(r)).Matched);
        r = Ssh(); r.Protocol = "TCP"; r.ApplicationService = null;
        Assert.False((await See(r)).Matched);
        r = Ssh(); r.ApplicationService = "TLS";
        Assert.False((await See(r)).Matched);
    }
    [Fact] public async Task Missing_Malformed_And_Secret_Bearing_Fingerprints_Are_Excluded()
    {
        var r = Ssh(); r.Ja4SSH = null;
        Assert.False((await See(r)).Matched);
        foreach (string fp in new[] { "bad fingerprint", "bad\nfingerprint", new string('x', 129) })
            Assert.False((await See(Ssh(fp))).Matched);
    }
    [Fact] public async Task Three_Distinct_Observations_Then_Global_Novelty_Expires()
    {
        for (int i = 0; i < 3; i++)
            Assert.Equal(i + 1, Assert.Single((await See(Ssh(src: $"10.35.0.{i+2}"), i)).Events).Count);
        Assert.False((await See(Ssh(src: "10.35.0.9"), 3)).Matched);
        Assert.Equal(1, Assert.Single((await See(Ssh(src: "10.35.0.10"), 4000)).Events).Count);
    }
    [Fact] public async Task Duplicate_Timestamps_Do_Not_Poison_Rarity()
    {
        Assert.Equal(1, Assert.Single((await See(Ssh(), 0)).Events).Count);
        for (int i = 0; i < 20; i++) Assert.True((await See(Ssh(), 0)).Suppressed);
        Assert.Equal(2, Assert.Single((await See(Ssh(src: "10.35.0.3"), 1)).Events).Count);
    }
    [Fact] public async Task Invalid_Endpoints_Empty_Packets_And_Cooldown()
    {
        var r = Ssh(); r.Source = "bad";
        Assert.False((await See(r)).Matched);
        r = Ssh(); r.Length = 0;
        Assert.False((await See(r)).Matched);
        r = Ssh(); r.IsQuic = true;
        Assert.False((await See(r)).Matched);
        Assert.True((await See(Ssh())).Matched);
        Assert.True((await See(Ssh(), 1)).Suppressed);
    }
}
