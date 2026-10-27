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
public sealed class R039AdvancedAccuracyBatchTests : IDisposable
{
    private readonly R039_AsnNoveltyOnSensitiveVlansRule _rule = new();
    private static readonly DateTime T0 = new(2026, 10, 27, 6, 0, 0, DateTimeKind.Utc);
    public R039AdvancedAccuracyBatchTests() => RuleEngine.ResetRuntimeStateForReplay();
    public void Dispose() => RuleEngine.ResetRuntimeStateForReplay();
    private async Task<RuleEvaluationResult> See(TrafficRecord r, int seconds = 0)
        => await _rule.EvaluateAsync(new RuleEvaluationContext(r, Sensitivity.Balanced, T0.AddSeconds(seconds)));

    private static TrafficRecord Sensitive(string asn = "AS64500 Example Networks", string src = "10.39.0.2",
        string dst = "8.8.8.8", string networkType = "OT")
        => new() { Source = src, Destination = dst, Protocol = "TLS", DestinationPort = 443,
            NetworkType = networkType, WhoisASN = asn, Length = 240 };

    [Fact] public async Task Explicit_Sensitive_Egress_With_Valid_Asn_Is_Observed_Once()
    {
        var e = Assert.Single((await See(Sensitive())).Events);
        Assert.Equal("R039", e.RuleId); Assert.Equal(SeverityLevel.High, e.Severity);
        Assert.Equal("10.39.0.2", e.SourceIp);
        Assert.DoesNotContain("Example Networks", e.Description);
        Assert.False((await See(Sensitive(), 1)).Matched);
    }

    [Fact] public async Task Distinct_Sensitive_Sources_Have_Independent_Novelty()
    {
        Assert.True((await See(Sensitive())).Matched);
        var e = Assert.Single((await See(Sensitive(src: "10.39.0.3"), 1)).Events);
        Assert.Equal("10.39.0.3", e.SourceIp);
    }

    [Fact] public async Task Office_Or_Missing_Sensitivity_Does_Not_Masquerade_As_Sensitive()
    {
        Assert.False((await See(Sensitive(networkType: "Office"))).Matched);
        Assert.False((await See(Sensitive(networkType: ""))).Matched);
        Assert.True((await See(Sensitive(networkType: "PCI"), 1)).Matched);
    }

    [Fact] public async Task Invalid_And_Out_Of_Range_Asn_Labels_Are_Excluded()
    {
        foreach (string asn in new[] { "", "64500", "AS0", "AS4294967296", "AS1234bad", "AS-123" })
            Assert.False((await See(Sensitive(asn: asn))).Matched);
        Assert.True((await See(Sensitive(), 1)).Matched);
    }

    [Fact] public async Task Inbound_Private_Documentation_And_Unattributed_Flows_Are_Not_Egress()
    {
        Assert.False((await See(Sensitive(src: "8.8.4.4", dst: "10.39.0.2"))).Matched);
        Assert.False((await See(Sensitive(dst: "192.0.2.1"))).Matched);
        Assert.False((await See(Sensitive(src: "bad"))).Matched);
        var r = Sensitive(); r.Length = 0;
        Assert.False((await See(r)).Matched);
        Assert.True((await See(Sensitive(), 1)).Matched);
    }

    [Fact] public async Task Out_Of_Order_Observations_Cannot_Overwrite_Novelty()
    {
        Assert.True((await See(Sensitive(), 100)).Matched);
        Assert.False((await See(Sensitive(), 10)).Matched);
        Assert.False((await See(Sensitive(), 101)).Matched);
    }

    [Fact] public async Task ASN_Organization_Text_Cannot_Leak_Into_Alert()
    {
        var e = Assert.Single((await See(Sensitive(asn: "as64500 Confidential Customer Name"))).Events);
        Assert.Contains("AS64500", e.Description);
        Assert.DoesNotContain("Confidential", e.Description);
    }
}
