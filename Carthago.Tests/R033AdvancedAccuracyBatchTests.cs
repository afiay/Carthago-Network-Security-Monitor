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
public sealed class R033AdvancedAccuracyBatchTests : IDisposable
{
    private readonly R033_IcmpOversizedEchoPayloadRule _rule = new();
    private static readonly DateTime T0 = new(2026, 10, 27, 5, 0, 0, DateTimeKind.Utc);
    public R033AdvancedAccuracyBatchTests() => RuleEngine.ResetRuntimeStateForReplay();
    public void Dispose() => RuleEngine.ResetRuntimeStateForReplay();
    private async Task<RuleEvaluationResult> See(TrafficRecord r, int sec = 0)
        => await _rule.EvaluateAsync(new RuleEvaluationContext(r, Sensitivity.Balanced, T0.AddSeconds(sec)));

    private static TrafficRecord Echo(int bytes = 1000, ushort type = 0x0800, string src = "10.33.0.2", string dst = "8.8.8.8")
        => new() { Source = src, Destination = dst, Protocol = "ICMP", Length = bytes, IcmpTypeCode = type };
    [Fact] public async Task Observed_Oversized_Echo_At_Boundary_Is_Attributed()
    {
        var e = Assert.Single((await See(Echo())).Events);
        Assert.Equal("R033", e.RuleId); Assert.Equal(1000, e.Count);
        Assert.Equal(SeverityLevel.Medium, e.Severity);
    }
    [Fact] public async Task Short_Echo_Packets_Do_Not_Trigger()
    {
        foreach (int size in new[] { 0, 1, 999 })
            Assert.False((await See(Echo(bytes: size))).Matched);
    }
    [Fact] public async Task Errors_Redirects_And_Unrelated_Icmp_Are_Excluded()
    {
        foreach (ushort code in new ushort[] { 0x0301, 0x0500, 0x0b00, 0x0104 })
            Assert.False((await See(Echo(type: code))).Matched);
    }
    [Fact] public async Task Missing_Type_And_NonIcmp_Protocol_Are_Excluded()
    {
        var r = Echo(); r.IcmpTypeCode = null;
        Assert.False((await See(r)).Matched);
        r = Echo(); r.Protocol = "UDP";
        Assert.False((await See(r)).Matched);
    }
    [Fact] public async Task Ipv6_Echo_Request_And_Reply_Are_Recognized()
    {
        Assert.Equal("R033", Assert.Single((await See(Echo(type: 0x8000))).Events).RuleId);
        Assert.Equal("9.9.9.9", Assert.Single((await See(Echo(type: 0x8100, dst: "9.9.9.9"))).Events).DestinationIp);
    }
    [Fact] public async Task Invalid_Endpoints_And_Duplicate_Cooldown()
    {
        Assert.False((await See(Echo(src: "bad"))).Matched);
        Assert.False((await See(Echo(dst: "bad"))).Matched);
        Assert.True((await See(Echo())).Matched);
        Assert.True((await See(Echo(), 1)).Suppressed);
    }
}
