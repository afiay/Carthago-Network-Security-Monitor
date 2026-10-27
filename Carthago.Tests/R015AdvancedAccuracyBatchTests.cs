// SPDX-License-Identifier: MIT
using System;
using System.Threading.Tasks;
using Carthago.Engine.Rules;
using Carthago.Engine.Rules.Existing;
using Carthago.Models;
using Carthago.Services;
using Xunit;

namespace Carthago.Tests;

/// <summary>R015: corroborated ARP claim conflicts with sender-MAC consistency.</summary>
[Collection("Legacy rules R011-R015 isolated")]
public sealed class R015AdvancedAccuracyBatchTests : IDisposable
{
    private readonly R015_ArpSpoofingRule _rule = new();
    private static readonly DateTime T0 = new(2026, 10, 27, 7, 0, 0, DateTimeKind.Utc);
    private const string MacA = "02:AA:BB:CC:DD:01";
    private const string MacB = "06:AA:BB:CC:DD:01";
    private const string MacC = "0A:AA:BB:CC:DD:01";
    public R015AdvancedAccuracyBatchTests() => RuleEngine.ResetRuntimeStateForReplay();
    public void Dispose() => RuleEngine.ResetRuntimeStateForReplay();

    private static TrafficRecord Claim(string ip = "10.15.0.1", string mac = MacA)
        => new() { Source = ip, Destination = "10.15.0.2", Protocol = "ARP",
            MacSource = mac, Info = $"ARP reply {ip} is-at {mac}", Length = 60 };

    private async Task<RuleEvaluationResult> See(TrafficRecord r, int second = 0)
        => await _rule.EvaluateAsync(new RuleEvaluationContext(r, Sensitivity.Balanced, T0.AddSeconds(second)));

    [Fact]
    public async Task Two_Temporally_Distinct_Conflicting_Claims_Produce_One_Candidate()
    {
        Assert.False((await See(Claim(), 0)).Matched);
        Assert.False((await See(Claim(mac: MacB), 1)).Matched);
        var evt = Assert.Single((await See(Claim(mac: MacB), 2)).Events);
        Assert.Equal("R015", evt.RuleId);
        Assert.Equal("10.15.0.1", evt.SourceIp);
        Assert.Equal(2, evt.Count);
        Assert.Equal(SeverityLevel.High, evt.Severity);
        Assert.DoesNotContain(MacA, evt.Description);
        Assert.DoesNotContain(MacB, evt.Description);
    }

    [Fact]
    public async Task Single_Conflicting_Claim_Cannot_Prove_Spoofing()
    {
        Assert.False((await See(Claim(), 0)).Matched);
        Assert.False((await See(Claim(mac: MacB), 1)).Matched);
    }

    [Fact]
    public async Task Equivalent_Mac_Formats_Do_Not_Count_As_A_Conflict()
    {
        Assert.False((await See(Claim(), 0)).Matched);
        var same = Claim(mac: "02-aa-bb-cc-dd-01");
        Assert.False((await See(same, 1)).Matched);
        Assert.False((await See(Claim(), 2)).Matched);
    }

    [Fact]
    public async Task Invalid_Ip_Mac_Multicast_And_Missing_Header_Are_Rejected()
    {
        var invalidIp = Claim(ip: "999.15.0.1");
        var publicIp = Claim(ip: "8.8.8.8");
        var multicastMac = Claim(mac: "01:AA:BB:CC:DD:01");
        var missingMac = Claim(); missingMac.MacSource = null;
        var invalidMac = Claim(mac: "zz:aa:bb:cc:dd:01");
        foreach (var record in new[] { invalidIp, publicIp, multicastMac, missingMac, invalidMac })
            Assert.False((await See(record)).Matched);
    }

    [Fact]
    public async Task Contradictory_Ethernet_Header_And_Source_Ip_Cannot_Seed_State()
    {
        var headerConflict = Claim(mac: MacB); headerConflict.MacSource = MacA;
        var sourceConflict = Claim(mac: MacB); sourceConflict.Source = "10.15.0.99";
        Assert.False((await See(headerConflict)).Matched);
        Assert.False((await See(sourceConflict)).Matched);
        Assert.False((await See(Claim(mac: MacB), 1)).Matched);
        Assert.False((await See(Claim(mac: MacA), 2)).Matched);
    }

    [Fact]
    public async Task Expired_Conflict_Requires_Fresh_Second_Corroboration()
    {
        Assert.False((await See(Claim(), 0)).Matched);
        Assert.False((await See(Claim(mac: MacB), 1)).Matched);
        Assert.False((await See(Claim(mac: MacB), 32)).Matched);
        Assert.True((await See(Claim(mac: MacB), 33)).Matched);
    }

    [Fact]
    public async Task Interleaved_Ip_Claims_Are_Independent()
    {
        const string otherIp = "10.15.0.3";
        Assert.False((await See(Claim(), 0)).Matched);
        Assert.False((await See(Claim(otherIp), 0)).Matched);
        Assert.False((await See(Claim(mac: MacB), 1)).Matched);
        Assert.False((await See(Claim(otherIp, MacC), 1)).Matched);
        Assert.Equal("10.15.0.1", Assert.Single((await See(Claim(mac: MacB), 2)).Events).SourceIp);
        Assert.Equal(otherIp, Assert.Single((await See(Claim(otherIp, MacC), 2)).Events).SourceIp);
    }

    [Fact]
    public async Task Baseline_Reassertion_Cancels_Uncorroborated_Conflict()
    {
        Assert.False((await See(Claim(), 0)).Matched);
        Assert.False((await See(Claim(mac: MacB), 1)).Matched);
        Assert.False((await See(Claim(), 2)).Matched);
        Assert.False((await See(Claim(mac: MacB), 3)).Matched);
        Assert.True((await See(Claim(mac: MacB), 4)).Matched);
    }

    [Fact]
    public async Task Same_Timestamp_Duplicates_Cannot_Confirm_A_New_Mac()
    {
        Assert.False((await See(Claim(), 0)).Matched);
        Assert.False((await See(Claim(mac: MacB), 1)).Matched);
        Assert.False((await See(Claim(mac: MacB), 1)).Matched);
        Assert.True((await See(Claim(mac: MacB), 2)).Matched);
    }

    [Fact]
    public async Task Suppressed_Repeat_Still_Updates_Mapping_Without_Emitting_Event()
    {
        await See(Claim(), 0);
        await See(Claim(mac: MacB), 1);
        Assert.True((await See(Claim(mac: MacB), 2)).Matched);
        Assert.False((await See(Claim(mac: MacC), 3)).Matched);
        var repeat = await See(Claim(mac: MacC), 4);
        Assert.True(repeat.Suppressed);
        Assert.Empty(repeat.Events);
        Assert.False((await See(Claim(mac: MacC), 5)).Matched);
    }
}
