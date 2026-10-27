// SPDX-License-Identifier: MIT
using System;
using System.Threading.Tasks;
using Carthago.Engine.Rules;
using Carthago.Engine.Rules.Existing;
using Carthago.Models;
using Carthago.Services;
using Xunit;

namespace Carthago.Tests;

/// <summary>R010: destination geolocation versus WHOIS/source-country decoys.</summary>
[Collection("Legacy rules R006-R010 isolated")]
public sealed class R010AdvancedAccuracyBatchTests : IDisposable
{
    private readonly R010_GeoIpRule _rule = new();
    private static readonly DateTime T0 = new(2026, 10, 27, 5, 0, 0, DateTimeKind.Utc);
    public R010AdvancedAccuracyBatchTests() => RuleEngine.ResetRuntimeStateForReplay();
    public void Dispose() => RuleEngine.ResetRuntimeStateForReplay();

    private static TrafficRecord Flow(string source = "10.210.0.1",
        string? destination = "8.8.8.8", string? destinationIso2 = null,
        string? whois = null, string? sourceIso2 = null)
        => new() { Source = source, Destination = destination, DestinationPort = 443,
            Protocol = "TCP", Length = 120, DstCountryIso2 = destinationIso2,
            WhoisCountry = whois, SrcCountryIso2 = sourceIso2 };

    private async Task<RuleEvaluationResult> See(TrafficRecord record, int second = 0)
        => await _rule.EvaluateAsync(new RuleEvaluationContext(
            record, Sensitivity.Balanced, T0.AddSeconds(second)));

    [Fact]
    public async Task Blacklisted_Destination_GeoIp_Is_Attributed_To_Destination()
    {
        var evt = Assert.Single((await See(Flow(destinationIso2: "RU"))).Events);
        Assert.Equal("R010", evt.RuleId);
        Assert.Equal("RU", evt.Country);
        Assert.Equal("8.8.8.8", evt.DestinationIp);
        Assert.Equal(SeverityLevel.High, evt.Severity);
    }

    [Fact]
    public async Task Whois_Registration_Country_Alone_Is_Not_Destination_Geolocation()
    {
        Assert.False((await See(Flow(whois: "RU"))).Matched);
        Assert.False((await See(Flow(whois: "CN"))).Matched);
    }

    [Fact]
    public async Task Source_Country_Alone_Does_Not_Make_A_Safe_Destination_Blocked()
    {
        Assert.False((await See(Flow(destinationIso2: "SE", sourceIso2: "RU"))).Matched);
    }

    [Fact]
    public async Task Contradictory_Whois_And_Destination_GeoIp_Do_Not_Override_Observed_Destination()
    {
        Assert.False((await See(Flow(destinationIso2: "SE", whois: "RU"))).Matched);
        var evt = Assert.Single((await See(Flow(source: "10.210.0.2",
            destinationIso2: "RU", whois: "SE"))).Events);
        Assert.Equal("RU", evt.Country);
    }

    [Fact]
    public async Task Private_Loopback_And_Documentation_Destinations_Are_Not_GeoIp_Egress()
    {
        foreach (var destination in new[] { "10.1.2.3", "127.0.0.1", "198.51.100.7", "192.0.2.5" })
            Assert.False((await See(Flow(destination: destination, destinationIso2: "RU"))).Matched);
    }

    [Fact]
    public async Task Malformed_Or_Missing_Iso2_Cannot_Trigger_A_Country_Match()
    {
        foreach (var iso in new string?[] { null, "", "RUS", "R1", "UNKNOWN", "DE" })
            Assert.False((await See(Flow(destinationIso2: iso))).Matched);
    }

    [Fact]
    public async Task Case_And_Whitespace_Normalization_Preserve_Exact_Country_Code()
    {
        var evt = Assert.Single((await See(Flow(destinationIso2: " ru "))).Events);
        Assert.Equal("RU", evt.Country);
    }

    [Fact]
    public async Task Cooldown_Is_Flow_Scoped_And_Different_Source_Remains_Visible()
    {
        Assert.True((await See(Flow(destinationIso2: "CN"))).Matched);
        var duplicate = await See(Flow(destinationIso2: "CN"), 1);
        Assert.True(duplicate.Suppressed);
        Assert.Empty(duplicate.Events);
        var independent = await See(Flow(source: "10.210.0.9", destinationIso2: "CN"), 1);
        Assert.Equal("10.210.0.9", Assert.Single(independent.Events).SourceIp);
    }

    [Fact]
    public async Task Missing_Source_Or_Destination_Does_Not_Fabricate_GeoIp_Finding()
    {
        var noSource = Flow(destinationIso2: "RU"); noSource.Source = null;
        Assert.False((await See(noSource)).Matched);
        Assert.False((await See(Flow(destination: null, destinationIso2: "RU"))).Matched);
    }
}
