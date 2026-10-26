// SPDX-License-Identifier: MIT
using System;
using System.Threading.Tasks;
using Carthago.Engine.Rules;
using Carthago.Engine.Rules.Existing;
using Carthago.Models;
using Carthago.Services;
using Xunit;

namespace Carthago.Tests;

/// <summary>R003 batch gate: five exact feed identity and suppression tests.</summary>
[Collection("Legacy rules R001-R005 isolated")]
public sealed class R003AdvancedAccuracyBatchTests : IDisposable
{
    private readonly R003_ThreatFeedHitRule _rule = new();
    private readonly string _indicator = "risk-" + Guid.NewGuid().ToString("N") + ".invalid";
    private static readonly DateTime Origin = new(2026, 10, 26, 12, 0, 0, DateTimeKind.Utc);

    public R003AdvancedAccuracyBatchTests()
    {
        RuleEngine.ResetRuntimeStateForReplay();
        ThreatFeedService.MaliciousHosts.Add(_indicator);
    }
    public void Dispose()
    {
        ThreatFeedService.MaliciousHosts.Remove(_indicator);
        RuleEngine.ResetRuntimeStateForReplay();
    }

    private static TrafficRecord Flow(string source, string? destination)
        => new() { Source = source, Destination = destination,
            Protocol = "TCP", Length = 160, DestinationPort = null };

    private async Task<RuleEvaluationResult> See(TrafficRecord record, int second = 0)
        => await _rule.EvaluateAsync(new RuleEvaluationContext(
            record, Sensitivity.Balanced, Origin.AddSeconds(second)));

    [Fact]
    public async Task Exact_Domain_With_Absolute_Dns_Root_Dot_Remains_A_Feed_Hit()
    {
        var hit = await See(Flow("192.0.2.101", _indicator + "."));
        Assert.True(hit.Matched);
        Assert.Equal("R003", Assert.Single(hit.Events).RuleId);
        Assert.Equal(SeverityLevel.Critical, hit.Events[0].Severity);
    }

    [Fact]
    public async Task Case_And_Whitespace_Normalization_Still_Require_Exact_Indicator()
    {
        var hit = await See(Flow("192.0.2.102", "  " + _indicator.ToUpperInvariant() + ".  "));
        Assert.True(hit.Matched);
        Assert.False((await See(Flow("192.0.2.103", "sub." + _indicator), 1)).Matched);
    }

    [Fact]
    public async Task Reputation_Boolean_And_Scary_Text_Cannot_Invent_A_Feed_Match()
    {
        var record = Flow("192.0.2.104", "clean-reputation.invalid");
        record.ReputationIsMalicious = true;
        record.ReputationScore = 100;
        record.ReputationReports = 100;
        record.Info = "Threat feed HIT: " + _indicator;
        Assert.False((await See(record)).Matched);
    }

    [Fact]
    public async Task Lookalike_Indicators_Cannot_Inherit_The_Original_Threat_Identity()
    {
        foreach (var candidate in new[]
        {
            "prefix-" + _indicator,
            _indicator + ".clean.invalid",
            "sub." + _indicator,
            _indicator.Replace(".invalid", ".example", StringComparison.Ordinal)
        })
            Assert.False((await See(Flow("192.0.2.105", candidate))).Matched);
    }

    [Fact]
    public async Task Duplicate_Feed_Observations_Are_Suppressed_But_Different_Clients_Stay_Visible()
    {
        var first = await See(Flow("192.0.2.106", _indicator));
        Assert.True(first.Matched);
        var duplicate = await See(Flow("192.0.2.106", _indicator), 1);
        Assert.Empty(duplicate.Events);
        var independent = await See(Flow("192.0.2.107", _indicator), 2);
        Assert.True(independent.Matched);
        Assert.Equal("192.0.2.107", Assert.Single(independent.Events).SourceIp);
    }
}
