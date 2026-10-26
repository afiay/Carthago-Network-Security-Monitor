// SPDX-License-Identifier: MIT
using System;
using System.Threading.Tasks;
using Carthago.Engine.Rules;
using Carthago.Engine.Rules.Existing;
using Carthago.Models;
using Carthago.Services;
using Xunit;

namespace Carthago.Tests;

[Collection("Legacy rules R001-R005 isolated")]
public sealed class R003Tests : IDisposable
{
    private static readonly DateTime T0 = new(2026, 10, 26, 12, 0, 0, DateTimeKind.Utc);
    private readonly R003_ThreatFeedHitRule _rule = new();
    // Synthetic indicator is never fetched from real threat intelligence.
    private readonly string _badHost = "holdout-" + Guid.NewGuid().ToString("N") + ".invalid";

    public R003Tests()
    {
        RuleEngine.ResetRuntimeStateForReplay();
        ThreatFeedService.MaliciousHosts.Add(_badHost);
    }

    public void Dispose()
    {
        ThreatFeedService.MaliciousHosts.Remove(_badHost);
        RuleEngine.ResetRuntimeStateForReplay();
    }

    private static TrafficRecord Flow(string source, string? destination)
        => new()
        {
            Source = source, Destination = destination, Protocol = "TCP",
            DestinationPort = null, // Do not mutate unrelated allowlist learning in tests.
            Length = 128
        };

    private async Task<RuleEvaluationResult> Evaluate(TrafficRecord record, int seconds = 0)
        => await _rule.EvaluateAsync(new RuleEvaluationContext(
            record, Sensitivity.Balanced, T0.AddSeconds(seconds)));

    [Fact]
    public async Task Exact_Known_Threat_Destination_Produces_Attributed_R003()
    {
        var result = await Evaluate(Flow("192.0.2.11", _badHost));
        Assert.True(result.Matched);
        var evt = Assert.Single(result.Events);
        Assert.Equal("R003", evt.RuleId);
        Assert.Equal(_badHost, evt.DestinationIp);
        Assert.Equal("192.0.2.11", evt.SourceIp);
        Assert.Equal(SeverityLevel.Critical, evt.Severity);
    }

    [Fact]
    public async Task Normalized_Uppercase_Indicator_Is_Matched_Without_Using_Description_Keywords()
    {
        var result = await Evaluate(Flow("192.0.2.12", _badHost.ToUpperInvariant()));
        Assert.True(result.Matched);
        Assert.Equal("R003", Assert.Single(result.Events).RuleId);
    }

    [Fact]
    public async Task Lookalike_Domain_And_Subdomain_Must_Not_Inherit_Exact_Feed_Identity()
    {
        Assert.False((await Evaluate(Flow("192.0.2.13", "prefix-" + _badHost))).Matched);
        Assert.False((await Evaluate(Flow("192.0.2.13", "sub." + _badHost), 5)).Matched);
        Assert.False((await Evaluate(Flow("192.0.2.13", _badHost + ".example"), 10)).Matched);
    }

    [Fact]
    public async Task Suspicious_Source_Alone_Is_Not_A_Malicious_Destination_Hit()
    {
        var safe = Flow(_badHost, "clean-destination.invalid");
        Assert.False((await Evaluate(safe)).Matched);
        Assert.False((await Evaluate(Flow("192.0.2.14", null), 1)).Matched);
    }

    [Fact]
    public async Task Repeated_Same_Source_Destination_Hit_Is_Debounced_Without_Dropping_Initial_Evidence()
    {
        Assert.True((await Evaluate(Flow("192.0.2.15", _badHost))).Matched);
        var repeated = await Evaluate(Flow("192.0.2.15", _badHost), 1);
        Assert.Empty(repeated.Events); // Returned as suppressed, not a duplicate alert event.
    }

    [Fact]
    public async Task Independent_Sources_To_Same_Threat_Indicator_Are_Attributed_Separately()
    {
        var first = await Evaluate(Flow("192.0.2.16", _badHost));
        var second = await Evaluate(Flow("192.0.2.17", _badHost), 1);
        Assert.True(first.Matched);
        Assert.True(second.Matched);
        Assert.Equal("192.0.2.16", Assert.Single(first.Events).SourceIp);
        Assert.Equal("192.0.2.17", Assert.Single(second.Events).SourceIp);
    }
}
