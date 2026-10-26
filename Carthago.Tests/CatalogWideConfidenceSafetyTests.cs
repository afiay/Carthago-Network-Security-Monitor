// SPDX-License-Identifier: MIT
using System;
using System.Globalization;
using Carthago.Engine.Rules;
using Carthago.Engine.Rules.Catalog;
using Carthago.Engine.Rules.Tuning;
using Carthago.Models;
using Carthago.Services.EnvironmentTuning;
using Xunit;

namespace Carthago.Tests;

/// <summary>
/// Contract tests run against the actual default rule catalog: numeric
/// corruption never authorizes an alert, and confidence is compared against
/// the precise floor rather than a rounded display percentage.
/// </summary>
public sealed class CatalogWideConfidenceSafetyTests
{
    [Fact]
    public void Every_Registered_Rule_Fails_Closed_On_Invalid_Confidence()
    {
        var registry = new ApprovedAssetRegistry(new EnvironmentTuningOptions());
        var record = new TrafficRecord
        {
            Source = "10.220.0.10",
            Destination = "198.51.100.20",
            Protocol = "TCP",
            DestinationPort = 443
        };

        Assert.Equal(544, RuleCatalog.All.Count);
        foreach (var descriptor in RuleCatalog.All)
        {
            var profile = RulePrecisionCatalog.GetProfile(descriptor);
            Assert.InRange(profile.MinimumConfidence, 1, 100);

            foreach (var corruptScore in new[]
                { double.NaN, double.PositiveInfinity, double.NegativeInfinity })
            {
                var evt = Event(descriptor, corruptScore);
                var precision = RulePrecisionRuntimeEvaluator.Evaluate(
                    descriptor, evt, record, RuleMode.Alert, "Research", registry);

                Assert.False(precision.ConfidenceSatisfied,
                    $"{descriptor.RuleId} accepted non-finite confidence {corruptScore}");
                Assert.False(precision.AllowsAlert,
                    $"{descriptor.RuleId} emitted with non-finite confidence {corruptScore}");
                Assert.Equal(0, precision.ConfidencePercent);
            }
        }
    }

    [Theory]
    [InlineData("R102")]
    [InlineData("R118")]
    [InlineData("R163")]
    [InlineData("R485")]
    public void Rounded_Percent_Does_Not_Bypass_Exact_Floor(string ruleId)
    {
        var descriptor = RuleCatalog.Find(ruleId)!;
        var profile = RulePrecisionCatalog.GetProfile(descriptor);
        var record = new TrafficRecord
        {
            Source = "10.220.0.10",
            Destination = "198.51.100.20",
            DestinationPort = 443,
            Protocol = "HTTP",
            HttpMethod = "POST",
            HttpUri = "/api/test",
            HttpHost = "security.example"
        };
        var registry = new ApprovedAssetRegistry(new EnvironmentTuningOptions());
        var justBelow = (profile.MinimumConfidence - 0.4) / 100.0;
        var result = RulePrecisionRuntimeEvaluator.Evaluate(
            descriptor, Event(descriptor, justBelow), record,
            RuleMode.Alert, "Research", registry);

        Assert.Equal(profile.MinimumConfidence, result.ConfidencePercent);
        Assert.False(result.ConfidenceSatisfied);
        Assert.False(result.AllowsAlert);
        Assert.Contains(result.Reasons, reason =>
            reason.Contains("below precision floor", StringComparison.OrdinalIgnoreCase));
    }

    [Theory]
    [InlineData(double.NaN)]
    [InlineData(double.PositiveInfinity)]
    [InlineData(double.NegativeInfinity)]
    public void Rule_Tuning_Does_Not_Promote_R163_With_Invalid_Confidence(double score)
    {
        var descriptor = RuleCatalog.Find("R163")!;
        var registry = new ApprovedAssetRegistry(new EnvironmentTuningOptions());
        var record = new TrafficRecord
        {
            Source = "10.220.0.10", Destination = "169.254.169.254",
            DestinationPort = 80, Protocol = "HTTP",
            HttpMethod = "GET", HttpHost = "169.254.169.254",
            HttpUri = "/latest/meta-data/iam/security-credentials/test"
        };
        var decision = RuleTuningCatalog.Resolve("Research",
            descriptor, Event(descriptor, score), record, registry,
            effectiveConfidenceScore: score, baselineReady: true);
        Assert.NotEqual(RuleMode.Alert, decision.EffectiveMode);
    }

    [Theory]
    [InlineData("R102", "Research")]
    [InlineData("R102", "Enterprise")]
    [InlineData("R163", "Research")]
    [InlineData("R118", "Research")]
    public void Tuning_Rejects_NonFinite_Confidence_Without_Baseline_Or_Profile_Bypass(
        string ruleId, string profileName)
    {
        var descriptor = RuleCatalog.Find(ruleId)!;
        var registry = new ApprovedAssetRegistry(new EnvironmentTuningOptions());
        var record = new TrafficRecord
        {
            Source = "10.220.0.10", Destination = "198.51.100.20",
            DestinationPort = 443, Protocol = "HTTP",
            HttpMethod = "POST", HttpHost = "security.example",
            HttpUri = "/api/test"
        };

        foreach (var score in new[] { double.NaN, double.PositiveInfinity, double.NegativeInfinity })
        {
            var decision = RuleTuningCatalog.Resolve(
                profileName, descriptor, Event(descriptor, score), record,
                registry, effectiveConfidenceScore: score, baselineReady: true);
            Assert.NotEqual(RuleMode.Alert, decision.EffectiveMode);
            Assert.Contains(decision.ReasonDetails, reason =>
                reason.Contains("Invalid or non-finite confidence",
                    StringComparison.OrdinalIgnoreCase));
        }
    }

    [Fact]
    public void Confidence_Builder_Never_Serializes_Invalid_Numeric_Values()
    {
        var evt = Event(RuleCatalog.Find("R118")!, 0.0);
        new ConfidenceBuilder()
            .AddEvidence(double.NaN, "invalid")
            .AddBaseline(double.PositiveInfinity, "invalid")
            .AddCorrelation(double.NegativeInfinity, "invalid")
            .ApplyTo(evt);

        Assert.True(double.IsFinite(evt.ConfidenceScore));
        Assert.Equal(0, evt.ConfidenceScore);
        Assert.Equal(DetectionConfidenceLabel.Unknown, evt.ConfidenceLabel);
    }

    [Fact]
    public void Confidence_Summary_Uses_Invariant_Decimals()
    {
        var previous = CultureInfo.CurrentCulture;
        try
        {
            CultureInfo.CurrentCulture = CultureInfo.GetCultureInfo("sv-SE");
            var evt = Event(RuleCatalog.Find("R118")!, 0.0);
            new ConfidenceBuilder().AddEvidence(0.5, "real-evidence").ApplyTo(evt);

            Assert.Contains("confidence=0.50",
                evt.StructuredEvidence!.Items[0].Value);
        }
        finally
        {
            CultureInfo.CurrentCulture = previous;
        }
    }

    private static DetectionEvent Event(RuleDescriptor descriptor, double confidence)
        => new()
        {
            RuleId = descriptor.RuleId,
            RuleName = descriptor.Name,
            ConfidenceScore = confidence,
            Severity = descriptor.DefaultSeverity,
            SourceIp = "10.220.0.10",
            DestinationIp = "198.51.100.20",
            Protocol = "TCP",
            Description = "Synthetic invalid-confidence regression control"
        };
}
