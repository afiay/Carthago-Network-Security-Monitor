using System;
using System.Collections.Generic;
using Carthago.Services.Benchmarking;
using Xunit;

namespace Carthago.Tests;

public sealed class DetectionQualityMetricsTests
{
    [Fact]
    public void SampleLevelScoresDistinguishTrueAndFalsePositivesAndNegatives()
    {
        var samples = new[]
        {
            Sample("threat-detected", ReplaySampleClassification.Malicious, true),
            Sample("threat-missed", ReplaySampleClassification.Malicious, false),
            Sample("ordinary-alerted", ReplaySampleClassification.Benign, true),
            Sample("ordinary-clean", ReplaySampleClassification.Benign, false)
        };

        var metrics = DetectionQualityMetrics.FromReplaySamples(samples, "SmallBusiness");

        Assert.Equal(1, metrics.TruePositives);
        Assert.Equal(1, metrics.FalsePositives);
        Assert.Equal(1, metrics.FalseNegatives);
        Assert.Equal(1, metrics.TrueNegatives);
        Assert.Equal(0.5, metrics.Precision);
        Assert.Equal(0.5, metrics.Recall);
        Assert.Equal(0.5, metrics.Specificity);
        Assert.Equal(0.5, metrics.F1Score);
    }

    [Fact]
    public void UndefinedDenominatorsAreNullRatherThanPretendingZeroPercent()
    {
        var metrics = DetectionQualityMetrics.FromReplaySamples(new[]
        {
            Sample("benign", ReplaySampleClassification.Benign, false)
        }, "SmallBusiness");

        Assert.Null(metrics.Precision);
        Assert.Null(metrics.Recall);
        Assert.Equal(1.0, metrics.Specificity);
        Assert.Null(metrics.F1Score);
    }

    [Fact]
    public void MissingProfileCannotSilentlyCountAsNoAlert()
    {
        var sample = new TuningBenchmarkSampleResult { Name = "unscored", Classification = ReplaySampleClassification.Malicious };
        Assert.Throws<InvalidOperationException>(() =>
            DetectionQualityMetrics.FromReplaySamples(new[] { sample }, "SmallBusiness"));
    }

    private static TuningBenchmarkSampleResult Sample(string name, ReplaySampleClassification classification, bool alert)
        => new()
        {
            Name = name,
            Classification = classification,
            Profiles = new Dictionary<string, TuningBenchmarkProfileSampleSummary>
            {
                ["SmallBusiness"] = new()
                {
                    ProfileName = "SmallBusiness",
                    AlertRuleIds = alert ? new List<string> { "R101" } : new List<string>()
                }
            }
        };
}
