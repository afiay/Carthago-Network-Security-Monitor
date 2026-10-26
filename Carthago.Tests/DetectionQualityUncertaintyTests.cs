// SPDX-License-Identifier: MIT
using Carthago.Services.Benchmarking;
using Xunit;

namespace Carthago.Tests;

public sealed class DetectionQualityUncertaintyTests
{
    [Fact]
    public void Perfect_Observed_Precision_Is_Not_An_Unbounded_Certainty_Claim()
    {
        var quality = new DetectionQualityMetrics
        {
            TruePositives = 8, FalsePositives = 0,
            FalseNegatives = 29, TrueNegatives = 43
        };

        Assert.Equal(1.0, quality.Precision);
        Assert.Equal(0.0, quality.FalsePositiveRate);
        Assert.Equal((8.0 / 37.0 + 1.0) / 2, quality.BalancedAccuracy!.Value, 6);

        var precisionBounds = Assert.IsType<DetectionRatioInterval>(quality.Precision95);
        Assert.Equal(8, precisionBounds.Observations);
        Assert.InRange(precisionBounds.Lower, 0.67, 0.69);
        Assert.Equal(1.0, precisionBounds.Upper, 6);

        var falsePositiveBounds = Assert.IsType<DetectionRatioInterval>(quality.FalsePositiveRate95);
        Assert.Equal(43, falsePositiveBounds.Observations);
        Assert.Equal(0.0, falsePositiveBounds.Lower, 6);
        Assert.InRange(falsePositiveBounds.Upper, 0.08, 0.09);
        Assert.True(quality.MatthewsCorrelationCoefficient > 0);
    }

    [Fact]
    public void Unobserved_Classes_Do_Not_Produce_Fabricated_Performance()
    {
        var empty = new DetectionQualityMetrics();
        Assert.Null(empty.Precision);
        Assert.Null(empty.Recall);
        Assert.Null(empty.Specificity);
        Assert.Null(empty.BalancedAccuracy);
        Assert.Null(empty.MatthewsCorrelationCoefficient);
        Assert.Null(empty.Precision95);
        Assert.Null(empty.FalsePositiveRate95);
        Assert.Null(DetectionQualityMetrics.Wilson95(-1, 3));
        Assert.Null(DetectionQualityMetrics.Wilson95(4, 3));
        Assert.Null(DetectionQualityMetrics.Wilson95(0, 0));
    }

    [Fact]
    public void Both_Observed_Classes_Yield_Finite_Wilson_Intervals()
    {
        foreach (var (passed, total) in new[]
            { (0, 2), (1, 2), (2, 2), (5, 20), (20, 20), (43, 43) })
        {
            var interval = Assert.IsType<DetectionRatioInterval>(
                DetectionQualityMetrics.Wilson95(passed, total));
            Assert.InRange(interval.Lower, 0.0, 1.0);
            Assert.InRange(interval.Upper, 0.0, 1.0);
            Assert.True(interval.Lower <= interval.Upper);
            Assert.True(interval.Lower <= (double)passed / total + 1e-12);
            Assert.True(interval.Upper >= (double)passed / total - 1e-12);
        }
    }

    [Fact]
    public void Markdown_Displays_Uncertainty_Without_Promising_Production_Performance()
    {
        var report = new TuningBenchmarkReport();
        report.Summary.SampleLevelQuality = new DetectionQualityMetrics
        {
            TruePositives = 8, FalsePositives = 0,
            FalseNegatives = 29, TrueNegatives = 43
        };
        report.Summary.SampleLevelQualityByProfile["Research"] =
            report.Summary.SampleLevelQuality;

        var markdown = new TuningBenchmarkReportStore().ToMarkdown(report);
        Assert.Contains("Balanced accuracy:", markdown);
        Assert.Contains("Precision Wilson 95% interval:", markdown);
        Assert.Contains("Benign false-positive-rate Wilson 95% interval:", markdown);
        Assert.Contains("Profile Comparison", markdown);
        Assert.Contains("sampling uncertainty", markdown);
        Assert.Contains("not proof of 100% field precision", markdown);
    }
}
