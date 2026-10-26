// SPDX-License-Identifier: MIT
using System;
using System.Collections.Generic;
using System.Linq;
using Carthago.Services.Benchmarking;
using Xunit;

namespace Carthago.Tests;

public sealed class TuningBenchmarkRuleEvidenceAnalyzerTests
{
    [Fact]
    public void Analyzer_Separates_Explicit_Positive_Negative_And_Unlabeled_Benign_Observations()
    {
        var report = new TuningBenchmarkReport
        {
            RuleCoverage = new List<TuningBenchmarkRuleCoverage>
            {
                new() { RuleId = "R102" },
                new() { RuleId = "R118" },
                new() { RuleId = "R163" },
                new() { RuleId = "R500" } // Catalog coverage without labeled controls.
            },
            SampleResults = new List<TuningBenchmarkSampleResult>
            {
                new()
                {
                    Name = "malicious",
                    Classification = ReplaySampleClassification.Malicious,
                    ExpectedMatches = new List<string> { "R102", "R118", "R102" },
                    ExpectedNonMatches = new List<string> { "R163" },
                    ActualMatches = new List<string> { "R102", "R102" }
                },
                new()
                {
                    Name = "benign-targeted",
                    Classification = ReplaySampleClassification.Benign,
                    ExpectedNonMatches = new List<string> { "R102", "R163" },
                    ActualMatches = new List<string> { "R102", "R118" }
                },
                new()
                {
                    Name = "benign-unlabeled",
                    Classification = ReplaySampleClassification.Benign,
                    ActualMatches = new List<string> { "R118" }
                }
            }
        };

        var coverage = TuningBenchmarkRuleEvidenceAnalyzer.Analyze(report);
        Assert.Equal(4, coverage.Count);
        var dns = Assert.Single(coverage, item => item.RuleId == "R102");
        Assert.Equal(1, dns.PositiveCases);
        Assert.Equal(1, dns.PositiveRecognized);
        Assert.Equal(0, dns.PositiveMissed);
        Assert.Equal(1, dns.ExplicitNegativeCases);
        Assert.Equal(0, dns.ExplicitNegativePassed);
        Assert.Equal(1, dns.ExplicitNegativeFailed);
        Assert.Equal(1, dns.BenignRawMatches);
        Assert.True(dns.HasPairedControls);
        Assert.Equal(1.0, dns.PositiveRecognitionRate);
        Assert.Equal(0.0, dns.ExplicitNegativePassRate);

        var iot = Assert.Single(coverage, item => item.RuleId == "R118");
        Assert.Equal(1, iot.PositiveCases);
        Assert.Equal(0, iot.PositiveRecognized);
        Assert.Equal(1, iot.PositiveMissed);
        Assert.Equal(2, iot.BenignRawMatches);
        Assert.Equal(0, iot.ExplicitNegativeCases);
        Assert.Null(iot.ExplicitNegativePassRate);
        Assert.False(iot.HasPairedControls);

        var ssrf = Assert.Single(coverage, item => item.RuleId == "R163");
        Assert.Equal(0, ssrf.PositiveCases);
        Assert.Equal(2, ssrf.ExplicitNegativeCases);
        Assert.Equal(2, ssrf.ExplicitNegativePassed);
        Assert.Null(ssrf.PositiveRecognitionRate);
        Assert.Equal(1.0, ssrf.ExplicitNegativePassRate);
        Assert.False(ssrf.HasPairedControls);

        var uncovered = Assert.Single(coverage, item => item.RuleId == "R500");
        Assert.Equal(0, uncovered.PositiveCases);
        Assert.Equal(0, uncovered.ExplicitNegativeCases);
        Assert.Null(uncovered.PositiveRecognitionRate);
        Assert.Null(uncovered.ExplicitNegativePassRate);
        Assert.Empty(report.RuleEvidenceCoverage); // Analysis does not mutate input.
    }

    [Fact]
    public void Analyzer_Does_Not_Assume_Every_Benign_Record_Is_An_Explicit_Negative()
    {
        var report = new TuningBenchmarkReport
        {
            SampleResults = new List<TuningBenchmarkSampleResult>
            {
                new()
                {
                    Classification = ReplaySampleClassification.Benign,
                    ActualMatches = new List<string> { "R135" },
                    ExpectedMatches = new List<string> { "R135" }
                }
            }
        };
        var item = Assert.Single(TuningBenchmarkRuleEvidenceAnalyzer.Analyze(report));
        Assert.Equal("R135", item.RuleId);
        Assert.Equal(1, item.BenignRawMatches);
        Assert.Equal(0, item.PositiveCases);
        Assert.Equal(0, item.ExplicitNegativeCases);
        Assert.False(item.HasPairedControls);
    }

    [Fact]
    public void Markdown_Displays_Evidence_Gaps_Without_Inventing_Specificity()
    {
        var report = new TuningBenchmarkReport
        {
            RuleEvidenceCoverage = new List<TuningBenchmarkRuleEvidenceCoverage>
            {
                new()
                {
                    RuleId = "R102", PositiveCases = 2, PositiveRecognized = 2,
                    ExplicitNegativeCases = 3, ExplicitNegativePassed = 2,
                    PositiveRecognitionRate = 1, ExplicitNegativePassRate = 2.0 / 3,
                    BenignRawMatches = 1
                },
                new() { RuleId = "R163" }
            }
        };
        var markdown = new TuningBenchmarkReportStore().ToMarkdown(report);
        Assert.Contains("## Explicit Rule Evidence Coverage", markdown);
        Assert.Contains("With paired controls: 1", markdown);
        Assert.Contains("2/2", markdown);
        Assert.Contains("2/3", markdown);
        Assert.Contains("N/A means no explicit positive or negative test", markdown);
        Assert.DoesNotContain("production specificity", markdown);
    }
}
