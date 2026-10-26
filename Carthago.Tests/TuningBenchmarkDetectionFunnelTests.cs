// SPDX-License-Identifier: MIT
using System;
using System.Collections.Generic;
using System.Globalization;
using System.Linq;
using Carthago.Services.Benchmarking;
using Xunit;

namespace Carthago.Tests;

public sealed class TuningBenchmarkDetectionFunnelTests
{
    [Fact]
    public void Analyzer_Separates_Recognition_Shadow_Disabled_And_Eligible_Emission()
    {
        var report = new TuningBenchmarkReport
        {
            SampleResults = new List<TuningBenchmarkSampleResult>
            {
                new()
                {
                    Name = "malicious-case",
                    Classification = ReplaySampleClassification.Malicious,
                    ExpectedMatches = new List<string>
                    { "R118", "R163", "R102", "R200", "R300", "R400" },
                    ActualMatches = new List<string>
                    { "R118", "R163", "R102", "R200", "R300" },
                    Profiles = new Dictionary<string, TuningBenchmarkProfileSampleSummary>
                    {
                        ["Research"] = new()
                        {
                            AlertRuleIds = new List<string> { "R200" },
                            ShadowRuleIds = new List<string> { "R118", "R102" },
                            SuppressedRuleIds = new List<string> { "R163" },
                            RuleDecisions = new List<TuningBenchmarkRuleDecision>
                            {
                                new() { RuleId = "R118", EffectiveMode = "Shadow" },
                                new() { RuleId = "R163", EffectiveMode = "Disabled" },
                                new() { RuleId = "R102", EffectiveMode = "Alert" },
                                new() { RuleId = "R200", EffectiveMode = "Alert" }
                                // R300 deliberately has no policy trace.
                            }
                        }
                    }
                },
                new()
                {
                    Name = "benign-control",
                    Classification = ReplaySampleClassification.Benign,
                    ExpectedMatches = new List<string> { "R135" },
                    ActualMatches = new List<string> { "R135" },
                    Profiles = new Dictionary<string, TuningBenchmarkProfileSampleSummary>
                    {
                        ["Research"] = new() { ShadowRuleIds = new List<string> { "R135" } }
                    }
                }
            }
        };

        var funnel = TuningBenchmarkDetectionFunnelAnalyzer.Analyze(report)["Research"];

        Assert.Equal(6, funnel.ExpectedMaliciousRules);
        Assert.Equal(5, funnel.RecognizedByDetector);
        Assert.Equal(1, funnel.DetectorMisses);
        Assert.Equal(1, funnel.SimulatedAlerted);
        Assert.Equal(1, funnel.PolicyShadowed);
        Assert.Equal(1, funnel.PolicyDisabled);
        Assert.Equal(1, funnel.MissingPolicyDecisions);
        Assert.Equal(2, funnel.PolicyEligibleRules);
        Assert.Equal(1, funnel.EligibleButNotAlerted);
        Assert.Equal(0, funnel.AlertDecisionMismatches);
        Assert.Equal(1, funnel.BenignRawRuleMatches);
        Assert.Equal(0, funnel.BenignSimulatedAlerts);
        Assert.Equal(5.0 / 6, funnel.DetectorRecognitionRate);
        Assert.Equal(1.0 / 6, funnel.AlertLevelRecall);
        Assert.Equal(0.5, funnel.EligibleAlertEmissionRate);

        // One and only one outcome for each recognized expected rule.
        Assert.Equal(funnel.RecognizedByDetector, funnel.SimulatedAlerted
            + funnel.PolicyShadowed + funnel.PolicyDisabled
            + funnel.MissingPolicyDecisions + funnel.EligibleButNotAlerted);
    }

    [Fact]
    public void Analyzer_Reports_NA_And_Never_Calls_Policy_Shadow_An_Alert()
    {
        var report = new TuningBenchmarkReport
        {
            SampleResults = new List<TuningBenchmarkSampleResult>
            {
                new()
                {
                    Name = "shadowed-malicious",
                    Classification = ReplaySampleClassification.Malicious,
                    ExpectedMatches = new List<string> { "R118" },
                    ActualMatches = new List<string> { "R118" },
                    Profiles = new Dictionary<string, TuningBenchmarkProfileSampleSummary>
                    {
                        ["Enterprise"] = new()
                        {
                            ShadowRuleIds = new List<string> { "R118" },
                            RuleDecisions = new List<TuningBenchmarkRuleDecision>
                            {
                                new() { RuleId = "R118", EffectiveMode = "Shadow" }
                            }
                        }
                    }
                }
            }
        };

        var result = TuningBenchmarkDetectionFunnelAnalyzer.Analyze(report)["Enterprise"];
        Assert.Equal(1.0, result.DetectorRecognitionRate);
        Assert.Equal(0.0, result.AlertLevelRecall);
        Assert.Equal(0, result.PolicyEligibleRules);
        Assert.Equal(1, result.PolicyShadowed);
        Assert.Null(result.EligibleAlertEmissionRate);
        Assert.Empty(report.DetectionFunnelByProfile); // Pure analysis, no mutation.
    }

    [Fact]
    public void Analyzer_Flags_Policy_And_Alert_Contradictions()
    {
        var report = new TuningBenchmarkReport
        {
            SampleResults = new List<TuningBenchmarkSampleResult>
            {
                new()
                {
                    Name = "inconsistent",
                    Classification = ReplaySampleClassification.Malicious,
                    ExpectedMatches = new List<string> { "R102", "R163" },
                    ActualMatches = new List<string> { "R102" },
                    Profiles = new Dictionary<string, TuningBenchmarkProfileSampleSummary>
                    {
                        ["Research"] = new()
                        {
                            AlertRuleIds = new List<string> { "R102", "R163" },
                            RuleDecisions = new List<TuningBenchmarkRuleDecision>
                            {
                                new() { RuleId = "R102", EffectiveMode = "Shadow" }
                            }
                        }
                    }
                }
            }
        };

        var funnel = TuningBenchmarkDetectionFunnelAnalyzer.Analyze(report)["Research"];
        Assert.Equal(2, funnel.AlertDecisionMismatches);
        Assert.Equal(1, funnel.RecognizedByDetector);
        Assert.Equal(1, funnel.DetectorMisses);
        Assert.Equal(1, funnel.SimulatedAlerted);
        Assert.Equal(0, funnel.PolicyEligibleRules);
        Assert.Null(funnel.EligibleAlertEmissionRate);
    }

    [Theory]
    [InlineData("sv-SE")]
    [InlineData("fr-FR")]
    [InlineData("en-US")]
    public void Markdown_Explains_Separate_Denominators_And_NA(string cultureName)
    {
        var report = new TuningBenchmarkReport
        {
            DetectionFunnelByProfile = new Dictionary<string, TuningBenchmarkDetectionFunnel>
            {
                ["Research"] = new()
                {
                    ProfileName = "Research",
                    ExpectedMaliciousRules = 1,
                    RecognizedByDetector = 1,
                    SimulatedAlerted = 0,
                    PolicyShadowed = 1,
                    DetectorRecognitionRate = 1,
                    AlertLevelRecall = 0,
                    EligibleAlertEmissionRate = null
                }
            }
        };

        var previousCulture = CultureInfo.CurrentCulture;
        try
        {
            CultureInfo.CurrentCulture = CultureInfo.GetCultureInfo(cultureName);
            var markdown = new TuningBenchmarkReportStore().ToMarkdown(report);
            Assert.Contains("## Detection, Policy, and Alert Funnel", markdown);
            Assert.Contains("100.0%", markdown);
            Assert.Contains("0.0%", markdown);
            Assert.Contains("N/A", markdown);
            Assert.Contains("not live notification delivery", markdown);
            Assert.DoesNotContain("100,0", markdown);
        }
        finally
        {
            CultureInfo.CurrentCulture = previousCulture;
        }
    }
}
