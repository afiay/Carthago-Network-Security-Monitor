// SPDX-License-Identifier: MIT
using System;
using System.Collections.Generic;
using System.Linq;
using Carthago.Services.Benchmarking;
using Xunit;

namespace Carthago.Tests;

public sealed class TuningBenchmarkRecallGapTests
{
    [Fact]
    public void Analyzer_Distinguishes_Raw_Matches_From_Alert_Eligibility()
    {
        var sample = new TuningBenchmarkSampleResult
        {
            Name = "labeled-malicious",
            Classification = ReplaySampleClassification.Malicious,
            ExpectedMatches = new List<string> { "R118", "R163", "R102", "R200", "R240" },
            ActualMatches = new List<string> { "R118", "R102", "R200", "R240" },
            ExpectedRuleDiagnostics = new List<TuningBenchmarkExpectedRuleDiagnostic>
            {
                new() { RuleId = "R118", Outcome = "Matched" },
                new() { RuleId = "R163", Outcome = "MissingTelemetry",
                    MissingRequiredTelemetry = new List<string> { "precision.Http" } },
                new() { RuleId = "R102", Outcome = "Matched" },
                new() { RuleId = "R200", Outcome = "Matched" },
                new() { RuleId = "R240", Outcome = "Matched" }
            },
            Profiles = new Dictionary<string, TuningBenchmarkProfileSampleSummary>
            {
                ["Enterprise"] = new()
                {
                    AlertRuleIds = new List<string> { "R240" },
                    RuleDecisions = new List<TuningBenchmarkRuleDecision>
                    {
                        new() { RuleId = "R118", DefaultMode = "Shadow",
                            PrecisionMode = "Shadow", EffectiveMode = "Shadow",
                            Confidence = 0.70 },
                        new() { RuleId = "R102", DefaultMode = "Alert",
                            PrecisionMode = "Shadow", EffectiveMode = "Shadow",
                            Confidence = 0.80, RuntimePrecisionReasons = new List<string>
                            { "Baseline not ready" } },
                        new() { RuleId = "R200", DefaultMode = "Alert",
                            PrecisionMode = "Alert", EffectiveMode = "Shadow",
                            Confidence = 0.60, ConfidenceFloor = 0.85,
                            Reasons = new List<string> { "ConfidenceFloorApplied" } },
                        new() { RuleId = "R240", DefaultMode = "Alert",
                            PrecisionMode = "Alert", EffectiveMode = "Alert", Confidence = 0.99 }
                    }
                }
            }
        };
        var report = new TuningBenchmarkReport { SampleResults = new List<TuningBenchmarkSampleResult> { sample } };

        var gaps = TuningBenchmarkRecallGapAnalyzer.Analyze(report);

        Assert.Equal(4, gaps.Count);
        Assert.Contains(gaps, gap => gap.RuleId == "R118" && gap.Cause == "ProfileShadow"
            && gap.DetectionOutcome == "Matched");
        Assert.Contains(gaps, gap => gap.RuleId == "R163" && gap.Cause == "MissingTelemetry"
            && gap.Evidence.Contains("Missing telemetry: precision.Http"));
        Assert.Contains(gaps, gap => gap.RuleId == "R102" && gap.Cause == "BaselineNotReady"
            && gap.BlockingFactors.Contains("PrecisionShadow"));
        Assert.Contains(gaps, gap => gap.RuleId == "R200" && gap.Cause == "ConfidenceFloor"
            && gap.ConfidenceFloor == 0.85);
        Assert.DoesNotContain(gaps, gap => gap.RuleId == "R240");
        Assert.All(gaps, gap => Assert.Equal("Enterprise", gap.ProfileName));
    }

    [Fact]
    public void Analyzer_Reports_Every_Independent_Precision_And_Environment_Gate()
    {
        var sample = new TuningBenchmarkSampleResult
        {
            Name = "policy-gated-malicious",
            Classification = ReplaySampleClassification.Malicious,
            ExpectedMatches = new List<string> { "R118", "R163", "R102", "R356" },
            ActualMatches = new List<string> { "R118", "R163", "R102", "R356" },
            Profiles = new Dictionary<string, TuningBenchmarkProfileSampleSummary>
            {
                ["Research"] = new()
                {
                    RuleDecisions = new List<TuningBenchmarkRuleDecision>
                    {
                        new() { RuleId = "R118", DefaultMode = "Alert", PrecisionMode = "Alert",
                            EffectiveMode = "Shadow", Confidence = 0.76,
                            RuntimePrecisionReasons = new List<string>
                            { "confidence 76% below precision floor 86%" } },
                        new() { RuleId = "R163", DefaultMode = "Alert", PrecisionMode = "Alert",
                            EffectiveMode = "Shadow", Confidence = 0.62, ConfidenceFloor = 0.75,
                            Reasons = new List<string> { "ConfidenceFloorApplied" },
                            RuntimePrecisionReasons = new List<string>
                            { "confidence 62% below precision floor 84%" } },
                        new() { RuleId = "R102", DefaultMode = "Alert", PrecisionMode = "Alert",
                            EffectiveMode = "Shadow", Confidence = 0.78,
                            RuntimePrecisionReasons = new List<string>
                            { "confidence 78% below precision floor 80%" } },
                        new() { RuleId = "R356", DefaultMode = "Alert", PrecisionMode = "Alert",
                            EffectiveMode = "Shadow", Confidence = 0.91,
                            RuntimePrecisionReasons = new List<string>
                            { "environment-scoped rule lacks approved asset/segment/controller evidence; non-paging until configured" } }
                    }
                },
                ["Enterprise"] = new()
                {
                    RuleDecisions = new List<TuningBenchmarkRuleDecision>
                    {
                        new() { RuleId = "R118", DefaultMode = "Shadow", PrecisionMode = "Alert",
                            EffectiveMode = "Shadow", Confidence = 0.76,
                            Reasons = new List<string> { "MissingEnvironmentConfiguration" },
                            RuntimePrecisionReasons = new List<string>
                            { "confidence 76% below precision floor 86%" } },
                        new() { RuleId = "R163", DefaultMode = "Alert", PrecisionMode = "Alert",
                            EffectiveMode = "Shadow", Confidence = 0.62, ConfidenceFloor = 0.75,
                            Reasons = new List<string> { "ConfidenceFloorApplied" },
                            RuntimePrecisionReasons = new List<string>
                            { "confidence 62% below precision floor 84%" } },
                        new() { RuleId = "R102", DefaultMode = "Shadow", PrecisionMode = "Alert",
                            EffectiveMode = "Shadow", Confidence = 0.78,
                            RuntimePrecisionReasons = new List<string>
                            { "confidence 78% below precision floor 80%" } },
                        new() { RuleId = "R356", DefaultMode = "Shadow", PrecisionMode = "Alert",
                            EffectiveMode = "Shadow", Confidence = 0.91,
                            RuntimePrecisionReasons = new List<string>
                            { "environment-scoped rule lacks approved asset/segment/controller evidence; non-paging until configured" } }
                    }
                }
            }
        };
        var report = new TuningBenchmarkReport
        {
            SampleResults = new List<TuningBenchmarkSampleResult> { sample }
        };

        var gaps = TuningBenchmarkRecallGapAnalyzer.Analyze(report);

        Assert.Equal(8, gaps.Count);
        Assert.Contains(gaps, gap => gap.ProfileName == "Research" && gap.RuleId == "R118"
            && gap.Cause == "PrecisionConfidenceFloor"
            && gap.BlockingFactors.Count == 1);
        Assert.Contains(gaps, gap => gap.ProfileName == "Research" && gap.RuleId == "R163"
            && gap.Cause == "ConfidenceFloor"
            && gap.BlockingFactors.Contains("PrecisionConfidenceFloor"));
        Assert.Contains(gaps, gap => gap.ProfileName == "Research" && gap.RuleId == "R102"
            && gap.Cause == "PrecisionConfidenceFloor");
        Assert.Contains(gaps, gap => gap.ProfileName == "Research" && gap.RuleId == "R356"
            && gap.Cause == "EnvironmentApprovalRequired");
        Assert.Contains(gaps, gap => gap.ProfileName == "Enterprise" && gap.RuleId == "R118"
            && gap.Cause == "PrecisionConfidenceFloor"
            && gap.BlockingFactors.Contains("EnvironmentConfigurationRequired")
            && gap.BlockingFactors.Contains("ProfileShadow"));
        Assert.Contains(gaps, gap => gap.ProfileName == "Enterprise" && gap.RuleId == "R356"
            && gap.BlockingFactors.Contains("ProfileShadow"));
        Assert.All(gaps, gap => Assert.Equal("Matched", gap.DetectionOutcome));
    }

    [Fact]
    public void Analyzer_Identifies_Unready_Baseline_Even_When_Detector_Confidence_Is_High()
    {
        var sample = new TuningBenchmarkSampleResult
        {
            Name = "corroborated-dns-txt-burst",
            Classification = ReplaySampleClassification.Malicious,
            ExpectedMatches = new List<string> { "R102" },
            ActualMatches = new List<string> { "R102" },
            Profiles = new Dictionary<string, TuningBenchmarkProfileSampleSummary>
            {
                ["Research"] = new()
                {
                    RuleDecisions = new List<TuningBenchmarkRuleDecision>
                    {
                        new()
                        {
                            RuleId = "R102",
                            DefaultMode = "Alert",
                            PrecisionMode = "Alert",
                            EffectiveMode = "Shadow",
                            Confidence = 0.98,
                            ConfidenceFloor = 0.80,
                            Reasons = new List<string> { "BaselineLearningMode" },
                            ReasonDetails = new List<string> {
                                "Baseline readiness is not established, so this baseline-dependent rule remains in Shadow."
                            }
                        }
                    }
                }
            }
        };

        var gap = Assert.Single(TuningBenchmarkRecallGapAnalyzer.Analyze(new TuningBenchmarkReport
        {
            SampleResults = new List<TuningBenchmarkSampleResult> { sample }
        }));
        Assert.Equal("BaselineNotReady", gap.Cause);
        Assert.Equal("Matched", gap.DetectionOutcome);
        Assert.Equal("Shadow", gap.EffectiveMode);
        Assert.Equal(0.98, gap.Confidence);
        Assert.Contains("BaselineNotReady", gap.BlockingFactors);
    }

    [Fact]
    public void Analyzer_Ignores_Benign_Matches_And_Leaves_Report_Unmodified()
    {
        var report = new TuningBenchmarkReport
        {
            SampleResults = new List<TuningBenchmarkSampleResult>
            {
                new() { Name = "safe", Classification = ReplaySampleClassification.Benign,
                    ExpectedMatches = new List<string> { "R163" },
                    ActualMatches = new List<string> { "R163" },
                    Profiles = new Dictionary<string, TuningBenchmarkProfileSampleSummary>
                    { ["Research"] = new() } }
            }
        };

        Assert.Empty(TuningBenchmarkRecallGapAnalyzer.Analyze(report));
        Assert.Empty(report.RecallGaps);
    }

    [Fact]
    public void Markdown_Report_Explains_Gaps_Without_Claiming_Shadow_Is_An_Alert()
    {
        var report = new TuningBenchmarkReport();
        report.RecallGaps.Add(new TuningBenchmarkRecallGap
        {
            ProfileName = "Research", SampleName = "proof|sample",
            RuleId = "R163", Cause = "ProfileShadow",
            BlockingFactors = new List<string> { "ProfileShadow", "PrecisionConfidenceFloor" },
            DetectionOutcome = "Matched", EffectiveMode = "Shadow",
            Confidence = 0.77, ConfidenceFloor = 0.84,
            Evidence = new List<string> { "Shadow|no promotion" }
        });

        var markdown = new TuningBenchmarkReportStore().ToMarkdown(report);

        Assert.Contains("## Alert-Level Recall Gaps", markdown);
        Assert.Contains("Research | ProfileShadow | 1", markdown);
        Assert.Contains("Additional blocking factors", markdown);
        Assert.Contains("PrecisionConfidenceFloor", markdown);
        Assert.Contains("proof\\|sample", markdown);
        Assert.Contains("Shadow\\|no promotion", markdown);
        Assert.Contains("raw detector match in Shadow mode", markdown);
    }
}
