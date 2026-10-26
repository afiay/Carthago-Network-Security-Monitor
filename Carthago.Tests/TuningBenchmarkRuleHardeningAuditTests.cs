// SPDX-License-Identifier: MIT
using System;
using System.Collections.Generic;
using System.Linq;
using Carthago.Engine.Rules.Catalog;
using Carthago.Services.Benchmarking;
using Xunit;

namespace Carthago.Tests;

/// <summary>
/// Verifies complete default-catalog enumeration and preserves the distinction
/// between a declared rule contract and observed, labeled replay evidence.
/// </summary>
public sealed class TuningBenchmarkRuleHardeningAuditTests
{
    [Fact]
    public void Audit_Covers_All_544_Registered_Rules_Without_Inventing_Test_Cases()
    {
        var report = new TuningBenchmarkReport
        {
            RuleEvidenceCoverage = new List<TuningBenchmarkRuleEvidenceCoverage>
            {
                new()
                {
                    RuleId = "R102", PositiveCases = 2, PositiveRecognized = 2,
                    ExplicitNegativeCases = 2, ExplicitNegativePassed = 2
                },
                new()
                {
                    RuleId = "R118", PositiveCases = 8, PositiveRecognized = 8
                }
            }
        };
        var audit = TuningBenchmarkRuleHardeningAudit.Analyze(report);

        Assert.Equal(544, RuleCatalog.All.Count);
        Assert.Equal(RuleCatalog.All.Count, audit.Count);
        Assert.Equal(audit.Count, audit.Select(item => item.RuleId)
            .Distinct(StringComparer.OrdinalIgnoreCase).Count());
        Assert.All(audit, entry =>
        {
            Assert.False(string.IsNullOrWhiteSpace(entry.RuleId));
            Assert.False(string.IsNullOrWhiteSpace(entry.Category));
            Assert.InRange(entry.MinimumConfidence, 1, 100);
            Assert.True(entry.RequiredTelemetryKinds > 0);
            Assert.True(entry.RequiredFields > 0);
            Assert.True(entry.EvidenceFields > 0);
            Assert.Empty(entry.ContractIssues);
        });

        var r102 = Assert.Single(audit, item => item.RuleId == "R102");
        Assert.Equal("PairedSyntheticControls", r102.EvidenceStatus);
        Assert.True(r102.PairedSyntheticControls);
        Assert.Equal(2, r102.PositiveCases);
        Assert.Equal(2, r102.ExplicitNegativeCases);

        var r118 = Assert.Single(audit, item => item.RuleId == "R118");
        Assert.Equal("PositiveOnly", r118.EvidenceStatus);
        Assert.False(r118.PairedSyntheticControls);

        var untested = Assert.Single(audit, item => item.RuleId == "R544");
        Assert.Equal("NoExplicitReplayControls", untested.EvidenceStatus);
        Assert.Equal(0, untested.PositiveCases);
        Assert.Equal(0, untested.ExplicitNegativeCases);
    }

    [Fact]
    public void Markdown_Lists_All_Rules_And_Prioritizes_Explicit_Gaps()
    {
        var report = new TuningBenchmarkReport
        {
            RuleHardeningAudit = TuningBenchmarkRuleHardeningAudit.Analyze(new TuningBenchmarkReport())
        };
        var content = new TuningBenchmarkReportStore().ToHardeningAuditMarkdown(report);

        Assert.Contains("Registered rules reviewed: 544", content);
        Assert.Contains("No explicit controls: 544", content);
        Assert.Contains("| R001 |", content);
        Assert.Contains("| R544 |", content);
        Assert.Contains("not production certification", content);
        Assert.Contains("## Coverage by detection family", content);
    }
}
