// SPDX-License-Identifier: MIT
using System;
using System.IO;
using System.Linq;
using System.Threading.Tasks;
using Carthago.Services.Benchmarking;
using Xunit;

namespace Carthago.Tests;

// Synthetic request-shape controls; not proof of enumeration intent.
[Collection("Legacy rules R011-R015 isolated")]
public sealed class Ga05JenkinsCrumbPairedReplayTests
{
    [Fact]
    public async Task Exact_Crumb_Request_And_Lookalike_Have_Paired_Replay_Controls()
    {
        var directory = Path.Combine(AppContext.BaseDirectory, "..", "..", "..", "..", "Tests", "RuleReplaySamples");
        var report = await new TuningBenchmarkRunner().RunAsync(new TuningBenchmarkOptions { ReplayDirectory = directory });
        var positive = Assert.Single(report.SampleResults, sample => sample.Name == "devops-jenkins-crumb");
        var negative = Assert.Single(report.SampleResults, sample => sample.Name == "ga05-r356-jenkins-crumb-lookalike");
        Assert.Equal(ReplaySampleClassification.Malicious, positive.Classification);
        Assert.Equal(ReplaySampleClassification.Benign, negative.Classification);
        Assert.Contains("R356", positive.ExpectedMatches);
        Assert.Contains("R356", positive.ActualMatches);
        Assert.Contains("R356", negative.ExpectedNonMatches);
        Assert.DoesNotContain("R356", negative.ActualMatches);
        Assert.Empty(positive.Errors);
        Assert.Empty(negative.Errors);
        var coverage = Assert.Single(report.RuleEvidenceCoverage, item => item.RuleId == "R356");
        Assert.True(coverage.PositiveCases >= 1);
        Assert.True(coverage.ExplicitNegativeCases >= 1);
        Assert.Equal(coverage.PositiveCases, coverage.PositiveRecognized);
        Assert.Equal(coverage.ExplicitNegativeCases, coverage.ExplicitNegativePassed);
        Assert.True(coverage.HasPairedControls);
        foreach (var profile in report.ProfileResults.Keys)
            Assert.DoesNotContain("R356", negative.Profiles[profile].AlertRuleIds);
    }
}
