// SPDX-License-Identifier: MIT
using System;
using System.IO;
using System.Linq;
using System.Threading.Tasks;
using Carthago.Services.Benchmarking;
using Xunit;

namespace Carthago.Tests;

/// <summary>
/// GA-03 development replay controls for existing stateful network/identity rules.
/// Synthetic labels are explicit and are not field precision or live alert proof.
/// </summary>
[Collection("Legacy rules R001-R005 isolated")]
public sealed class Ga03ExistingRulePairedReplayTests
{
    [Fact]
    public async Task Existing_Stateful_Rules_Have_Recognized_Positive_And_Explicit_Negative_Replays()
    {
        var replayDirectory = Path.Combine(
            AppContext.BaseDirectory, "..", "..", "..", "..", "Tests", "RuleReplaySamples");
        var report = await new TuningBenchmarkRunner().RunAsync(
            new TuningBenchmarkOptions { ReplayDirectory = replayDirectory });

        var pairs = new[]
        {
            (RuleId: "R001",
                Positive: "ga03-r001-eight-distinct-tcp-syn-ports",
                Negative: "ga03-r001-retransmissions-and-synack"),
            (RuleId: "R004",
                Positive: "ga03-r004-twelve-attributed-ssh-failures",
                Negative: "ga03-r004-successful-ssh-and-banners"),
            (RuleId: "R017",
                Positive: "ga03-r017-ten-private-host-syn-sweep",
                Negative: "ga03-r017-retransmissions-and-ack-only"),
            (RuleId: "R030",
                Positive: "ga03-r030-eight-private-admin-syn-targets",
                Negative: "r030-synack-not-lateral-sweep")
        };

        foreach (var pair in pairs)
        {
            var positive = Assert.Single(report.SampleResults,
                sample => sample.Name == pair.Positive);
            var negative = Assert.Single(report.SampleResults,
                sample => sample.Name == pair.Negative);
            Assert.Equal(ReplaySampleClassification.Malicious, positive.Classification);
            Assert.Equal(ReplaySampleClassification.Benign, negative.Classification);

            Assert.Contains(pair.RuleId, positive.ExpectedMatches);
            Assert.Contains(pair.RuleId, positive.ActualMatches);
            Assert.Contains(pair.RuleId, negative.ExpectedNonMatches);
            Assert.DoesNotContain(pair.RuleId, negative.ActualMatches);
            Assert.Empty(positive.Errors);
            Assert.Empty(negative.Errors);

            var coverage = Assert.Single(report.RuleEvidenceCoverage,
                evidence => evidence.RuleId == pair.RuleId);
            Assert.True(coverage.PositiveCases > 0, pair.RuleId + ": missing positive replay");
            Assert.True(coverage.ExplicitNegativeCases > 0,
                pair.RuleId + ": missing explicit negative replay");
            Assert.Equal(coverage.PositiveCases, coverage.PositiveRecognized);
            Assert.Equal(coverage.ExplicitNegativeCases, coverage.ExplicitNegativePassed);

            foreach (var profile in report.ProfileResults.Keys)
                Assert.DoesNotContain(pair.RuleId, negative.Profiles[profile].AlertRuleIds);
        }
    }
}
