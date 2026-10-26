// SPDX-License-Identifier: MIT
using System;
using System.IO;
using System.Linq;
using System.Threading.Tasks;
using Carthago.Services.Benchmarking;
using Xunit;

namespace Carthago.Tests;

/// <summary>
/// Independent candidate-vs-control replay to assess the new R102 evidence.
/// A high-confidence match must NOT bypass an unready baseline or turn into an
/// alert by silently weakening the precision policy.
/// </summary>
public sealed class R102PairedReplayQualityTests
{
    [Fact]
    public async Task Paired_Txt_Replays_Show_Stronger_Distinct_Burst_Evidence_Without_Alert_Promotion()
    {
        var replayDirectory = Path.Combine(
            AppContext.BaseDirectory, "..", "..", "..", "..", "Tests", "RuleReplaySamples");

        var report = await new TuningBenchmarkRunner().RunAsync(
            new TuningBenchmarkOptions { ReplayDirectory = replayDirectory });

        var burst = report.SampleResults.Single(sample =>
            sample.Name == "r102-distinct-txt-burst-candidate");
        var retry = report.SampleResults.Single(sample =>
            sample.Name == "r102-retried-txt-verification-control");

        Assert.Equal(ReplaySampleClassification.Malicious, burst.Classification);
        Assert.Equal(ReplaySampleClassification.Benign, retry.Classification);
        Assert.Contains("R102", burst.ActualMatches);
        Assert.Contains("R102", retry.ActualMatches);
        Assert.Empty(burst.Errors);
        Assert.Empty(retry.Errors);

        foreach (var profile in report.ProfileResults.Keys)
        {
            var burstDecision = Assert.Single(burst.Profiles[profile].RuleDecisions,
                decision => decision.RuleId == "R102");
            var retryDecision = Assert.Single(retry.Profiles[profile].RuleDecisions,
                decision => decision.RuleId == "R102");
            Assert.True(burstDecision.Confidence >= 0.90,
                $"{profile}: expected correlated candidate confidence >= 90%, got {burstDecision.Confidence:P0}");
            Assert.True(burstDecision.Confidence > retryDecision.Confidence,
                $"{profile}: distinct TXT burst must exceed identical-retry confidence.");
            Assert.DoesNotContain("R102", burst.Profiles[profile].AlertRuleIds);
            Assert.DoesNotContain("R102", retry.Profiles[profile].AlertRuleIds);
            Assert.Equal("Shadow", burstDecision.EffectiveMode);
        }

        Assert.All(report.Summary.SampleLevelQualityByProfile.Values,
            quality => Assert.Equal(0, quality.FalsePositives));
    }
}
