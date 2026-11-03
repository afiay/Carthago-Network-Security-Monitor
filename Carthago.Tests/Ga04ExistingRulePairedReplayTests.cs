// SPDX-License-Identifier: MIT
using System;
using System.IO;
using System.Linq;
using System.Threading.Tasks;
using Carthago.Services.Benchmarking;
using Xunit;

namespace Carthago.Tests;

/// <summary>
/// GA-04 end-to-end paired replay controls for existing R014/R026/R027/R031.
/// Synthetic fixture classification is not proof of malicious intent or field accuracy.
/// </summary>
[Collection("Legacy rules R011-R015 isolated")]
public sealed class Ga04ExistingRulePairedReplayTests
{
    [Fact]
    public async Task Credential_External_Service_And_Dns_Spike_Rules_Have_Paired_Replay_Evidence()
    {
        var replayDirectory = Path.Combine(
            AppContext.BaseDirectory, "..", "..", "..", "..", "Tests", "RuleReplaySamples");
        var report = await new TuningBenchmarkRunner().RunAsync(
            new TuningBenchmarkOptions { ReplayDirectory = replayDirectory });

        var pairs = new[]
        {
            (Rule: "R014", Positive: "ga04-r014-cleartext-ftp-pass-observed",
                Negative: "ga04-r014-encrypted-pass-and-auth-negotiation"),
            (Rule: "R026", Positive: "ga04-r026-private-to-public-smb-syn",
                Negative: "ga04-r026-internal-smb-and-public-synack"),
            (Rule: "R027", Positive: "ga04-r027-private-to-public-rdp-syn",
                Negative: "ga04-r027-internal-ssh-and-mismatched-service"),
            (Rule: "R031", Positive: "ga04-r031-fifteen-valid-txt-queries",
                Negative: "ga04-r031-txt-responses-and-nontxt-queries")
        };

        foreach (var pair in pairs)
        {
            var positive = Assert.Single(report.SampleResults,
                sample => sample.Name == pair.Positive);
            var negative = Assert.Single(report.SampleResults,
                sample => sample.Name == pair.Negative);

            Assert.Equal(ReplaySampleClassification.Malicious, positive.Classification);
            Assert.Equal(ReplaySampleClassification.Benign, negative.Classification);
            Assert.Contains(pair.Rule, positive.ExpectedMatches);
            Assert.Contains(pair.Rule, positive.ActualMatches);
            Assert.Contains(pair.Rule, negative.ExpectedNonMatches);
            Assert.DoesNotContain(pair.Rule, negative.ActualMatches);
            Assert.Empty(positive.Errors);
            Assert.Empty(negative.Errors);

            var coverage = Assert.Single(report.RuleEvidenceCoverage,
                evidence => evidence.RuleId == pair.Rule);
            Assert.True(coverage.PositiveCases >= 1, pair.Rule + ": missing positive");
            Assert.True(coverage.ExplicitNegativeCases >= 1, pair.Rule + ": missing explicit negative");
            Assert.Equal(coverage.PositiveCases, coverage.PositiveRecognized);
            Assert.Equal(coverage.ExplicitNegativeCases, coverage.ExplicitNegativePassed);

            foreach (var profile in report.ProfileResults.Keys)
                Assert.DoesNotContain(pair.Rule, negative.Profiles[profile].AlertRuleIds);
        }

        // Fixture secrets are synthetic. Detection-event descriptions should not
        // retain raw credentials or turn a port observation into proven compromise.
        var exported = System.Text.Json.JsonSerializer.Serialize(
            report.SampleResults.Where(sample =>
                sample.Name.StartsWith("ga04-", StringComparison.Ordinal)).ToArray());
        Assert.DoesNotContain("synthetic-test-only-value", exported, StringComparison.Ordinal);
    }
}
