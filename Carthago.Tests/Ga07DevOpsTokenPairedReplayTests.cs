// SPDX-License-Identifier: MIT
using System;
using System.IO;
using System.Linq;
using System.Text.Json;
using System.Threading.Tasks;
using Carthago.Services.Benchmarking;
using Xunit;

namespace Carthago.Tests;

[Collection("Legacy rules R011-R015 isolated")]
public sealed class Ga07DevOpsTokenPairedReplayTests
{
    [Fact]
    public async Task Parser_Derived_Token_Shapes_Pair_With_Existing_Negatives()
    {
        var directory = Path.Combine(AppContext.BaseDirectory, "..", "..", "..", "..", "Tests", "RuleReplaySamples");
        var report = await new TuningBenchmarkRunner().RunAsync(new TuningBenchmarkOptions { ReplayDirectory = directory });
        var cases = new[]
        {
            (Id: "R353", Name: "ga07-r353-github-token-shaped-cleartext-request", Secret: "ghp_AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"),
            (Id: "R354", Name: "ga07-r354-gitlab-token-shaped-cleartext-request", Secret: "glpat-BBBBBBBBBBBBBBBBBBBBBBBB"),
            (Id: "R359", Name: "ga07-r359-azure-pat-shaped-cleartext-query", Secret: "CCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCC")
        };
        foreach (var item in cases)
        {
            var sample = Assert.Single(report.SampleResults, entry => entry.Name == item.Name);
            Assert.Equal(ReplaySampleClassification.Malicious, sample.Classification);
            Assert.Contains(item.Id, sample.ExpectedMatches);
            Assert.Contains(item.Id, sample.ActualMatches);
            Assert.Empty(sample.Errors);
            Assert.DoesNotContain(item.Secret, JsonSerializer.Serialize(sample), StringComparison.Ordinal);
            var coverage = Assert.Single(report.RuleEvidenceCoverage, entry => entry.RuleId == item.Id);
            Assert.True(coverage.HasPairedControls);
            Assert.Equal(coverage.PositiveCases, coverage.PositiveRecognized);
            Assert.Equal(coverage.ExplicitNegativeCases, coverage.ExplicitNegativePassed);
        }
    }
}
