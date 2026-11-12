// SPDX-License-Identifier: MIT
using System;
using System.IO;
using System.Linq;
using System.Threading.Tasks;
using Carthago.Services.Benchmarking;
using Xunit;

namespace Carthago.Tests;

[Collection("Legacy rules R011-R015 isolated")]
public sealed class Ga06CanonicalReplayLabelTests
{
    [Fact]
    public async Task Legacy_Negative_Labels_Reference_Registered_Detectors()
    {
        var directory = Path.Combine(AppContext.BaseDirectory, "..", "..", "..", "..", "Tests", "RuleReplaySamples");
        var report = await new TuningBenchmarkRunner().RunAsync(new TuningBenchmarkOptions { ReplayDirectory = directory });
        var registered = report.RuleHardeningAudit.Select(item => item.RuleId).ToHashSet(StringComparer.OrdinalIgnoreCase);
        foreach (var sample in report.SampleResults)
        {
            foreach (var id in sample.ExpectedNonMatches)
                Assert.Contains(id, registered);
        }
        for (var number = 41; number <= 50; number++)
        {
            var id = $"R{number:000}";
            var sample = Assert.Single(report.SampleResults, item => item.Name.StartsWith($"r{number:000}-", StringComparison.Ordinal));
            Assert.Contains(id, sample.ExpectedNonMatches);
            Assert.DoesNotContain(id, sample.ActualMatches);
            Assert.Empty(sample.Errors);
            var coverage = Assert.Single(report.RuleEvidenceCoverage, item => item.RuleId == id);
            Assert.True(coverage.ExplicitNegativeCases > 0);
            Assert.Equal(coverage.ExplicitNegativeCases, coverage.ExplicitNegativePassed);
        }
        Assert.Equal(registered.Count, report.RuleEvidenceCoverage.Count);
        Assert.All(report.RuleEvidenceCoverage, item => Assert.Contains(item.RuleId, registered));
    }
}
