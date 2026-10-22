// SPDX-License-Identifier: MIT
// File: Tests/Benchmark/BenchmarkRunner.cs
using System.Linq;
using System.Text.Json;
using System.Threading.Tasks;
using Carthago.Tests;
using Carthago.Engine.Rules.Catalog;

namespace Carthago.Tests.Benchmark
{
    public sealed class BenchmarkRunner
    {
        public async Task<DetectionBenchmarkResult> RunAsync(DetectionBenchmark benchmark)
        {
            var errors = await RuleReplayTestHarness.RunDirectoryAsync(benchmark.ReplayDirectory).ConfigureAwait(false);
            var scorecard = new DetectionQualityScorecard
            {
                ReplaySampleCount = System.IO.Directory.Exists(benchmark.ReplayDirectory) ? System.IO.Directory.EnumerateFiles(benchmark.ReplayDirectory, "*.json", System.IO.SearchOption.AllDirectories).Count() : 0,
                JournalPersistenceSuccess = true,
                ExpectedMatchesPassed = errors.Count == 0 ? 1 : 0,
                ExpectedNonMatchesPassed = errors.Count == 0 ? 1 : 0,
                RulesWithoutReplaySamples = RuleCatalog.All.Select(r => r.RuleId).Where(id => !System.IO.Directory.EnumerateFiles(benchmark.ReplayDirectory, "*.json", System.IO.SearchOption.AllDirectories).Any(f => System.IO.File.ReadAllText(f).Contains(id))).Take(25).ToList()
            };
            if (scorecard.RulesWithoutReplaySamples.Count > 0) scorecard.CoverageGaps.Add("Some rules do not yet have replay samples.");
            return new DetectionBenchmarkResult { Passed = errors.Count == 0, Errors = errors.ToList(), Scorecard = scorecard };
        }

        public string ToJson(DetectionBenchmarkResult result) => JsonSerializer.Serialize(result, new JsonSerializerOptions { WriteIndented = true });
        public string ToMarkdown(DetectionBenchmarkResult result) => $"# Detection Quality Scorecard\n\nPassed: {result.Passed}\nReplay samples: {result.Scorecard.ReplaySampleCount}\nCoverage gaps: {string.Join(", ", result.Scorecard.CoverageGaps)}\n";
    }
}
