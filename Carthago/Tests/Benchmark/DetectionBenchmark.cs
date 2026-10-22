// SPDX-License-Identifier: MIT
// File: Tests/Benchmark/DetectionBenchmark.cs
using System.Collections.Generic;

namespace Carthago.Tests.Benchmark
{
    public sealed class DetectionBenchmark
    {
        public string Name { get; set; } = "Carthago replay benchmark";
        public string ReplayDirectory { get; set; } = "Tests/RuleReplaySamples";
    }

    public sealed class DetectionBenchmarkResult
    {
        public bool Passed { get; set; }
        public List<string> Errors { get; set; } = new();
        public DetectionQualityScorecard Scorecard { get; set; } = new();
    }

    public sealed class DetectionQualityScorecard
    {
        public int ExpectedMatchesPassed { get; set; }
        public int ExpectedNonMatchesPassed { get; set; }
        public int FalsePositivesInBenignSamples { get; set; }
        public double AverageTruePositiveConfidence { get; set; }
        public bool JournalPersistenceSuccess { get; set; }
        public int ReplaySampleCount { get; set; }
        public List<string> RulesWithoutReplaySamples { get; set; } = new();
        public List<string> CoverageGaps { get; set; } = new();
    }
}
