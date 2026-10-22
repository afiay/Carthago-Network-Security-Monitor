// SPDX-License-Identifier: MIT
// File: Services/Benchmarking/RuleReplayCoverageService.cs
using System;
using System.Collections.Generic;
using System.Linq;
using Carthago.Engine.Rules;
using Carthago.Engine.Rules.Catalog;

namespace Carthago.Services.Benchmarking
{
    public enum RuleReplayCoverageStatus
    {
        NoCoverage,
        BenignOnly,
        MaliciousOnly,
        Covered,
        Failing
    }

    public sealed class RuleReplayCoverageSnapshot
    {
        public string RuleId { get; set; } = string.Empty;
        public RuleReplayCoverageStatus Status { get; set; }
        public int SampleCount { get; set; }
        public int BenignSampleCount { get; set; }
        public int MaliciousSampleCount { get; set; }
        public int ExpectedMatchCount { get; set; }
        public int ActualMatchCount { get; set; }
        public int EmittedCount { get; set; }
        public int MissingExpectedCount { get; set; }
        public int UnexpectedMatchCount { get; set; }
        public int FailedSampleCount { get; set; }
        public double AverageConfidence { get; set; }
        public double MaximumConfidence { get; set; }
        public List<string> SampleNames { get; set; } = new();
        public List<string> FailureMessages { get; set; } = new();

        public static RuleReplayCoverageSnapshot Empty(string ruleId) => new()
        {
            RuleId = ruleId,
            Status = RuleReplayCoverageStatus.NoCoverage
        };
    }

    public sealed class RuleReplayCoverageService
    {
        public IReadOnlyDictionary<string, RuleReplayCoverageSnapshot> Build(
            RuleReplayDirectoryResult? replayResult,
            IEnumerable<RuleDescriptor>? descriptors = null)
        {
            var ruleIds = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
            foreach (var descriptor in descriptors ?? RuleCatalog.All)
            {
                if (!string.IsNullOrWhiteSpace(descriptor.RuleId))
                    ruleIds.Add(descriptor.RuleId);
            }

            if (replayResult?.Samples != null)
            {
                foreach (var sample in replayResult.Samples)
                {
                    foreach (var ruleId in sample.MatchedRuleIds.Concat(sample.EmittedRuleIds).Concat(sample.ExpectedMatchRuleIds).Concat(sample.ExpectedNonMatchRuleIds).Concat(sample.MissingExpectedRuleIds).Concat(sample.UnexpectedRuleIds))
                    {
                        if (!string.IsNullOrWhiteSpace(ruleId))
                            ruleIds.Add(ruleId);
                    }
                }
            }

            var builders = ruleIds.ToDictionary(static id => id, static id => new CoverageBuilder(id), StringComparer.OrdinalIgnoreCase);
            if (replayResult?.Samples != null)
            {
                foreach (var sample in replayResult.Samples)
                {
                    var relevantRuleIds = sample.MatchedRuleIds
                        .Concat(sample.EmittedRuleIds)
                        .Concat(sample.ExpectedMatchRuleIds)
                        .Concat(sample.ExpectedNonMatchRuleIds)
                        .Concat(sample.MissingExpectedRuleIds)
                        .Concat(sample.UnexpectedRuleIds)
                        .Concat(sample.RuleObservations.Select(static observation => observation.RuleId))
                        .Where(static id => !string.IsNullOrWhiteSpace(id))
                        .Distinct(StringComparer.OrdinalIgnoreCase)
                        .ToArray();

                    foreach (var ruleId in relevantRuleIds)
                    {
                        if (!builders.TryGetValue(ruleId, out var builder))
                        {
                            builder = new CoverageBuilder(ruleId);
                            builders[ruleId] = builder;
                        }

                        builder.Observe(sample);
                    }
                }
            }

            return builders.ToDictionary(static pair => pair.Key, static pair => pair.Value.ToSnapshot(), StringComparer.OrdinalIgnoreCase);
        }

        public RuleReplayCoverageSnapshot GetCoverage(
            string ruleId,
            RuleReplayDirectoryResult? replayResult,
            IEnumerable<RuleDescriptor>? descriptors = null)
        {
            if (string.IsNullOrWhiteSpace(ruleId))
                return RuleReplayCoverageSnapshot.Empty(string.Empty);

            var coverage = Build(replayResult, descriptors);
            return coverage.TryGetValue(ruleId, out var snapshot) ? snapshot : RuleReplayCoverageSnapshot.Empty(ruleId);
        }

        private sealed class CoverageBuilder
        {
            private readonly HashSet<string> _samples = new(StringComparer.OrdinalIgnoreCase);
            private readonly HashSet<string> _failures = new(StringComparer.OrdinalIgnoreCase);
            private double _confidenceSum;
            private int _confidenceCount;

            public CoverageBuilder(string ruleId) => RuleId = ruleId;
            public string RuleId { get; }
            public int BenignSampleCount { get; private set; }
            public int MaliciousSampleCount { get; private set; }
            public int ExpectedMatchCount { get; private set; }
            public int ActualMatchCount { get; private set; }
            public int EmittedCount { get; private set; }
            public int MissingExpectedCount { get; private set; }
            public int UnexpectedMatchCount { get; private set; }
            public int FailedSampleCount { get; private set; }
            public double MaximumConfidence { get; private set; }

            public void Observe(RuleReplaySampleResult sample)
            {
                if (sample == null)
                    return;

                _samples.Add(sample.Name);
                if (sample.Classification == ReplaySampleClassification.Benign)
                    BenignSampleCount++;
                else
                    MaliciousSampleCount++;

                if (sample.MissingExpectedRuleIds.Contains(RuleId, StringComparer.OrdinalIgnoreCase))
                    MissingExpectedCount++;
                if (sample.UnexpectedRuleIds.Contains(RuleId, StringComparer.OrdinalIgnoreCase))
                    UnexpectedMatchCount++;
                if (!sample.Passed && (sample.MissingExpectedRuleIds.Contains(RuleId, StringComparer.OrdinalIgnoreCase) || sample.UnexpectedRuleIds.Contains(RuleId, StringComparer.OrdinalIgnoreCase)))
                {
                    FailedSampleCount++;
                    foreach (var error in sample.Errors.Where(error => error.Contains(RuleId, StringComparison.OrdinalIgnoreCase)))
                        _failures.Add(error);
                }

                var observation = sample.RuleObservations.FirstOrDefault(o => string.Equals(o.RuleId, RuleId, StringComparison.OrdinalIgnoreCase));
                if (observation != null)
                {
                    ActualMatchCount += observation.MatchedCount;
                    EmittedCount += observation.EmittedCount;
                    if (observation.MaximumConfidence > 0)
                    {
                        MaximumConfidence = Math.Max(MaximumConfidence, observation.MaximumConfidence);
                        _confidenceSum += observation.AverageConfidence > 0 ? observation.AverageConfidence : observation.MaximumConfidence;
                        _confidenceCount++;
                    }
                }

                if (sample.ExpectedMatchRuleIds.Contains(RuleId, StringComparer.OrdinalIgnoreCase))
                    ExpectedMatchCount++;
            }

            public RuleReplayCoverageSnapshot ToSnapshot()
            {
                var status = RuleReplayCoverageStatus.NoCoverage;
                if (FailedSampleCount > 0 || MissingExpectedCount > 0 || UnexpectedMatchCount > 0)
                    status = RuleReplayCoverageStatus.Failing;
                else if (BenignSampleCount > 0 && MaliciousSampleCount > 0)
                    status = RuleReplayCoverageStatus.Covered;
                else if (BenignSampleCount > 0)
                    status = RuleReplayCoverageStatus.BenignOnly;
                else if (MaliciousSampleCount > 0)
                    status = RuleReplayCoverageStatus.MaliciousOnly;

                return new RuleReplayCoverageSnapshot
                {
                    RuleId = RuleId,
                    Status = status,
                    SampleCount = _samples.Count,
                    BenignSampleCount = BenignSampleCount,
                    MaliciousSampleCount = MaliciousSampleCount,
                    ExpectedMatchCount = ExpectedMatchCount,
                    ActualMatchCount = ActualMatchCount,
                    EmittedCount = EmittedCount,
                    MissingExpectedCount = MissingExpectedCount,
                    UnexpectedMatchCount = UnexpectedMatchCount,
                    FailedSampleCount = FailedSampleCount,
                    AverageConfidence = _confidenceCount <= 0 ? 0.0 : _confidenceSum / _confidenceCount,
                    MaximumConfidence = MaximumConfidence,
                    SampleNames = _samples.OrderBy(static name => name, StringComparer.OrdinalIgnoreCase).ToList(),
                    FailureMessages = _failures.OrderBy(static item => item, StringComparer.OrdinalIgnoreCase).ToList()
                };
            }
        }
    }
}
