// SPDX-License-Identifier: MIT
// File: Services/Benchmarking/TuningBenchmarkRuleEvidenceAnalyzer.cs
using System;
using System.Collections.Generic;
using System.Linq;

namespace Carthago.Services.Benchmarking
{
    /// <summary>
    /// Measures how well the replay suite explicitly exercises each detector.
    /// Only positive labels from malicious samples and explicit nonmatch labels
    /// form denominators. We do not infer negatives from benign traffic that
    /// was not labeled for a particular rule.
    /// </summary>
    public static class TuningBenchmarkRuleEvidenceAnalyzer
    {
        public static List<TuningBenchmarkRuleEvidenceCoverage> Analyze(TuningBenchmarkReport report)
        {
            if (report == null) throw new ArgumentNullException(nameof(report));

            var allRuleIds = report.RuleCoverage.Select(static item => item.RuleId)
                .Concat(report.SampleResults.SelectMany(static sample => sample.ExpectedMatches))
                .Concat(report.SampleResults.SelectMany(static sample => sample.ExpectedNonMatches))
                .Concat(report.SampleResults
                    .Where(static sample => sample.Classification == ReplaySampleClassification.Benign)
                    .SelectMany(static sample => sample.ActualMatches))
                .Where(static id => !string.IsNullOrWhiteSpace(id))
                .Distinct(StringComparer.OrdinalIgnoreCase)
                .OrderBy(static id => id, StringComparer.OrdinalIgnoreCase);

            var entries = allRuleIds.ToDictionary(
                static id => id,
                static id => new TuningBenchmarkRuleEvidenceCoverage { RuleId = id },
                StringComparer.OrdinalIgnoreCase);

            foreach (var sample in report.SampleResults)
            {
                var observed = new HashSet<string>(sample.ActualMatches, StringComparer.OrdinalIgnoreCase);

                if (sample.Classification == ReplaySampleClassification.Malicious)
                {
                    foreach (var ruleId in sample.ExpectedMatches
                        .Where(static id => !string.IsNullOrWhiteSpace(id))
                        .Distinct(StringComparer.OrdinalIgnoreCase))
                    {
                        var item = entries[ruleId];
                        item.PositiveCases++;
                        if (observed.Contains(ruleId))
                            item.PositiveRecognized++;
                        else
                            item.PositiveMissed++;
                    }
                }
                else
                {
                    // Raw benign matches may be purposeful Shadow findings and
                    // must not be relabeled as incorrect detector predictions.
                    foreach (var ruleId in observed)
                    {
                        if (entries.TryGetValue(ruleId, out var item))
                            item.BenignRawMatches++;
                    }
                }

                // Both benign and malicious samples can contain explicit
                // per-rule negative controls. Count only what was labeled.
                foreach (var ruleId in sample.ExpectedNonMatches
                    .Where(static id => !string.IsNullOrWhiteSpace(id))
                    .Distinct(StringComparer.OrdinalIgnoreCase))
                {
                    var item = entries[ruleId];
                    item.ExplicitNegativeCases++;
                    if (observed.Contains(ruleId))
                        item.ExplicitNegativeFailed++;
                    else
                        item.ExplicitNegativePassed++;
                }
            }

            foreach (var item in entries.Values)
            {
                item.PositiveRecognitionRate = item.PositiveCases == 0 ? null
                    : (double)item.PositiveRecognized / item.PositiveCases;
                item.ExplicitNegativePassRate = item.ExplicitNegativeCases == 0 ? null
                    : (double)item.ExplicitNegativePassed / item.ExplicitNegativeCases;
            }

            return entries.Values
                .OrderBy(static item => item.RuleId, StringComparer.OrdinalIgnoreCase)
                .ToList();
        }
    }
}
