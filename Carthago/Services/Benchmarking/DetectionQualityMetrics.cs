// SPDX-License-Identifier: MIT
using System;
using System.Collections.Generic;
using System.Linq;

namespace Carthago.Services.Benchmarking
{
    /// <summary>
    /// Sample-level confusion matrix for a specified alerting profile.
    /// This evaluates labeled offline replay samples, not real-world prevalence.
    /// Undefined ratios stay null instead of being misrepresented as zero.
    /// </summary>
    public sealed record DetectionQualityMetrics
    {
        public int TruePositives { get; init; }
        public int FalsePositives { get; init; }
        public int FalseNegatives { get; init; }
        public int TrueNegatives { get; init; }

        public double? Precision => Ratio(TruePositives, TruePositives + FalsePositives);
        public double? Recall => Ratio(TruePositives, TruePositives + FalseNegatives);
        public double? Specificity => Ratio(TrueNegatives, TrueNegatives + FalsePositives);
        public double? F1Score => Ratio(2 * TruePositives, 2 * TruePositives + FalsePositives + FalseNegatives);

        public static DetectionQualityMetrics FromReplaySamples(
            IEnumerable<TuningBenchmarkSampleResult> samples, string profileName)
        {
            ArgumentNullException.ThrowIfNull(samples);
            if (string.IsNullOrWhiteSpace(profileName)) throw new ArgumentException("A profile is required.", nameof(profileName));

            var tp = 0;
            var fp = 0;
            var fn = 0;
            var tn = 0;

            foreach (var sample in samples)
            {
                if (sample == null) throw new ArgumentException("Replay samples cannot contain null entries.", nameof(samples));

                var profile = sample.Profiles.FirstOrDefault(pair =>
                    string.Equals(pair.Key, profileName, StringComparison.OrdinalIgnoreCase)).Value;
                if (profile == null)
                    throw new InvalidOperationException($"Replay sample '{sample.Name}' has no '{profileName}' alert profile.");

                var alerted = profile.AlertRuleIds.Count > 0;
                if (sample.Classification == ReplaySampleClassification.Malicious)
                {
                    if (alerted) tp++;
                    else fn++;
                }
                else if (sample.Classification == ReplaySampleClassification.Benign)
                {
                    if (alerted) fp++;
                    else tn++;
                }
                else
                    throw new ArgumentOutOfRangeException(nameof(samples), "Unexpected replay classification.");
            }

            return new DetectionQualityMetrics
            {
                TruePositives = tp,
                FalsePositives = fp,
                FalseNegatives = fn,
                TrueNegatives = tn
            };
        }

        private static double? Ratio(int numerator, int denominator)
            => denominator == 0 ? null : (double)numerator / denominator;
    }
}
