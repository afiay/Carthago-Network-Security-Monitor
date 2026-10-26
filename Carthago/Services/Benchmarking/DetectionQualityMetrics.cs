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
    public sealed record DetectionRatioInterval(double Lower, double Upper, int Observations);

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
        public double? Accuracy => Ratio(TruePositives + TrueNegatives,
            TruePositives + FalsePositives + FalseNegatives + TrueNegatives);
        public double? FalsePositiveRate => Ratio(FalsePositives, FalsePositives + TrueNegatives);
        // Balanced accuracy prevents a large benign class from hiding missed
        // malicious samples. Undefined when either class has no observations.
        public double? BalancedAccuracy =>
            Recall is { } recall && Specificity is { } specificity
                ? (recall + specificity) / 2.0 : null;

        public double? MatthewsCorrelationCoefficient
        {
            get
            {
                var tp = (double)TruePositives;
                var fp = (double)FalsePositives;
                var fn = (double)FalseNegatives;
                var tn = (double)TrueNegatives;
                var divisor = Math.Sqrt((tp + fp) * (tp + fn) * (tn + fp) * (tn + fn));
                return divisor > 0 ? (tp * tn - fp * fn) / divisor : null;
            }
        }

        // Wilson 95% score intervals on curated fixture proportions.
        // Their uncertainty still assumes independent Bernoulli samples,
        // which may not hold for related synthetic replay variants.
        public DetectionRatioInterval? Precision95 => Wilson95(TruePositives, TruePositives + FalsePositives);
        public DetectionRatioInterval? Recall95 => Wilson95(TruePositives, TruePositives + FalseNegatives);
        public DetectionRatioInterval? Specificity95 => Wilson95(TrueNegatives, TrueNegatives + FalsePositives);
        public DetectionRatioInterval? FalsePositiveRate95 => Wilson95(FalsePositives, FalsePositives + TrueNegatives);

        public static DetectionRatioInterval? Wilson95(int successes, int observations)
        {
            if (observations <= 0 || successes < 0 || successes > observations)
                return null;

            const double z = 1.959963984540054;
            var n = (double)observations;
            var p = successes / n;
            var z2 = z * z;
            var denominator = 1.0 + z2 / n;
            var centre = (p + z2 / (2.0 * n)) / denominator;
            var radius = z * Math.Sqrt(p * (1.0 - p) / n + z2 / (4.0 * n * n))
                / denominator;
            return new DetectionRatioInterval(
                Math.Clamp(centre - radius, 0.0, 1.0),
                Math.Clamp(centre + radius, 0.0, 1.0),
                observations);
        }

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
