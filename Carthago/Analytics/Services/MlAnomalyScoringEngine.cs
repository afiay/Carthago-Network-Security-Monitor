// SPDX-License-Identifier: MIT
using System;
using System.Collections.Generic;
using System.Linq;
using Carthago.Analytics.Models;
using Microsoft.ML;
using Microsoft.ML.Data;
using Microsoft.ML.Transforms.TimeSeries;

namespace Carthago.Analytics.Services
{
    public sealed class MlAnomalyScoringEngine
    {
        private readonly MLContext _ml = new(seed: 1);
        private readonly int _minHistoryWindows;
        private readonly int _maxHistoryWindows;
        private readonly Dictionary<string, List<MlFeatureWindow>> _history = new(StringComparer.OrdinalIgnoreCase);

        private static readonly MetricDefinition[] MetricDefinitions =
        {
            new("OutboundBytes", window => window.OutboundBytes, "ML.NET detected an unusual spike in outbound bytes for this host."),
            new("UniqueDestinationCount", window => window.UniqueDestinationCount, "ML.NET detected unusual destination fan-out compared with recent host activity."),
            new("RuleHitCount", window => window.RuleHitCount, "ML.NET detected a rule-hit spike in the current host window."),
            new("SeverityWeightedRuleCount", window => window.SeverityWeightedRuleCount, "ML.NET detected an unusual increase in severity-weighted detections."),
            new("NewDestinationCount", window => window.NewDestinationCount, "ML.NET detected unusual destination novelty for this host."),
            new("ThreatIntelHitCount", window => window.ThreatIntelHitCount, "ML.NET detected an unusual concentration of threat-intelligence matches.")
        };

        public MlAnomalyScoringEngine(int minHistoryWindows = 6, int maxHistoryWindows = 72)
        {
            _minHistoryWindows = Math.Max(4, minHistoryWindows);
            _maxHistoryWindows = Math.Max(_minHistoryWindows + 1, maxHistoryWindows);
        }

        public MlAnomalyScore? Evaluate(MlFeatureWindow window)
        {
            if (window == null || string.IsNullOrWhiteSpace(window.SourceIp))
                return null;

            if (!_history.TryGetValue(window.SourceIp, out var hostHistory))
            {
                hostHistory = new List<MlFeatureWindow>();
                _history[window.SourceIp] = hostHistory;
            }

            try
            {
                if (hostHistory.Count < _minHistoryWindows)
                {
                    AppendWindow(hostHistory, window);
                    return null;
                }

                var contributions = new Dictionary<string, double>(StringComparer.OrdinalIgnoreCase);
                var reasons = new List<string>();

                foreach (var metric in MetricDefinitions)
                {
                    var signal = ScoreMetric(metric, hostHistory, window);
                    if (signal == null || !signal.IsAnomalous)
                        continue;

                    contributions[metric.Name] = signal.Score;
                    reasons.Add(signal.Reason);
                }

                AppendWindow(hostHistory, window);

                if (contributions.Count == 0)
                    return new MlAnomalyScore
                    {
                        SourceIp = window.SourceIp,
                        WindowStartUtc = window.WindowStartUtc,
                        WindowEndUtc = window.WindowEndUtc,
                        Score = 0,
                        Confidence = HistoryConfidence(hostHistory.Count),
                        IsAnomalous = false
                    };

                var topContributions = contributions
                    .OrderByDescending(kv => kv.Value)
                    .Take(3)
                    .ToArray();

                var combinedScore = Math.Clamp(topContributions.Average(kv => kv.Value), 0, 100);
                var confidence = Math.Clamp(HistoryConfidence(hostHistory.Count) + (topContributions.Max(kv => kv.Value) / 250.0), 0, 1);
                var isAnomalous = combinedScore >= 55 && confidence >= 0.45;

                var normalizedReasons = reasons
                    .Where(reason => !string.IsNullOrWhiteSpace(reason))
                    .Distinct(StringComparer.OrdinalIgnoreCase)
                    .Take(3)
                    .ToList();

                foreach (var contribution in topContributions)
                    normalizedReasons.Add($"Top ML feature: {ToReadableMetric(contribution.Key)} ({contribution.Value:0}/100)");

                return new MlAnomalyScore
                {
                    SourceIp = window.SourceIp,
                    WindowStartUtc = window.WindowStartUtc,
                    WindowEndUtc = window.WindowEndUtc,
                    Score = Math.Round(combinedScore, 1),
                    Confidence = Math.Round(confidence, 2),
                    IsAnomalous = isAnomalous,
                    Reasons = normalizedReasons
                        .Distinct(StringComparer.OrdinalIgnoreCase)
                        .Take(5)
                        .ToArray(),
                    FeatureContributions = contributions
                };
            }
            catch (Exception ex)
            {
                Console.Error.WriteLine($"[MlAnomalyScoringEngine] Failed to score window for {window.SourceIp}: {ex.Message}");
                AppendWindow(hostHistory, window);
                return null;
            }
        }

        private MetricSignal? ScoreMetric(MetricDefinition metric, List<MlFeatureWindow> history, MlFeatureWindow currentWindow)
        {
            var historyValues = history.Select(metric.Selector).Where(value => float.IsFinite(value)).ToArray();
            if (historyValues.Length < _minHistoryWindows)
                return null;

            var variance = historyValues.Max() - historyValues.Min();
            if (!float.IsFinite(variance) || variance <= 0)
                return null;

            var values = historyValues.Append(metric.Selector(currentWindow))
                .Select(value => new MetricPoint { Value = SanitizeFloat(value) })
                .ToArray();

            var dataView = _ml.Data.LoadFromEnumerable(values);
            var historyLength = Math.Clamp(historyValues.Length, 4, 32);
            var estimator = _ml.Transforms.DetectIidSpike(
                outputColumnName: nameof(MetricPrediction.Prediction),
                inputColumnName: nameof(MetricPoint.Value),
                confidence: 95d,
                pvalueHistoryLength: historyLength);
            var transformed = estimator.Fit(dataView).Transform(dataView);
            var last = _ml.Data.CreateEnumerable<MetricPrediction>(transformed, reuseRowObject: false).LastOrDefault();
            var prediction = last?.Prediction;
            if (prediction == null || prediction.Length < 3)
                return null;

            var alert = prediction[0] > 0;
            var rawScore = Math.Abs(prediction[1]);
            var pValue = double.IsFinite(prediction[2]) ? Math.Clamp(prediction[2], 0, 1) : 1;
            var mean = historyValues.Average(value => (double)value);
            var currentValue = metric.Selector(currentWindow);
            var ratio = mean > 0 ? currentValue / mean : currentValue > 0 ? 2 : 0;
            var deviationComponent = Math.Clamp((ratio - 1) * 18, 0, 40);
            var confidenceComponent = Math.Clamp((1 - pValue) * 60, 0, 60);
            var magnitudeComponent = Math.Clamp(Math.Log10(rawScore + 1) * 20, 0, 25);
            var normalizedScore = Math.Clamp(confidenceComponent + deviationComponent + magnitudeComponent, 0, 100);

            if (!double.IsFinite(normalizedScore))
                normalizedScore = 0;

            if (!alert && normalizedScore < 65)
                return null;

            return new MetricSignal(true, normalizedScore, metric.ReasonTemplate);
        }

        private void AppendWindow(List<MlFeatureWindow> history, MlFeatureWindow window)
        {
            history.Add(window);
            if (history.Count > _maxHistoryWindows)
                history.RemoveRange(0, history.Count - _maxHistoryWindows);
        }

        private static float SanitizeFloat(float value)
            => float.IsFinite(value) ? value : 0;

        private static double HistoryConfidence(int historyCount)
            => Math.Clamp(historyCount / 12.0, 0.25, 1.0);

        private static string ToReadableMetric(string metricName)
        {
            return metricName switch
            {
                "OutboundBytes" => "outbound bytes",
                "UniqueDestinationCount" => "destination fan-out",
                "RuleHitCount" => "rule-hit count",
                "SeverityWeightedRuleCount" => "severity-weighted detections",
                "NewDestinationCount" => "new destination count",
                "ThreatIntelHitCount" => "threat-intelligence hit count",
                _ => metricName
            };
        }

        private sealed class MetricPoint
        {
            public float Value { get; set; }
        }

        private sealed class MetricPrediction
        {
            [VectorType(3)]
            public double[] Prediction { get; set; } = Array.Empty<double>();
        }

        private sealed record MetricDefinition(string Name, Func<MlFeatureWindow, float> Selector, string ReasonTemplate);
        private sealed record MetricSignal(bool IsAnomalous, double Score, string Reason);
    }
}
