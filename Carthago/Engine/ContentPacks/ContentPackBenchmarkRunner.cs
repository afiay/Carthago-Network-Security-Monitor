// SPDX-License-Identifier: MIT
// File: Engine/ContentPacks/ContentPackBenchmarkRunner.cs
using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Text;
using System.Text.Json;
using System.Text.Json.Serialization;
using Carthago.Engine.Rules;
using Carthago.Models;
using Carthago.Services.Benchmarking;

namespace Carthago.Engine.ContentPacks
{
    public sealed class ContentPackBenchmarkRunner
    {
        private static readonly JsonSerializerOptions JsonOptions = new()
        {
            WriteIndented = true,
            Converters = { new JsonStringEnumConverter() }
        };

        private readonly ContentPackRegistry _registry;

        public ContentPackBenchmarkRunner(ContentPackRegistry? registry = null)
            => _registry = registry ?? new ContentPackRegistry();

        public ContentPackBenchmarkResultSummary Run(string packId, string outputDirectory = "build-verify")
        {
            var manifest = _registry.LoadInstalledManifest(packId) ?? _registry.GetAvailablePacks().First(item => string.Equals(item.PackId, packId, StringComparison.OrdinalIgnoreCase));
            var rules = _registry.GetAllAvailableRuleRegistrations()
                .Where(registration => string.Equals(registration.PackId, packId, StringComparison.OrdinalIgnoreCase))
                .Select(static registration => registration.CompiledRule)
                .Where(static rule => rule != null)
                .Cast<IContentPackRule>()
                .ToArray();
            var rulesById = rules.ToDictionary(static rule => rule.Descriptor.RuleId, StringComparer.OrdinalIgnoreCase);

            var covered = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
            var telemetryGaps = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
            var recommendedProfileChanges = new List<string>();
            var positivePasses = 0;
            var positiveCount = 0;
            var benignFalsePositives = 0;
            var criticalFalsePositives = 0;
            var confidenceSamples = new List<double>();

            foreach (var replay in manifest.ReplaySamples)
            {
                var sample = LoadReplaySample(replay.RelativePath);
                var actualMatches = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
                var actualEvents = new List<DetectionEvent>();

                foreach (var record in sample.Records)
                {
                    foreach (var rule in rules)
                    {
                        var telemetry = RuleTelemetryValidator.Validate(rule, record);
                        if (!telemetry.CanRunSafely)
                        {
                            telemetryGaps.Add(rule.Descriptor.RuleId);
                            continue;
                        }

                        var result = rule.EvaluateAsync(new RuleEvaluationContext(record, Sensitivity.Balanced, DateTime.UtcNow)).AsTask().GetAwaiter().GetResult();
                        foreach (var evt in result.Events)
                        {
                            actualMatches.Add(evt.RuleId);
                            actualEvents.Add(evt);
                            confidenceSamples.Add(evt.ConfidenceScore);
                        }
                    }
                }

                foreach (var expected in replay.ExpectedRuleIds)
                    covered.Add(expected);

                if (replay.Classification == ReplaySampleClassification.Malicious)
                {
                    positiveCount++;
                    if (replay.ExpectedRuleIds.All(expected => actualMatches.Contains(expected)))
                        positivePasses++;
                }
                else
                {
                    benignFalsePositives += actualEvents.Count;
                    criticalFalsePositives += actualEvents.Count(evt => evt.Severity == SeverityLevel.Critical);
                }
            }

            var defaultMode = criticalFalsePositives > 0
                ? RuleMode.Shadow
                : positiveCount > 0 && (double)positivePasses / positiveCount >= 0.8
                    ? RuleMode.Alert
                    : RuleMode.Shadow;
            if (criticalFalsePositives > 0)
                recommendedProfileChanges.Add("Keep default production mode at Shadow until critical benign false positives are reduced.");
            if (telemetryGaps.Count > 0)
                recommendedProfileChanges.Add("Fill missing telemetry before promoting more pack rules to Alert.");

            var summary = new ContentPackBenchmarkResultSummary
            {
                PackId = manifest.PackId,
                Version = manifest.Version,
                EnabledProfiles = manifest.Profiles.Select(static profile => profile.ProfileName).ToList(),
                RulesCovered = covered.Count,
                RulesWithoutSamples = rulesById.Keys.Except(covered, StringComparer.OrdinalIgnoreCase).OrderBy(static id => id, StringComparer.OrdinalIgnoreCase).ToList(),
                PositivePassRate = positiveCount == 0 ? 0.0 : (double)positivePasses / positiveCount,
                BenignFalsePositiveCount = benignFalsePositives,
                CriticalFalsePositiveCount = criticalFalsePositives,
                AverageConfidence = confidenceSamples.Count == 0 ? 0.0 : confidenceSamples.Average(),
                RecommendedDefaultMode = defaultMode,
                RecommendedProfileChanges = recommendedProfileChanges,
                TelemetryGaps = telemetryGaps.OrderBy(static id => id, StringComparer.OrdinalIgnoreCase).ToList()
            };

            foreach (var expectation in manifest.Benchmarks)
            {
                if (summary.PositivePassRate < expectation.MinimumPositivePassRate)
                    summary.FailedExpectations.Add($"{expectation.ProfileName}: positive pass rate {summary.PositivePassRate:P1} below {expectation.MinimumPositivePassRate:P1}");
                if (summary.CriticalFalsePositiveCount > expectation.MaximumCriticalFalsePositives)
                    summary.FailedExpectations.Add($"{expectation.ProfileName}: critical false positives {summary.CriticalFalsePositiveCount} exceeded {expectation.MaximumCriticalFalsePositives}");
            }

            summary.PassedExpectations = summary.FailedExpectations.Count == 0;

            Directory.CreateDirectory(outputDirectory);
            summary.JsonPath = Path.Combine(outputDirectory, "content-pack-benchmark.json");
            summary.MarkdownPath = Path.Combine(outputDirectory, "content-pack-benchmark.md");
            File.WriteAllText(summary.JsonPath, JsonSerializer.Serialize(summary, JsonOptions));
            File.WriteAllText(summary.MarkdownPath, ToMarkdown(summary));
            return summary;
        }

        private static RuleReplaySample LoadReplaySample(string relativePath)
        {
            var path = Path.IsPathRooted(relativePath)
                ? relativePath
                : Path.GetFullPath(Path.Combine(AppContext.BaseDirectory, "..", "..", "..", "..", relativePath));
            using var stream = File.Open(path, FileMode.Open, FileAccess.Read, FileShare.Read);
            return JsonSerializer.Deserialize<RuleReplaySample>(stream, new JsonSerializerOptions { PropertyNameCaseInsensitive = true, Converters = { new JsonStringEnumConverter() } })
                ?? new RuleReplaySample();
        }

        private static string ToMarkdown(ContentPackBenchmarkResultSummary summary)
        {
            var builder = new StringBuilder();
            builder.AppendLine("# Content Pack Benchmark");
            builder.AppendLine();
            builder.AppendLine($"- Pack: `{summary.PackId}`");
            builder.AppendLine($"- Version: `{summary.Version}`");
            builder.AppendLine($"- Enabled profiles: {string.Join(", ", summary.EnabledProfiles)}");
            builder.AppendLine($"- Rules covered: {summary.RulesCovered}");
            builder.AppendLine($"- Positive pass rate: {summary.PositivePassRate:P1}");
            builder.AppendLine($"- Benign false positives: {summary.BenignFalsePositiveCount}");
            builder.AppendLine($"- Critical false positives: {summary.CriticalFalsePositiveCount}");
            builder.AppendLine($"- Average confidence: {summary.AverageConfidence:F2}");
            builder.AppendLine($"- Recommended default mode: `{summary.RecommendedDefaultMode}`");
            builder.AppendLine($"- Passed expectations: `{summary.PassedExpectations}`");
            builder.AppendLine();

            builder.AppendLine("## Rules Without Samples");
            if (summary.RulesWithoutSamples.Count == 0)
            {
                builder.AppendLine("- None");
            }
            else
            {
                foreach (var ruleId in summary.RulesWithoutSamples)
                    builder.AppendLine($"- {ruleId}");
            }

            builder.AppendLine();
            builder.AppendLine("## Recommended Profile Changes");
            if (summary.RecommendedProfileChanges.Count == 0)
            {
                builder.AppendLine("- None");
            }
            else
            {
                foreach (var change in summary.RecommendedProfileChanges)
                    builder.AppendLine($"- {change}");
            }

            builder.AppendLine();
            builder.AppendLine("## Telemetry Gaps");
            if (summary.TelemetryGaps.Count == 0)
            {
                builder.AppendLine("- None");
            }
            else
            {
                foreach (var gap in summary.TelemetryGaps)
                    builder.AppendLine($"- {gap}");
            }

            builder.AppendLine();
            builder.AppendLine("## Failed Expectations");
            if (summary.FailedExpectations.Count == 0)
            {
                builder.AppendLine("- None");
            }
            else
            {
                foreach (var failure in summary.FailedExpectations)
                    builder.AppendLine($"- {failure}");
            }

            return builder.ToString();
        }
    }
}
