// SPDX-License-Identifier: MIT
// File: Services/Benchmarking/TuningBenchmarkReportStore.cs
using System;
using System.IO;
using System.Linq;
using System.Text;
using System.Text.Json;
using System.Text.Json.Serialization;
using System.Threading;
using System.Threading.Tasks;

namespace Carthago.Services.Benchmarking
{
    public sealed class TuningBenchmarkReportStore
    {
        private static readonly JsonSerializerOptions JsonOptions = new()
        {
            PropertyNamingPolicy = JsonNamingPolicy.CamelCase,
            DefaultIgnoreCondition = JsonIgnoreCondition.WhenWritingNull,
            WriteIndented = true,
            Converters = { new JsonStringEnumConverter() }
        };

        public string GetJsonPath(string outputDirectory) => Path.Combine(outputDirectory, "tuning-benchmark.json");
        public string GetMarkdownPath(string outputDirectory) => Path.Combine(outputDirectory, "tuning-benchmark.md");

        public async Task SaveAsync(TuningBenchmarkReport report, string outputDirectory, CancellationToken cancellationToken = default)
        {
            if (report == null) throw new ArgumentNullException(nameof(report));
            Directory.CreateDirectory(outputDirectory);
            var jsonPath = GetJsonPath(outputDirectory);
            await File.WriteAllTextAsync(jsonPath, JsonSerializer.Serialize(report, JsonOptions), cancellationToken).ConfigureAwait(false);
            await File.WriteAllTextAsync(GetMarkdownPath(outputDirectory), ToMarkdown(report), cancellationToken).ConfigureAwait(false);
        }

        public async Task<TuningBenchmarkReport?> LoadAsync(string outputDirectory, CancellationToken cancellationToken = default)
        {
            var path = GetJsonPath(outputDirectory);
            if (!File.Exists(path))
                return null;

            await using var stream = File.Open(path, FileMode.Open, FileAccess.Read, FileShare.ReadWrite);
            return await JsonSerializer.DeserializeAsync<TuningBenchmarkReport>(stream, JsonOptions, cancellationToken).ConfigureAwait(false);
        }

        public string ToMarkdown(TuningBenchmarkReport report)
        {
            var summary = report.Summary;
            var sb = new StringBuilder();
            sb.AppendLine("# Tuning Benchmark");
            sb.AppendLine();
            sb.AppendLine($"Generated (UTC): `{report.GeneratedAtUtc:u}`");
            sb.AppendLine($"Replay directory: `{report.ReplayDirectory}`");
            sb.AppendLine();
            sb.AppendLine("## Summary");
            sb.AppendLine($"- Replay samples: {summary.ReplaySampleCount}");
            sb.AppendLine($"- True-positive pass rate: {summary.TruePositivePassRate:P1}");
            sb.AppendLine($"- Benign false positives: {summary.BenignFalsePositiveCount}");
            sb.AppendLine($"- Benign critical alerts: {summary.BenignCriticalAlertCount}");
            if (summary.SampleLevelQuality is { } quality)
            {
                sb.AppendLine();
                sb.AppendLine("## Sample-level Detection Quality (SmallBusiness alert profile)");
                sb.AppendLine($"- True positives: {quality.TruePositives}");
                sb.AppendLine($"- False positives: {quality.FalsePositives}");
                sb.AppendLine($"- False negatives: {quality.FalseNegatives}");
                sb.AppendLine($"- True negatives: {quality.TrueNegatives}");
                sb.AppendLine($"- Precision: {FormatRatio(quality.Precision)}");
                sb.AppendLine($"- Recall: {FormatRatio(quality.Recall)}");
                sb.AppendLine($"- Specificity: {FormatRatio(quality.Specificity)}");
                sb.AppendLine($"- F1: {FormatRatio(quality.F1Score)}");
                sb.AppendLine("- Scope: labeled offline replay samples, not field prevalence or detection accuracy in production.");
            }
            sb.AppendLine();
            sb.AppendLine("## Alert-Level Recall Gaps");
            sb.AppendLine("- Unit: one expected malicious (sample, rule, profile) without an alert.");
            sb.AppendLine("- A raw detector match in Shadow mode remains a missed alert for this report.");
            sb.AppendLine("- Causes identify evidence and policy bottlenecks; they do not authorize automatic rule promotion.");
            if (report.RecallGaps.Count == 0)
            {
                sb.AppendLine("- No missed expected malicious alerts in the labeled replays.");
            }
            else
            {
                sb.AppendLine();
                sb.AppendLine("| Profile | Cause | Missed expected alerts |");
                sb.AppendLine("| --- | --- | ---: |");
                foreach (var group in report.RecallGaps.GroupBy(static gap => new { gap.ProfileName, gap.Cause })
                    .OrderBy(static group => group.Key.ProfileName, StringComparer.OrdinalIgnoreCase)
                    .ThenByDescending(static group => group.Count())
                    .ThenBy(static group => group.Key.Cause, StringComparer.OrdinalIgnoreCase))
                {
                    sb.AppendLine($"| {EscapeCell(group.Key.ProfileName)} | {EscapeCell(group.Key.Cause)} | {group.Count()} |");
                }
                sb.AppendLine();
                sb.AppendLine("### Missed alert examples");
                sb.AppendLine("| Profile | Sample | Rule | Cause | Mode | Confidence / floor | Evidence |");
                sb.AppendLine("| --- | --- | --- | --- | --- | --- | --- |");
                foreach (var gap in report.RecallGaps.Take(50))
                {
                    var confidence = gap.Confidence.HasValue ? gap.Confidence.Value.ToString("F2") : "N/A";
                    var floor = gap.ConfidenceFloor.HasValue ? gap.ConfidenceFloor.Value.ToString("F2") : "N/A";
                    sb.AppendLine($"| {EscapeCell(gap.ProfileName)} | {EscapeCell(gap.SampleName)} | {EscapeCell(gap.RuleId)} | {EscapeCell(gap.Cause)} | {EscapeCell(gap.EffectiveMode)} | {confidence} / {floor} | {EscapeCell(string.Join("; ", gap.Evidence))} |");
                }
                if (report.RecallGaps.Count > 50)
                    sb.AppendLine($"- Showing 50 of {report.RecallGaps.Count} gaps. The JSON report includes every gap.");
            }
            sb.AppendLine();
            sb.AppendLine("## Profile Results");
            foreach (var profile in report.ProfileResults.Values.OrderBy(static item => item.ProfileName, StringComparer.OrdinalIgnoreCase))
            {
                sb.AppendLine($"### {profile.ProfileName}");
                sb.AppendLine($"- Alerts: {profile.AlertCount}");
                sb.AppendLine($"- Shadows: {profile.ShadowCount}");
                sb.AppendLine($"- Suppressed: {profile.SuppressedCount}");
                sb.AppendLine($"- Benign alerts: {profile.BenignAlertCount}");
                sb.AppendLine($"- Malicious pass rate: {profile.TruePositivePassRate:P1}");
                if (profile.AlertRuleIds.Count > 0)
                    sb.AppendLine($"- Alerting rules: {string.Join(", ", profile.AlertRuleIds.Take(20))}");
                sb.AppendLine();
            }

            AppendList(sb, "Noisy Rules", summary.NoisyRules);
            AppendList(sb, "Rules Recommended For Shadow", summary.RulesRecommendedForShadow);
            AppendList(sb, "Rules Recommended For Alert", summary.RulesRecommendedForAlert);
            AppendList(sb, "Rules Without Replay Coverage", summary.RulesWithoutReplayCoverage);
            AppendList(sb, "Rules Without Benign Coverage", summary.RulesWithoutBenignCoverage);

            sb.AppendLine("## Confidence Distribution");
            foreach (var bucket in summary.ConfidenceDistribution.OrderBy(static item => item.Key, StringComparer.OrdinalIgnoreCase))
                sb.AppendLine($"- {bucket.Key}: {bucket.Value}");

            sb.AppendLine();
            sb.AppendLine("## Sample Errors");
            foreach (var sample in report.SampleResults.Where(static item => item.Errors.Count > 0))
            {
                sb.AppendLine($"### {sample.Name}");
                foreach (var error in sample.Errors)
                    sb.AppendLine($"- {error}");
                sb.AppendLine();
            }

            return sb.ToString();
        }

        private static string EscapeCell(string? value)
        {
            var clean = (value ?? string.Empty).Replace("\r", " ").Replace("\n", " ").Replace("|", "\\|");
            return clean.Length > 180 ? clean.Substring(0, 177) + "..." : clean;
        }

        private static string FormatRatio(double? value) => value.HasValue ? value.Value.ToString("P1") : "N/A";

        private static void AppendList(StringBuilder sb, string title, System.Collections.Generic.IReadOnlyList<string> items)
        {
            sb.AppendLine($"## {title}");
            if (items.Count == 0)
            {
                sb.AppendLine("- None");
                sb.AppendLine();
                return;
            }

            foreach (var item in items.Take(25))
                sb.AppendLine($"- {item}");
            sb.AppendLine();
        }
    }
}
