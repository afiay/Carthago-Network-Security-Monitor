// SPDX-License-Identifier: MIT
// File: Services/Benchmarking/TuningBenchmarkReportStore.cs
using System;
using System.IO;
using System.Globalization;
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
        public string GetHardeningAuditPath(string outputDirectory)
            => Path.Combine(outputDirectory, "rule-hardening-audit.md");

        public async Task SaveAsync(TuningBenchmarkReport report, string outputDirectory, CancellationToken cancellationToken = default)
        {
            if (report == null) throw new ArgumentNullException(nameof(report));
            Directory.CreateDirectory(outputDirectory);
            var jsonPath = GetJsonPath(outputDirectory);
            await File.WriteAllTextAsync(jsonPath, JsonSerializer.Serialize(report, JsonOptions), cancellationToken).ConfigureAwait(false);
            await File.WriteAllTextAsync(GetMarkdownPath(outputDirectory), ToMarkdown(report), cancellationToken).ConfigureAwait(false);
            await File.WriteAllTextAsync(GetHardeningAuditPath(outputDirectory),
                ToHardeningAuditMarkdown(report), cancellationToken).ConfigureAwait(false);
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
            sb.AppendLine($"- True-positive pass rate: {FormatRatio(summary.TruePositivePassRate)}");
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
                sb.AppendLine($"- False-positive rate: {FormatRatio(quality.FalsePositiveRate)}");
                sb.AppendLine($"- Balanced accuracy: {FormatRatio(quality.BalancedAccuracy)}");
                sb.AppendLine($"- Matthews correlation coefficient: {FormatNumber(quality.MatthewsCorrelationCoefficient)}");
                sb.AppendLine($"- F1: {FormatRatio(quality.F1Score)}");
                sb.AppendLine($"- Precision Wilson 95% interval: {FormatInterval(quality.Precision95)}");
                sb.AppendLine($"- Recall Wilson 95% interval: {FormatInterval(quality.Recall95)}");
                sb.AppendLine($"- Benign false-positive-rate Wilson 95% interval: {FormatInterval(quality.FalsePositiveRate95)}");
                sb.AppendLine("- Scope: labeled offline replay samples, not field prevalence or detection accuracy in production.");
                sb.AppendLine("- Related synthetic variants are NOT independent trials. Wilson intervals illustrate sampling uncertainty and can understate it when fixtures are correlated.");
                sb.AppendLine("- A measured 100% precision with few emitted alerts is not proof of 100% field precision.");
            }
            sb.AppendLine();
            sb.AppendLine("## Profile Comparison — Alert-level Quality and Uncertainty");
            sb.AppendLine("| Profile | TP | FP | FN | TN | Precision | Precision 95% | Recall | Balanced accuracy | MCC | Benign FPR | Benign FPR 95% |");
            sb.AppendLine("| --- | ---: | ---: | ---: | ---: | ---: | --- | ---: | ---: | ---: | ---: | --- |");
            foreach (var row in summary.SampleLevelQualityByProfile
                .OrderBy(static pair => pair.Key, StringComparer.OrdinalIgnoreCase))
            {
                var metrics = row.Value;
                sb.AppendLine($"| {EscapeCell(row.Key)} | {metrics.TruePositives} | {metrics.FalsePositives} | {metrics.FalseNegatives} | {metrics.TrueNegatives} | {FormatRatio(metrics.Precision)} | {FormatInterval(metrics.Precision95)} | {FormatRatio(metrics.Recall)} | {FormatRatio(metrics.BalancedAccuracy)} | {FormatNumber(metrics.MatthewsCorrelationCoefficient)} | {FormatRatio(metrics.FalsePositiveRate)} | {FormatInterval(metrics.FalsePositiveRate95)} |");
            }
            sb.AppendLine();
            sb.AppendLine("## Detection, Policy, and Alert Funnel");
            sb.AppendLine("- Unit: one labeled malicious (sample, expected rule) per replay profile; the same expected rule may appear in multiple samples.");
            sb.AppendLine("- Recognized: the detector matched, regardless of policy. Shadow/Suppressed are not alerts.");
            sb.AppendLine("- Policy-blocked: recognized matches held in Shadow or Disabled, not missing detections.");
            sb.AppendLine("- Eligible emission: among recognized expected rules with an effective Alert policy decision, the fraction actually recorded as simulated alerts.");
            sb.AppendLine("- N/A means there were no eligible decisions; it must not be presented as either 0% or 100% recall.");
            sb.AppendLine("- This is offline policy simulation, not live notification delivery or production precision.");
            sb.AppendLine();
            sb.AppendLine("| Profile | Expected | Recognized | Detector recall | Simulated alerts | Alert recall | Shadow | Disabled | No decision | Eligible | Eligible missing | Eligible emission | Policy inconsistencies | Benign alerts |");
            sb.AppendLine("| --- | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: |");
            foreach (var funnel in report.DetectionFunnelByProfile.Values
                .OrderBy(static entry => entry.ProfileName, StringComparer.OrdinalIgnoreCase))
            {
                sb.AppendLine($"| {EscapeCell(funnel.ProfileName)} | {funnel.ExpectedMaliciousRules} | {funnel.RecognizedByDetector} | {FormatRatio(funnel.DetectorRecognitionRate)} | {funnel.SimulatedAlerted} | {FormatRatio(funnel.AlertLevelRecall)} | {funnel.PolicyShadowed} | {funnel.PolicyDisabled} | {funnel.MissingPolicyDecisions} | {funnel.PolicyEligibleRules} | {funnel.EligibleButNotAlerted} | {FormatRatio(funnel.EligibleAlertEmissionRate)} | {funnel.AlertDecisionMismatches} | {funnel.BenignSimulatedAlerts} |");
            }

            sb.AppendLine();
            sb.AppendLine("## Explicit Rule Evidence Coverage");
            sb.AppendLine("- Unit: (replay sample, rule) pairs; positives are expected matches from malicious samples; negatives are explicitly labeled ExpectedNonMatches in either class.");
            sb.AppendLine("- Do not infer rule-level specificity or precision from unlabeled benign traffic. A benign raw detector match can be intentionally Shadowed.");
            sb.AppendLine("- N/A means no explicit positive or negative test exists for the denominator. Both control types are needed for paired evidence.");
            var coverage = report.RuleEvidenceCoverage;
            sb.AppendLine($"- Rules in inventory: {coverage.Count}");
            sb.AppendLine($"- With positive controls: {coverage.Count(static entry => entry.PositiveCases > 0)}");
            sb.AppendLine($"- With explicit negative controls: {coverage.Count(static entry => entry.ExplicitNegativeCases > 0)}");
            sb.AppendLine($"- With paired controls: {coverage.Count(static entry => entry.HasPairedControls)}");
            sb.AppendLine();
            sb.AppendLine("| Rule | Positive matched / cases | Recognition | Explicit negatives passed / cases | Negative pass rate | Benign raw matches | Paired |");
            sb.AppendLine("| --- | ---: | ---: | ---: | ---: | ---: | --- |");
            foreach (var entry in coverage.Where(static item =>
                    item.PositiveCases > 0 || item.ExplicitNegativeCases > 0)
                .OrderByDescending(static item => item.PositiveCases)
                .ThenByDescending(static item => item.ExplicitNegativeCases)
                .ThenBy(static item => item.RuleId, StringComparer.OrdinalIgnoreCase)
                .Take(40))
            {
                sb.AppendLine($"| {EscapeCell(entry.RuleId)} | {entry.PositiveRecognized}/{entry.PositiveCases} | {FormatRatio(entry.PositiveRecognitionRate)} | {entry.ExplicitNegativePassed}/{entry.ExplicitNegativeCases} | {FormatRatio(entry.ExplicitNegativePassRate)} | {entry.BenignRawMatches} | {(entry.HasPairedControls ? "Yes" : "No")} |");
            }
            if (coverage.Count(static item => item.PositiveCases > 0 || item.ExplicitNegativeCases > 0) > 40)
                sb.AppendLine("- Showing 40 tested rules. Full per-rule inventory and zero-coverage rules are available in the JSON report.");

            sb.AppendLine();
            sb.AppendLine("## Structured DNS Input Telemetry Diagnostics");
            sb.AppendLine("- Reporting only: missing/contradictory input fields are not inferred, repaired, or trusted.");
            sb.AppendLine("- Input issues describe replay evidence gaps, not an assertion that a DNS tunneling attack occurred.");
            var inputIssues = report.SampleResults
                .SelectMany(sample => sample.ExpectedRuleDiagnostics
                    .Where(diag => diag.InputTelemetryIssueCodes.Count > 0)
                    .Select(diag => (sample.Name, Diagnostic: diag)))
                .ToArray();
            if (inputIssues.Length == 0)
                sb.AppendLine("- No structured DNS input issues recorded for expected DNS rules.");
            else
            {
                sb.AppendLine("| Sample | Rule | Outcome | Affected / inspected | Stable input codes |");
                sb.AppendLine("| --- | --- | --- | ---: | --- |");
                foreach (var row in inputIssues.Take(40))
                {
                    // Keep raw query strings, IP addresses or arbitrary
                    // scenario identifiers out of this diagnostic section.
                    var safeName = row.Name.Length is > 0 and <= 100
                        && row.Name.All(static ch => char.IsAsciiLetterOrDigit(ch)
                            || ch is '-' or '_') ? row.Name : "REDACTED_SCENARIO";
                    sb.AppendLine($"| {EscapeCell(safeName)} | {EscapeCell(row.Diagnostic.RuleId)} | {EscapeCell(row.Diagnostic.Outcome)} | {row.Diagnostic.InputRecordsWithIssues}/{row.Diagnostic.InputRecordsInspected} | {EscapeCell(string.Join(", ", row.Diagnostic.InputTelemetryIssueCodes))} |");
                }
                if (inputIssues.Length > 40)
                    sb.AppendLine($"- Showing 40 of {inputIssues.Length} diagnostics. JSON retains all stable issue codes.");
            }

            sb.AppendLine();
            sb.AppendLine("## Alert-Level Recall Gaps");
            sb.AppendLine("- Unit: one expected malicious (sample, rule, profile) without an alert.");
            sb.AppendLine("- A raw detector match in Shadow mode remains a missed alert for this report.");
            sb.AppendLine("- The primary cause is prioritized for triage; additional factors may independently block the same alert.");
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
                sb.AppendLine("| Profile | Sample | Rule | Primary cause | Additional blocking factors | Mode | Confidence / floor | Evidence |");
                sb.AppendLine("| --- | --- | --- | --- | --- | --- | --- | --- |");
                foreach (var gap in report.RecallGaps.Take(50))
                {
                    var confidence = gap.Confidence.HasValue ? gap.Confidence.Value.ToString("F2", CultureInfo.InvariantCulture) : "N/A";
                    var floor = gap.ConfidenceFloor.HasValue ? gap.ConfidenceFloor.Value.ToString("F2", CultureInfo.InvariantCulture) : "N/A";
                    var otherFactors = gap.BlockingFactors.Where(factor =>
                        !string.Equals(factor, gap.Cause, StringComparison.OrdinalIgnoreCase));
                    sb.AppendLine($"| {EscapeCell(gap.ProfileName)} | {EscapeCell(gap.SampleName)} | {EscapeCell(gap.RuleId)} | {EscapeCell(gap.Cause)} | {EscapeCell(string.Join(", ", otherFactors))} | {EscapeCell(gap.EffectiveMode)} | {confidence} / {floor} | {EscapeCell(string.Join("; ", gap.Evidence))} |");
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
                sb.AppendLine($"- Malicious pass rate: {FormatRatio(profile.TruePositivePassRate)}");
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

        public string ToHardeningAuditMarkdown(TuningBenchmarkReport report)
        {
            if (report == null) throw new ArgumentNullException(nameof(report));

            var audit = report.RuleHardeningAudit;
            var sb = new StringBuilder();
            sb.AppendLine("# Carthago — full rule hardening audit");
            sb.AppendLine();
            sb.AppendLine("Evidence status here is only the scope of explicit offline replay controls. "
                + "It is not production certification, independent field precision, or approval to promote alerts.");
            sb.AppendLine("Shared numerical, telemetry and policy guards protect the detection engine, "
                + "but each rule requires independently validated real-world positive, benign, ambiguous and malformed cases.");
            sb.AppendLine();
            sb.AppendLine($"- Registered rules reviewed: {audit.Count}");
            sb.AppendLine($"- Contract issues: {audit.Count(static entry => entry.ContractIssues.Count > 0)}");
            sb.AppendLine($"- Paired synthetic controls: {audit.Count(static entry => entry.PairedSyntheticControls)}");
            sb.AppendLine($"- Positive only: {audit.Count(static entry => entry.EvidenceStatus == "PositiveOnly")}");
            sb.AppendLine($"- Negative only: {audit.Count(static entry => entry.EvidenceStatus == "NegativeOnly")}");
            sb.AppendLine($"- No explicit controls: {audit.Count(static entry => entry.EvidenceStatus == "NoExplicitReplayControls")}");
            sb.AppendLine();
            sb.AppendLine("## Coverage by detection family");
            sb.AppendLine("| Category | Rules | Paired | Positive-only | Negative-only | No controls | Contract issues |");
            sb.AppendLine("| --- | ---: | ---: | ---: | ---: | ---: | ---: |");
            foreach (var family in audit.GroupBy(static entry => entry.Category)
                .OrderByDescending(static group => group.Count())
                .ThenBy(static group => group.Key, StringComparer.OrdinalIgnoreCase))
            {
                sb.AppendLine($"| {EscapeCell(family.Key)} | {family.Count()} | {family.Count(static entry => entry.PairedSyntheticControls)} | {family.Count(static entry => entry.EvidenceStatus == "PositiveOnly")} | {family.Count(static entry => entry.EvidenceStatus == "NegativeOnly")} | {family.Count(static entry => entry.EvidenceStatus == "NoExplicitReplayControls")} | {family.Count(static entry => entry.ContractIssues.Count > 0)} |");
            }
            sb.AppendLine();
            sb.AppendLine("## All registered rules");
            sb.AppendLine("| Rule | Category | Maturity | Mode | Floor | + controls | - controls | Evidence status | Contract issues |");
            sb.AppendLine("| --- | --- | --- | --- | ---: | ---: | ---: | --- | --- |");
            foreach (var entry in audit.OrderByDescending(static item => item.ContractIssues.Count)
                .ThenBy(static item => item.PairedSyntheticControls)
                .ThenBy(static item => item.RuleId, StringComparer.OrdinalIgnoreCase))
            {
                sb.AppendLine($"| {EscapeCell(entry.RuleId)} | {EscapeCell(entry.Category)} | {EscapeCell(entry.Maturity)} | {EscapeCell(entry.PrecisionDefaultMode)} | {entry.MinimumConfidence}% | {entry.PositiveRecognized}/{entry.PositiveCases} | {entry.ExplicitNegativePassed}/{entry.ExplicitNegativeCases} | {EscapeCell(entry.EvidenceStatus)} | {EscapeCell(string.Join(", ", entry.ContractIssues))} |");
            }
            return sb.ToString();
        }

        private static string EscapeCell(string? value)
        {
            var clean = (value ?? string.Empty).Replace("\r", " ").Replace("\n", " ").Replace("|", "\\|");
            return clean.Length > 180 ? clean.Substring(0, 177) + "..." : clean;
        }

        // Markdown reports must be stable across Windows locale settings,
        // including Swedish comma decimals and localized percent spacing.
        private static string FormatRatio(double? value)
            => value.HasValue
                ? (value.Value * 100.0).ToString("F1", CultureInfo.InvariantCulture) + "%"
                : "N/A";

        private static string FormatInterval(DetectionRatioInterval? interval)
            => interval == null
                ? "N/A"
                : $"{FormatRatio(interval.Lower)}–{FormatRatio(interval.Upper)} (n={interval.Observations})";

        private static string FormatNumber(double? value)
            => value.HasValue
                ? value.Value.ToString("F3", CultureInfo.InvariantCulture)
                : "N/A";

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
