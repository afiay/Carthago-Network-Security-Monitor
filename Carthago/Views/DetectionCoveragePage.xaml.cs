// SPDX-License-Identifier: MIT
// File: Views/DetectionCoveragePage.xaml.cs
using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using System.Windows;
using System.Windows.Controls;
using System.Windows.Input;
using Carthago.Engine.Rules;
using Carthago.Engine.Rules.Catalog;
using Carthago.Engine.Rules.Health;
using Carthago.Services;
using Carthago.Services.Diagnostics;

namespace Carthago.Views
{
    public partial class DetectionCoveragePage : UserControl
    {
        private IReadOnlyList<CoverageRow> _rows = Array.Empty<CoverageRow>();
        private bool _hasLoaded;
        private bool _refreshing;
        private long? _previousEngineEvaluations;
        private DateTime? _lastSuccessfulRefreshUtc;

        public event EventHandler? DetectionsRequested;
        public event EventHandler? SettingsRequested;

        public DetectionCoveragePage()
        {
            InitializeComponent();
            Loaded += async (_, _) =>
            {
                if (!_hasLoaded && !_refreshing)
                    await RefreshSnapshotAsync();
            };
        }

        private async void RefreshCoverage_Click(object sender, RoutedEventArgs e)
            => await RefreshSnapshotAsync();

        private async Task RefreshSnapshotAsync()
        {
            if (_refreshing)
                return;

            _refreshing = true;
            RefreshCoverageButton.IsEnabled = false;
            SnapshotStatusText.Text = "Reading registered rule metadata and local process counters…";

            try
            {
                // Catalog scoring/validation runs away from the UI thread. It does not
                // change modes, enable rules, or subscribe to incoming traffic.
                var snapshots = await Task.Run(RuleCatalog.HealthSnapshots);
                var capturedAt = DateTime.UtcNow;

                // Snapshot the policy/counters into the same projection as the displayed rows.
                // These independent stores are sampled sequentially, not atomically.
                var metricCounts = RuleEngineMetrics.Snapshot();
                _rows = snapshots.Select(snapshot => new CoverageRow(snapshot, metricCounts)).ToArray();
                _hasLoaded = true;
                RegisteredCount.Text = _rows.Count.ToString("N0");
                AlertModeCount.Text = _rows.Count(row => row.Snapshot.CurrentMode == RuleMode.Alert).ToString("N0");
                EvaluatedCount.Text = _rows.Count(row => row.Snapshot.RuntimeStats.Evaluations > 0).ToString("N0");
                ValidationErrorCount.Text = _rows.Count(row => row.Snapshot.HasValidationErrors).ToString("N0");

                // These are in-process counters, not packet-capture totals or a quality PASS.
                var engineCounters = RuleEngineHealthState.ReadLifetimeCounters();
                long CountMetric(string name) => metricCounts
                    .Where(pair => pair.Key == name || pair.Key.EndsWith(":" + name, StringComparison.Ordinal))
                    .Sum(pair => pair.Value);
                RuntimeFunnelText.Text =
                    $"Engine record evaluations: {engineCounters.Evaluations:N0}  •  " +
                    $"Rule evaluations: {_rows.Sum(row => row.Snapshot.RuntimeStats.Evaluations):N0}  •  " +
                    $"Rule matches: {_rows.Sum(row => row.Snapshot.RuntimeStats.Matches):N0}  •  " +
                    $"Rule skips: {_rows.Sum(row => row.Snapshot.RuntimeStats.Skipped):N0}  •  " +
                    $"Rule failures: {_rows.Sum(row => row.Snapshot.RuntimeStats.Failed):N0}  •  " +
                    $"Journal failures: {engineCounters.JournalFailures:N0}.\n" +
                    $"Post-policy outcomes: shadowed {CountMetric(RuleMetricNames.RuleShadowedTotal):N0}  •  " +
                    $"suppressed {CountMetric(RuleMetricNames.RuleSuppressedTotal):N0}  •  " +
                    $"emitted {CountMetric(RuleMetricNames.RuleEmittedTotal):N0}  •  " +
                    $"persisted {CountMetric(RuleMetricNames.RulePersistedTotal):N0}. " +
                    "Counts are since process start; categories can overlap and are not packet totals. " +
                    "Refresh while capture is active to diagnose the detection path.";
                RuntimeDiagnosisText.Text = DetectionActivityDiagnosis.ForPipeline(
                    engineCounters.Evaluations,
                    _rows.Sum(row => row.Snapshot.RuntimeStats.Evaluations),
                    _rows.Sum(row => row.Snapshot.RuntimeStats.Matches),
                    CountMetric(RuleMetricNames.RuleShadowedTotal),
                    CountMetric(RuleMetricNames.RuleSuppressedTotal),
                    CountMetric(RuleMetricNames.RuleEmittedTotal),
                    engineCounters.JournalFailures);
                RuntimeProgressText.Text = DetectionActivityDiagnosis.ForProgress(
                    _previousEngineEvaluations, engineCounters.Evaluations);
                _previousEngineEvaluations = engineCounters.Evaluations;
                _lastSuccessfulRefreshUtc = capturedAt;

                var unobserved = _rows.Count(row => row.Snapshot.TelemetryCoverage.MissingRequiredTelemetry.Count > 0);
                SnapshotStatusText.Text = $"Catalog read at {capturedAt:yyyy-MM-dd HH:mm:ss} UTC • " +
                    $"{unobserved:N0} rules have required telemetry kinds not yet observed in this process. " +
                    "Refresh to inspect newer runtime observations.";
                ApplyFilter();
            }
            catch (Exception ex)
            {
                // Failed reads are explicit; retain any last successfully loaded snapshot.
                SnapshotStatusText.Text = $"Rule catalog snapshot unavailable: {ex.GetType().Name}: {ex.Message}";
            }
            finally
            {
                _refreshing = false;
                RefreshCoverageButton.IsEnabled = true;
            }
        }

        private void CopyDiagnostics_Click(object sender, RoutedEventArgs e)
        {
            if (!_hasLoaded || !_lastSuccessfulRefreshUtc.HasValue)
            {
                CopyDiagnosticsStatusText.Text = "Refresh actual status before copying diagnostics.";
                return;
            }

            // Bounded, source-observed diagnostic metadata only; no raw packets,
            // payloads, host addresses or inferred rule qualification.
            try
            {
                var report = new StringBuilder()
                    .AppendLine("CARTHAGO DETECTION DIAGNOSTICS — SOURCE-OBSERVED, NOT ACCURACY CERTIFIED")
                    .AppendLine($"Snapshot UTC: {_lastSuccessfulRefreshUtc.Value:O}")
                    .AppendLine("Counters: local to the process; sampled non-atomically; no packet counts.")
                    .AppendLine(RuntimeDiagnosisText.Text)
                    .AppendLine(RuntimeProgressText.Text)
                    .AppendLine(RuntimeFunnelText.Text)
                    .AppendLine($"Catalog rules: {_rows.Count:N0}")
                    .AppendLine("Active or skipped rules (up to 30, prioritizing failures):");

                var active = _rows
                    .Where(row => row.Snapshot.RuntimeStats.Evaluations > 0 ||
                                  row.Snapshot.RuntimeStats.Skipped > 0 ||
                                  row.Snapshot.RuntimeStats.Failed > 0)
                    .OrderByDescending(row => row.Snapshot.RuntimeStats.Failed)
                    .ThenByDescending(row => row.Snapshot.RuntimeStats.Skipped)
                    .ThenBy(row => row.RuleId, StringComparer.Ordinal)
                    .Take(30)
                    .ToArray();
                if (active.Length == 0)
                    report.AppendLine("No per-rule execution or selector-skip counters observed.");
                foreach (var row in active)
                    report.AppendLine(
                        $"{row.RuleId}: {row.ActivityStatus} | evaluated={row.Evaluations} " +
                        $"matches={row.Matches} skipped={row.Skipped} failures={row.Snapshot.RuntimeStats.Failed} " +
                        $"emitted={row.Emitted} reason={row.NoMatchReason}");

                Clipboard.SetText(report.ToString());
                CopyDiagnosticsStatusText.Text = $"Copied bounded diagnostic metadata for {active.Length} rules.";
            }
            catch (Exception ex)
            {
                CopyDiagnosticsStatusText.Text = $"Copy unavailable: {ex.GetType().Name}: {ex.Message}";
            }
        }

        private void RuleSearch_KeyDown(object sender, KeyEventArgs e)
        {
            if (e.Key != Key.Enter)
                return;

            ApplyFilter();
            e.Handled = true;
        }

        private void ApplyRuleSearch_Click(object sender, RoutedEventArgs e) => ApplyFilter();

        private void RuleStatusFilter_SelectionChanged(object sender, SelectionChangedEventArgs e)
        {
            if (IsLoaded)
                ApplyFilter();
        }

        private void ApplyFilter()
        {
            var search = RuleSearchText.Text.Trim();
            var status = RuleStatusFilter.SelectedIndex;
            var selectedRuleId = (RuleCoverageGrid.SelectedItem as CoverageRow)?.RuleId;

            var filtered = _rows.Where(row =>
                    (search.Length == 0 || row.RuleId.Contains(search, StringComparison.OrdinalIgnoreCase)
                        || row.Name.Contains(search, StringComparison.OrdinalIgnoreCase)
                        || row.Category.Contains(search, StringComparison.OrdinalIgnoreCase))
                    && (status switch
                    {
                        1 => row.Snapshot.RuntimeStats.Evaluations == 0,
                        2 => row.Snapshot.HasValidationErrors,
                        3 => row.Snapshot.TelemetryCoverage.MissingRequiredTelemetry.Count > 0,
                        4 => row.Snapshot.CurrentMode != RuleMode.Alert,
                        5 => row.Diagnosis.State == RuleActivityState.MatchedNotEmitted,
                        6 => row.Diagnosis.State == RuleActivityState.EvaluatedNoMatch,
                        7 => row.Diagnosis.State is RuleActivityState.SkippedBeforeEvaluation or RuleActivityState.TelemetryUnobserved,
                        8 => row.Snapshot.RuntimeStats.Failed > 0,
                        _ => true
                    }))
                .ToArray();

            RuleCoverageGrid.ItemsSource = filtered;
            FilteredRuleCountText.Text = $"Showing {filtered.Length:N0} of {_rows.Count:N0} registered rules. " +
                "Choose a row for its evidence requirements and source-observed counters.";
            if (selectedRuleId != null)
                RuleCoverageGrid.SelectedItem = filtered.FirstOrDefault(row => row.RuleId == selectedRuleId);

            if (RuleCoverageGrid.SelectedItem == null)
                ShowDetails(null);
        }

        private void RuleCoverageGrid_SelectionChanged(object sender, SelectionChangedEventArgs e)
            => ShowDetails(RuleCoverageGrid.SelectedItem as CoverageRow);

        private void ShowDetails(CoverageRow? row)
        {
            if (row == null)
            {
                RuleDetailHeading.Text = "Select a rule to inspect its actual status";
                RuleDetailText.Text = "No rule selected. This view never changes detection policy.";
                return;
            }

            var snapshot = row.Snapshot;
            var runtime = snapshot.RuntimeStats;
            var telemetry = snapshot.TelemetryCoverage;
            var requirements = telemetry.RequiredTelemetry.Count == 0
                ? "No required kinds listed"
                : string.Join(", ", telemetry.RequiredTelemetry);
            var missing = telemetry.MissingRequiredTelemetry.Count == 0
                ? "None missing from observed kinds"
                : string.Join(", ", telemetry.MissingRequiredTelemetry);
            var findings = snapshot.ValidationFindings.Count == 0
                ? "None reported by catalog validator"
                : string.Join("; ", snapshot.ValidationFindings.Take(5).Select(finding =>
                    $"{finding.Severity} {finding.Code}: {finding.Message}"));

            var diagnosis = row.Diagnosis;
            var dominant = snapshot.NoMatchStats.DominantReason;
            var noMatchExplanation = dominant == null
                ? (runtime.Evaluations == 0
                    ? "No evaluation yet; inspect selector skips, policy, and required telemetry."
                    : "No recorded no-match reason; a match, suppression or instrumentation gap may explain this.")
                : $"{dominant.Code} ({dominant.Category}, {dominant.Count:N0} observations): {dominant.Message}";
            // This catalog view has no attached replay execution result by default.
            // A historical replay PASS is not independently labelled field accuracy.
            var replay = snapshot.ReplayCoverage;
            var replayExplanation = replay.SampleCount == 0
                ? "No replay evidence loaded in this view (does not mean no historical tests exist)."
                : $"{replay.Status}  •  {replay.BenignSampleCount} benign / {replay.MaliciousSampleCount} malicious cases  •  {replay.FailedSampleCount} failed; not independent field certification.";

            RuleDetailHeading.Text = $"{snapshot.RuleId}  /  {snapshot.Name}";
            RuleDetailText.Text =
                $"Policy: {snapshot.CurrentMode}  •  Default enabled: {snapshot.Descriptor.EnabledByDefault}\n" +
                $"Evaluations: {runtime.Evaluations:N0}  •  Matches: {runtime.Matches:N0}  •  " +
                $"Skipped: {runtime.Skipped:N0}  •  Failures: {runtime.Failed:N0}\n" +
                $"Runtime interpretation: {diagnosis.Label} — {diagnosis.Explanation}\n" +
                $"Next diagnostic check: {diagnosis.NextCheck}\n" +
                $"Post-policy: shadowed {row.Shadowed:N0}  •  " +
                $"suppressed {row.Suppressed:N0}  •  " +
                $"emitted {row.Emitted:N0}  •  " +
                $"persisted {row.Persisted:N0}\n" +
                $"No-match / skipped reason: {noMatchExplanation}\n" +
                $"Replay qualification: {replayExplanation}\n" +
                $"Last evaluated (UTC): {runtime.LastEvaluatedUtc?.ToString("u") ?? "Not observed"}\n" +
                $"Required telemetry kinds: {requirements}\n" +
                $"Required telemetry kinds not yet observed: {missing}\n" +
                $"Catalog validation findings: {findings}\n" +
                $"Description: {snapshot.Descriptor.Description}";
        }

        private void OpenDetections_Click(object sender, RoutedEventArgs e)
            => DetectionsRequested?.Invoke(this, EventArgs.Empty);

        private void OpenSettings_Click(object sender, RoutedEventArgs e)
            => SettingsRequested?.Invoke(this, EventArgs.Empty);

        private sealed class CoverageRow
        {
            public CoverageRow(RuleHealthSnapshot snapshot, IReadOnlyDictionary<string, long> metrics)
            {
                Snapshot = snapshot;
                long Count(string name) => metrics.TryGetValue(snapshot.RuleId + ":" + name, out var count) ? count : 0;
                Shadowed = Count(RuleMetricNames.RuleShadowedTotal);
                Suppressed = Count(RuleMetricNames.RuleSuppressedTotal);
                Emitted = Count(RuleMetricNames.RuleEmittedTotal);
                Persisted = Count(RuleMetricNames.RulePersistedTotal);
                Diagnosis = DetectionActivityDiagnosis.ForRule(
                    snapshot.RuntimeStats,
                    snapshot.CurrentMode,
                    snapshot.NoMatchStats,
                    snapshot.TelemetryCoverage.MissingRequiredTelemetry.Count,
                    Shadowed, Suppressed, Emitted);
            }

            public RuleHealthSnapshot Snapshot { get; }
            public long Shadowed { get; }
            public long Suppressed { get; }
            public long Emitted { get; }
            public long Persisted { get; }
            public RuleActivityDiagnosis Diagnosis { get; }
            public string ActivityStatus => Diagnosis.Label;
            public string RuleId => Snapshot.RuleId;
            public string Name => Snapshot.Name;
            public string Category => Snapshot.Category;
            public string Mode => Snapshot.CurrentMode.ToString();
            public long Evaluations => Snapshot.RuntimeStats.Evaluations;
            public long Matches => Snapshot.RuntimeStats.Matches;
            public long Skipped => Snapshot.RuntimeStats.Skipped;
            public string NoMatchReason => Snapshot.NoMatchStats.DominantReason?.Code ??
                (Snapshot.RuntimeStats.Evaluations == 0 ? "Not evaluated" : "Not recorded");
            public string TelemetryStatus
            {
                get
                {
                    var impact = Snapshot.TelemetryCoverage;
                    return impact.RequiredTelemetry.Count == 0 ? "None required"
                        : $"{impact.ObservedRequiredTelemetry.Count}/{impact.RequiredTelemetry.Count} kinds observed";
                }
            }
            public string FindingStatus => Snapshot.HasValidationErrors
                ? $"{Snapshot.ValidationFindings.Count} findings; errors"
                : Snapshot.ValidationFindings.Count == 0
                    ? "No catalog findings"
                    : $"{Snapshot.ValidationFindings.Count} non-error findings";
        }
    }
}
