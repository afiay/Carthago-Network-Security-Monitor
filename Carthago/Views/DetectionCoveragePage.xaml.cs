// SPDX-License-Identifier: MIT
// File: Views/DetectionCoveragePage.xaml.cs
using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;
using System.Windows;
using System.Windows.Controls;
using System.Windows.Input;
using Carthago.Engine.Rules;
using Carthago.Engine.Rules.Catalog;
using Carthago.Engine.Rules.Health;

namespace Carthago.Views
{
    public partial class DetectionCoveragePage : UserControl
    {
        private IReadOnlyList<CoverageRow> _rows = Array.Empty<CoverageRow>();
        private bool _hasLoaded;
        private bool _refreshing;

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

                _rows = snapshots.Select(snapshot => new CoverageRow(snapshot)).ToArray();
                _hasLoaded = true;
                RegisteredCount.Text = _rows.Count.ToString("N0");
                AlertModeCount.Text = _rows.Count(row => row.Snapshot.CurrentMode == RuleMode.Alert).ToString("N0");
                EvaluatedCount.Text = _rows.Count(row => row.Snapshot.RuntimeStats.Evaluations > 0).ToString("N0");
                ValidationErrorCount.Text = _rows.Count(row => row.Snapshot.HasValidationErrors).ToString("N0");

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

            RuleDetailHeading.Text = $"{snapshot.RuleId}  /  {snapshot.Name}";
            RuleDetailText.Text =
                $"Policy: {snapshot.CurrentMode}  •  Default enabled: {snapshot.Descriptor.EnabledByDefault}\n" +
                $"Evaluations: {runtime.Evaluations:N0}  •  Matches: {runtime.Matches:N0}  •  " +
                $"Skipped: {runtime.Skipped:N0}  •  Failures: {runtime.Failed:N0}\n" +
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
            public CoverageRow(RuleHealthSnapshot snapshot) => Snapshot = snapshot;

            public RuleHealthSnapshot Snapshot { get; }
            public string RuleId => Snapshot.RuleId;
            public string Name => Snapshot.Name;
            public string Category => Snapshot.Category;
            public string Mode => Snapshot.CurrentMode.ToString();
            public long Evaluations => Snapshot.RuntimeStats.Evaluations;
            public long Matches => Snapshot.RuntimeStats.Matches;
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
