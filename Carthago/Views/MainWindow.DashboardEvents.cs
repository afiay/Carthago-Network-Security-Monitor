// SPDX-License-Identifier: MIT
// GA UI-05 — SOURCE CANDIDATE — UNVERIFIED; no builds or tests executed.
// Dashboard-only projection of existing local DetectionEvent collection.
using System;
using System.Collections.Generic;
using System.Collections.ObjectModel;
using System.Collections.Specialized;
using System.Globalization;
using System.Linq;
using System.Windows;
using System.Windows.Controls;
using System.Windows.Threading;
using Carthago.Models;

namespace Carthago
{
    internal sealed class DashboardEventRowVm
    {
        public string EventTime { get; init; } = "—";
        public string Source { get; init; } = "—";
        public string Destination { get; init; } = "—";
        public string RuleId { get; init; } = "—";
        public string Severity { get; init; } = "—";
        public string Protocol { get; init; } = "—";
        public string EvidenceSummary { get; init; } = "Not reported";
        public string DeliveryStatus { get; init; } = "—";

        public static DashboardEventRowVm FromDetection(DetectionEvent evt)
        {
            var evidenceCount = evt.StructuredEvidence?.Items?.Count ?? 0;
            return new DashboardEventRowVm
            {
                // Display the recorded timestamp as-is; never silently assert its timezone.
                EventTime = evt.Timestamp == default
                    ? "—" : evt.Timestamp.ToString("yyyy-MM-dd HH:mm:ss", CultureInfo.InvariantCulture),
                Source = Display(evt.SourceIp),
                Destination = Display(evt.DestinationIp),
                RuleId = Display(evt.RuleId),
                Severity = evt.Severity.ToString(),
                Protocol = Display(evt.Protocol),
                // Neither raw Evidence nor sensitive StructuredEvidence.Items are rendered.
                EvidenceSummary = evidenceCount > 0
                    ? $"{evidenceCount} reported" :
                    string.IsNullOrWhiteSpace(evt.Evidence) ? "Not reported" : "Reported",
                // DetectionEvent.DeliveryStatus is not an incident triage or resolution state.
                DeliveryStatus = evt.DeliveryStatus.ToString()
            };
        }

        private static string Display(string? value)
            => string.IsNullOrWhiteSpace(value) ? "—" : value;
    }

    public partial class MainWindow
    {
        private const int DashboardLiveEventDisplayLimit = 80;
        private readonly ObservableCollection<DashboardEventRowVm> _dashboardLiveEventRows = new();
        private readonly DispatcherTimer _dashboardLiveEventsTimer =
            new() { Interval = TimeSpan.FromSeconds(1) };
        private bool _dashboardLiveEventsDirty = true;
        private bool _dashboardLiveEventsLastDemo;
        private string _dashboardLiveEventsLastCaptureStatus = string.Empty;

        private void InitializeDashboardLiveEvents()
        {
            DashboardLiveEventsGrid.ItemsSource = _dashboardLiveEventRows;
            _alerts.CollectionChanged += DashboardAlertsCollectionChanged;
            _dashboardLiveEventsTimer.Tick += DashboardLiveEventsTimerTick;
            _dashboardLiveEventsTimer.Start();
            RefreshDashboardLiveEvents();
        }

        private void CleanupDashboardLiveEvents()
        {
            _dashboardLiveEventsTimer.Stop();
            _dashboardLiveEventsTimer.Tick -= DashboardLiveEventsTimerTick;
            _alerts.CollectionChanged -= DashboardAlertsCollectionChanged;
        }

        private void DashboardAlertsCollectionChanged(object? sender, NotifyCollectionChangedEventArgs e)
            => _dashboardLiveEventsDirty = true;

        private void DashboardLiveEventsTimerTick(object? sender, EventArgs e)
        {
            if (!_dashboardCallbackGate.IsOpen || DashboardView.Visibility != Visibility.Visible)
                return;

            var captureStatus = CaptureStatusText.Text ?? string.Empty;
            if (_dashboardLiveEventsDirty || _dashboardLiveEventsLastDemo != _demoModeEnabled ||
                !string.Equals(_dashboardLiveEventsLastCaptureStatus, captureStatus, StringComparison.Ordinal))
                RefreshDashboardLiveEvents();
        }

        private void DashboardLiveEventsFilterChanged(object sender, SelectionChangedEventArgs e)
            => RefreshDashboardLiveEvents();

        private void DashboardLiveEventsTextChanged(object sender, TextChangedEventArgs e)
            => RefreshDashboardLiveEvents();

        private void DashboardLiveEventsClearFilters_Click(object sender, RoutedEventArgs e)
        {
            DashboardLiveSeverityFilter.SelectedIndex = 0;
            DashboardLiveProtocolFilter.SelectedIndex = 0;
            DashboardLiveRuleFilter.Clear();
            DashboardLiveSearchFilter.Clear();
            RefreshDashboardLiveEvents();
        }

        private void DashboardLiveEventsOpenDetections_Click(object sender, RoutedEventArgs e)
            => Nav_Alerts_Click(sender, e);

        private void RefreshDashboardLiveEvents()
        {
            if (!_dashboardInitialized || !_dashboardCallbackGate.IsOpen)
                return;

            var severity = (DashboardLiveSeverityFilter.SelectedItem as ComboBoxItem)?.Tag?.ToString() ?? string.Empty;
            var protocol = (DashboardLiveProtocolFilter.SelectedItem as ComboBoxItem)?.Tag?.ToString() ?? string.Empty;
            var rule = DashboardLiveRuleFilter.Text.Trim();
            var search = DashboardLiveSearchFilter.Text.Trim();

            IEnumerable<DetectionEvent> filtered = _alerts;
            if (!string.IsNullOrEmpty(severity))
                filtered = filtered.Where(evt => string.Equals(evt.Severity.ToString(), severity, StringComparison.OrdinalIgnoreCase));
            if (!string.IsNullOrEmpty(protocol))
                filtered = filtered.Where(evt => string.Equals(evt.Protocol, protocol, StringComparison.OrdinalIgnoreCase));
            if (!string.IsNullOrEmpty(rule))
                filtered = filtered.Where(evt => (evt.RuleId ?? string.Empty).Contains(rule, StringComparison.OrdinalIgnoreCase));
            if (!string.IsNullOrEmpty(search))
                filtered = filtered.Where(evt =>
                    (evt.SourceIp ?? string.Empty).Contains(search, StringComparison.OrdinalIgnoreCase) ||
                    (evt.DestinationIp ?? string.Empty).Contains(search, StringComparison.OrdinalIgnoreCase) ||
                    (evt.RuleId ?? string.Empty).Contains(search, StringComparison.OrdinalIgnoreCase) ||
                    (evt.Protocol ?? string.Empty).Contains(search, StringComparison.OrdinalIgnoreCase));

            var rows = filtered.Take(DashboardLiveEventDisplayLimit)
                .Select(DashboardEventRowVm.FromDetection).ToArray();
            ReplaceCollection(_dashboardLiveEventRows, rows);
            DashboardLiveEmptyText.Visibility = rows.Length == 0 ? Visibility.Visible : Visibility.Collapsed;
            DashboardLiveEmptyText.Text = _alerts.Count == 0
                ? "No local detection events observed in this session."
                : "No local detections match the selected filters.";

            var captureStatus = CaptureStatusText.Text ?? string.Empty;
            var monitoring = string.Equals(captureStatus, "MONITORING", StringComparison.OrdinalIgnoreCase);
            var degraded = string.Equals(captureStatus, "DEGRADED", StringComparison.OrdinalIgnoreCase);
            var captureCaption = monitoring ? "Capture monitoring" :
                degraded ? "Capture degraded" : "Capture not monitoring; retained rows may be historical";

            DashboardLiveEventsStatusText.Text =
                $"{rows.Length} shown · {_alerts.Count} local detection events retained (max 500) · newest received first · {captureCaption}";
            DashboardLiveEventsProvenanceText.Text = _demoModeEnabled
                ? "Demo mode enabled: events may include demo detections. Evidence is presence/count only; delivery is not incident resolution."
                : "Evidence is presence/count only; delivery is not incident resolution. Event time shown as recorded (timezone unverified).";

            _dashboardLiveEventsDirty = false;
            _dashboardLiveEventsLastDemo = _demoModeEnabled;
            _dashboardLiveEventsLastCaptureStatus = captureStatus;
        }
    }
}
