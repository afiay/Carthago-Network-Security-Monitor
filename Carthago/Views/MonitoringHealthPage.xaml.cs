// SPDX-License-Identifier: MIT
// File: Views/MonitoringHealthPage.xaml.cs
using System;
using System.Windows;
using System.Windows.Controls;
using System.Windows.Media;
using Carthago.Services;

namespace Carthago.Views
{
    public partial class MonitoringHealthPage : UserControl
    {
        public event RoutedEventHandler? RawTrafficRequested;

        public MonitoringHealthPage()
        {
            InitializeComponent();
        }

        public void UpdateSnapshot(
            string status,
            string sourceName,
            CaptureSourceHealth source,
            TrafficCaptureService.CaptureFlowSnapshot flow,
            string? error,
            DateTime? lastAnalysisUtc)
        {
            var isRunning = string.Equals(status, "Monitoring", StringComparison.OrdinalIgnoreCase)
                || string.Equals(status, "Degraded", StringComparison.OrdinalIgnoreCase);
            var recorded = source.Running || source.Observed > 0 || source.Forwarded > 0 || source.Dropped > 0
                || flow.Captured > 0 || flow.Displayed > 0 || flow.Dropped > 0;
            var unknown = "—";

            CaptureStateText.Text = status.ToUpperInvariant();
            CaptureStateText.Foreground = status switch
            {
                "Monitoring" => Brushes.LightGreen,
                "Degraded" or "Paused" => Brushes.Orange,
                "Error" => Brushes.IndianRed,
                _ => Brushes.LightSlateGray
            };
            SourceNameText.Text = string.IsNullOrWhiteSpace(sourceName)
                ? $"Capture source: {source.Source}"
                : $"Selected source: {sourceName} · producer: {source.Source}";
            CaptureExplanationText.Text = isRunning
                ? "Current local capture session; counters accumulate until the session is restarted."
                : recorded
                    ? "Capture is not active. The counters below are retained session observations, not current activity."
                    : "Capture is not active. No source or delivery observations are currently available.";

            SourceForwardedLabel.Text = source.Source.Equals("Npcap", StringComparison.OrdinalIgnoreCase)
                ? "PARSED RECORDS"
                : source.Source.Equals("ETW", StringComparison.OrdinalIgnoreCase)
                    ? "PUBLISHED EVENTS"
                    : "SOURCE FORWARDED";
            SourceDroppedLabel.Text = source.Source.Equals("Npcap", StringComparison.OrdinalIgnoreCase)
                ? "PARSE ERRORS"
                : source.Source.Equals("ETW", StringComparison.OrdinalIgnoreCase)
                    ? "SOURCE EVENT DROPS"
                    : "SOURCE ERRORS / DROPS";

            SourceObservedText.Text = source.Running || recorded ? source.Observed.ToString("N0") : unknown;
            SourceForwardedText.Text = source.Running || recorded ? source.Forwarded.ToString("N0") : unknown;
            SourceDroppedText.Text = source.Running || recorded ? source.Dropped.ToString("N0") : unknown;
            FlowCapturedText.Text = recorded ? flow.Captured.ToString("N0") : unknown;
            FlowDisplayedText.Text = recorded ? flow.Displayed.ToString("N0") : unknown;
            FlowDroppedText.Text = recorded ? flow.Dropped.ToString("N0") : unknown;

            LastAnalysisText.Text = lastAnalysisUtc.HasValue
                ? $"Last recorded analysis: {lastAnalysisUtc.Value.ToLocalTime():yyyy-MM-dd HH:mm:ss} (historical; not a heartbeat)"
                : "Last recorded analysis: unavailable";
            FlowReasonText.Text = $"Flow diagnostic: {flow.Reason}";
            var reportedError = string.IsNullOrWhiteSpace(error) ? source.Error : error;
            CaptureErrorText.Text = string.IsNullOrWhiteSpace(reportedError) ? string.Empty : $"Capture error: {reportedError}";
            SnapshotTimeText.Text = $"Local UI snapshot: {DateTime.Now:yyyy-MM-dd HH:mm:ss}";
        }

        private void OpenRawTraffic_Click(object sender, RoutedEventArgs e)
            => RawTrafficRequested?.Invoke(this, e);
    }
}
