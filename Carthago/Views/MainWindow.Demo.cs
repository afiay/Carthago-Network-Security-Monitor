// SPDX-License-Identifier: MIT
using System;
using System.Linq;
using System.Threading.Tasks;
using System.Windows;
using System.Windows.Media;
using Carthago.Analytics.Services;

namespace Carthago
{
    public partial class MainWindow
    {
        private readonly DemoScenarioService _demoScenarioService = new();
        private bool _demoModeEnabled;

        private void InitializeDemoMode()
        {
#if DEBUG
            _demoModeEnabled = true;
#else
            _demoModeEnabled = Environment.GetCommandLineArgs()
                .Any(arg => string.Equals(arg, "--demo-mode", StringComparison.OrdinalIgnoreCase));
#endif

            if (DemoModeGroup == null || DemoModeStatusText == null)
                return;

            DemoModeGroup.Visibility = _demoModeEnabled ? Visibility.Visible : Visibility.Collapsed;
            if (DashboardShowDemoCheck != null)
            {
                DashboardShowDemoCheck.IsEnabled = _demoModeEnabled;
                if (!_demoModeEnabled)
                    DashboardShowDemoCheck.IsChecked = false;
            }

            RefreshDashboardCustomizationSources();
            RefreshDashboardLayoutFromPreferences();

            if (_demoModeEnabled)
            {
                ShowDemoStatus("Demo mode is enabled. Use the buttons below to generate clearly labeled simulated analytics data for a live product walkthrough.");
            }
        }

        private async void RunDemoIncident_Click(object sender, RoutedEventArgs e)
        {
            if (!_demoModeEnabled)
                return;

            EnsureSinkHost();
            var analytics = _sinkHost!.Analytics;
            var demo = _demoScenarioService.BuildCompromisedLaptopScenario();

            analytics.ClearDemoData(includeFeedback: false);

            foreach (var record in demo.TrafficRecords)
                analytics.OnTrafficRecord(record, demo.ScenarioTag);

            foreach (var anomaly in demo.AnomalySignals)
                analytics.OnAnomaly(anomaly, demo.ScenarioTag);

            foreach (var detection in demo.DetectionEvents)
                analytics.OnDetection(detection, demo.ScenarioTag);

            await Task.Delay(900);

            var incident = analytics.GetRecentIncidents(50)
                .Where(item => item.Tags.Any(tag => string.Equals(tag, demo.ScenarioTag, StringComparison.OrdinalIgnoreCase)))
                .OrderByDescending(item => item.RiskScore)
                .ThenByDescending(item => item.UpdatedUtc)
                .FirstOrDefault();

            if (incident != null)
            {
                analytics.UpdateIncidentPresentation(incident.Id, demo.ExpectedIncidentTitle, demo.ExpectedIncidentCategory);
            }

            await Task.Delay(200);

            ShowView(DashboardView);
            RefreshDashboardIncidents();
            RefreshDashboardAnomalies();
            RefreshDashboardBaseline();

            var selectedIncident = analytics.GetRecentIncidents(50)
                .Where(item => item.Tags.Any(tag => string.Equals(tag, demo.ScenarioTag, StringComparison.OrdinalIgnoreCase)))
                .OrderByDescending(item => item.RiskScore)
                .ThenByDescending(item => item.UpdatedUtc)
                .FirstOrDefault();

            if (selectedIncident != null)
                SelectDashboardIncident(selectedIncident.Id);

            ShowDemoStatus("Demo incident generated: Suspicious outbound behavior from 192.168.1.44", isSuccess: true);
        }

        private void ClearDemoData_Click(object sender, RoutedEventArgs e)
        {
            if (!_demoModeEnabled || _sinkHost == null)
                return;

            var removed = _sinkHost.Analytics.ClearDemoData();
            RefreshDashboardIncidents();
            RefreshDashboardAnomalies();
            RefreshDashboardBaseline();
            ShowView(DashboardView);
            ShowDemoStatus(
                removed == 0
                    ? "Demo data cleared. No tagged demo incidents or anomalies were present."
                    : $"Demo data cleared. Removed {removed} tagged demo items while leaving real incidents, settings, capture, and forensic views untouched.",
                isSuccess: true);
        }

        private void OpenDemoIncidentQueue_Click(object sender, RoutedEventArgs e)
        {
            ShowView(IncidentsView);
            if (IncidentsFrame.Content is not Views.IncidentsPage)
                IncidentsFrame.Content = new Views.IncidentsPage(_sinkHost!);
            ShowDemoStatus("Incident queue opened. Demo incidents remain labeled as simulated and separate from normal monitoring data.", isSuccess: true);
        }

        private void ShowDemoStatus(string message, bool isSuccess = false)
        {
            if (DemoModeStatusText == null)
                return;

            DemoModeStatusText.Text = message;
            DemoModeStatusText.Foreground = isSuccess
                ? (Brush)(TryFindResource("TextPrimaryBrush") ?? Brushes.White)
                : (Brush)(TryFindResource("TextSubtleBrush") ?? Brushes.Gainsboro);
        }
    }
}
