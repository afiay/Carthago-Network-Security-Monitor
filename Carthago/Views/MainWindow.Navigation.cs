// SPDX-License-Identifier: MIT
// File: Views/MainWindow.Navigation.cs
using System.Windows;
using System.Windows.Controls;
using Carthago.Views;

namespace Carthago
{
    public partial class MainWindow
    {
        /// <summary>
        /// Central helper to switch between high-level views.
        /// Collapses all known views, then shows the requested one.
        /// </summary>
        private void ShowView(Grid target)
        {
            // Map overlay work is UI-only and should not continue while hidden.
            _trafficMapSvc?.SetVisualizationActive(ReferenceEquals(target, AnalyticsView));
            // Collapse everything
            DashboardView.Visibility = Visibility.Collapsed;
            MonitoringHealthView.Visibility = Visibility.Collapsed;
            NetworkInvestigationView.Visibility = Visibility.Collapsed;
            DetectionCoverageView.Visibility = Visibility.Collapsed;
            AnomaliesView.Visibility = Visibility.Collapsed;
            LiveTrafficView.Visibility = Visibility.Collapsed;
            AlertsView.Visibility = Visibility.Collapsed;
            SinkEventsView.Visibility = Visibility.Collapsed;
            HostIntegrityView.Visibility = Visibility.Collapsed;
            AnalyticsView.Visibility = Visibility.Collapsed;
            IntegrationsView.Visibility = Visibility.Collapsed;
            IncidentsView.Visibility = Visibility.Collapsed;
            ThreatFeedView.Visibility = Visibility.Collapsed;
            CiscoToolsView.Visibility = Visibility.Collapsed;
            SessionArchiveView.Visibility = Visibility.Collapsed;
            SettingsView.Visibility = Visibility.Collapsed;

            // Show selected
            target.Visibility = Visibility.Visible;
        }

        // ========================= NAV: DASHBOARD =========================

        private void Nav_Dashboard_Click(object? sender, RoutedEventArgs e)
        {
            ShowView(DashboardView);
            SidebarPanel?.ActivateNav("Dashboard");

            // No filters in sidebar for dashboard
            SidebarPanel?.HideAllFilters();
        }

        private void DashboardOpenMonitoringHealth_Click(object sender, RoutedEventArgs e)
            => Nav_MonitoringHealth_Click(sender, e);

        private void DashboardOpenDetectionCoverage_Click(object sender, RoutedEventArgs e)
            => OpenDetectionRulesWorkspace();

        private void Nav_MonitoringHealth_Click(object? sender, RoutedEventArgs e)
        {
            if (MonitoringHealthFrame.Content is not MonitoringHealthPage page)
            {
                page = new MonitoringHealthPage();
                page.RawTrafficRequested += (_, _) => Nav_LiveTraffic_Click(this, new RoutedEventArgs());
                MonitoringHealthFrame.Content = page;
            }

            ShowView(MonitoringHealthView);
            SidebarPanel?.ActivateNav("MonitoringHealth");
            SidebarPanel?.HideAllFilters();
            UpdateMonitoringHeader();
        }

        // ======================= NAV: LIVE TRAFFIC ========================

        private void Nav_LiveTraffic_Click(object? sender, RoutedEventArgs e)
        {
            ShowView(LiveTrafficView);
            SidebarPanel?.ActivateNav("LiveTraffic");

            // Only show the Live Traffic filter
            SidebarPanel?.ShowTrafficFilters();
        }

        // ========================= NAV: ALERTS / IDS ======================

        private void Nav_Alerts_Click(object? sender, RoutedEventArgs e)
        {
            ShowView(AlertsView);
            SidebarPanel?.ActivateNav("Alerts");

            // Only show the IDS / Alerts filter
            SidebarPanel?.ShowDetectionFilters();
        }

        // ======================== NAV: HOST INTEGRITY =====================

        private void Nav_HostIntegrity_Click(object? sender, RoutedEventArgs e)
        {
            ShowView(HostIntegrityView);
            SidebarPanel?.ActivateNav("HostIntegrity");

            // Populate the frame on demand. The v6 shell already had the
            // container, but without this assignment the page could open blank.
            if (HostIntegrityFrame.Content is not Carthago.Views.HostIntegrityPage)
                HostIntegrityFrame.Content = new Carthago.Views.HostIntegrityPage();
            ApplyResponsiveLayoutTo(HostIntegrityFrame.Content);

            // No sidebar filters for this view
            SidebarPanel?.HideAllFilters();
        }

        // ========================= NAV: SETTINGS ==========================

        private void Nav_Settings_Click(object? sender, RoutedEventArgs e)
        {
            ShowView(SettingsView);
            SidebarPanel?.ActivateNav("SystemSettings");

            SidebarPanel?.HideAllFilters();
        }

        // ======================== NAV: CISCO TOOLS ========================

        private void Nav_CiscoTools_Click(object? sender, RoutedEventArgs e)
        {
            ShowView(CiscoToolsView);
            SidebarPanel?.ActivateNav("CiscoTools");

            // Cisco tools uses its own internal filtering, no sidebar filters
            SidebarPanel?.HideAllFilters();
        }

        internal void OpenDetectionRulesWorkspace()
        {
            if (DetectionCoverageFrame.Content is not DetectionCoveragePage page)
            {
                page = new DetectionCoveragePage();
                page.DetectionsRequested += (_, _) => Nav_Alerts_Click(this, new RoutedEventArgs());
                page.SettingsRequested += (_, _) => Nav_Settings_Click(this, new RoutedEventArgs());
                DetectionCoverageFrame.Content = page;
            }

            ShowView(DetectionCoverageView);
            SidebarPanel?.ActivateNav("DetectionRules");
            SidebarPanel?.HideAllFilters();
        }

        private void Nav_DetectionCoverage_Click(object? sender, RoutedEventArgs e)
            => OpenDetectionRulesWorkspace();

        private void SettingsOpenDetectionCoverage_Click(object sender, RoutedEventArgs e)
            => OpenDetectionRulesWorkspace();

        private void SettingsOpenNetworkInvestigation_Click(object sender, RoutedEventArgs e)
            => OpenNetworkInvestigation(string.Empty);

        internal void OpenRawTrafficWorkspace()
            => Nav_LiveTraffic_Click(this, new RoutedEventArgs());

        internal void OpenRawDetectionsWorkspace()
            => Nav_Alerts_Click(this, new RoutedEventArgs());

        internal void OpenAnomaliesWorkspace()
            => Nav_Anomalies_Click(this, new RoutedEventArgs());

        internal void OpenHostIntegrityWorkspace()
            => Nav_HostIntegrity_Click(this, new RoutedEventArgs());

        internal void OpenIncidentWorkspace(string? incidentId)
        {
            EnsureSinkHost();
            ShowView(IncidentsView);
            SidebarPanel?.ActivateNav("Incidents");

            if (IncidentsFrame.Content is not IncidentsPage page)
            {
                page = new IncidentsPage(_sinkHost!, "Incidents");
                IncidentsFrame.Content = page;
            }

            AttachIncidentInvestigation(page);
            ApplyResponsiveLayoutTo(page);
            page.SelectIncident(incidentId);
        }
    }
}
