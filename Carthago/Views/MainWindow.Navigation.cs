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
            // Collapse everything
            DashboardView.Visibility = Visibility.Collapsed;
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
            ShowView(SettingsView);
            SidebarPanel?.ActivateNav("DetectionRules");
            SidebarPanel?.HideAllFilters();
        }

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

            ApplyResponsiveLayoutTo(page);
            page.SelectIncident(incidentId);
        }
    }
}
