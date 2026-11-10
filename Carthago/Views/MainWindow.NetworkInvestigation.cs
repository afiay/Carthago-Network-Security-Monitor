// SPDX-License-Identifier: MIT
// File: Views/MainWindow.NetworkInvestigation.cs
using System;
using System.Windows;
using System.Windows.Input;
using Carthago.Models;
using Carthago.Views;

namespace Carthago
{
    public partial class MainWindow
    {
        private void AttachIncidentInvestigation(IncidentsPage page)
        {
            page.NetworkInvestigationRequested -= OpenNetworkInvestigation;
            page.NetworkInvestigationRequested += OpenNetworkInvestigation;
            page.ExportAnalysisRequested -= OpenAvailableAnalysisExport;
            page.ExportAnalysisRequested += OpenAvailableAnalysisExport;
        }

        private void Nav_NetworkInvestigation_Click(object? sender, RoutedEventArgs e)
            => OpenNetworkInvestigation(null);

        private void GlobalInvestigationSearch_Click(object sender, RoutedEventArgs e)
            => OpenNetworkInvestigation(GlobalInvestigationSearchText.Text);

        private void GlobalInvestigationSearch_KeyDown(object sender, KeyEventArgs e)
        {
            if (e.Key != Key.Enter)
                return;
            OpenNetworkInvestigation(GlobalInvestigationSearchText.Text);
            e.Handled = true;
        }

        internal void OpenNetworkInvestigation(string? searchTerm)
        {
            if (NetworkInvestigationFrame.Content is not NetworkInvestigationPage page)
            {
                page = new NetworkInvestigationPage();
                page.SearchRequested += (_, _) => OpenNetworkInvestigation(page.SearchTerm);
                page.TrafficRequested += (_, _) => Nav_LiveTraffic_Click(this, new RoutedEventArgs());
                page.DetectionsRequested += (_, _) => Nav_Alerts_Click(this, new RoutedEventArgs());
                page.AnalyticsRequested += (_, _) => Nav_Analytics_Click2(this, new RoutedEventArgs());
                page.IncidentQueueRequested += (_, _) => Nav_IncidentQueue_Click(this, new RoutedEventArgs());
                page.DetectionRulesRequested += (_, _) => OpenDetectionRulesWorkspace();
                page.IncidentRequested += id => OpenIncidentWorkspace(id);
                NetworkInvestigationFrame.Content = page;
            }

            ShowView(NetworkInvestigationView);
            SidebarPanel?.ActivateNav("NetworkInvestigation");
            SidebarPanel?.HideAllFilters();
            var cachedIncidents = _sinkHost?.Analytics.GetRecentIncidents(250)
                ?? Array.Empty<Carthago.Analytics.Models.Incident>();
            // Sidebar return resumes the active investigation instead of
            // replacing it with a blank query. Explicit empty searches still
            // create a fresh step through the existing search controls.
            page.UpdateSnapshot(_traffic, _alerts, cachedIncidents,
                searchTerm ?? page.CurrentHistoryTerm);
        }

        private void TrafficInvestigateSource_Click(object sender, RoutedEventArgs e)
        {
            if (TrafficGrid.SelectedItem is TrafficRecord record && !string.IsNullOrWhiteSpace(record.Source))
                OpenNetworkInvestigation(record.Source);
        }

        private void TrafficInvestigateDestination_Click(object sender, RoutedEventArgs e)
        {
            if (TrafficGrid.SelectedItem is TrafficRecord record && !string.IsNullOrWhiteSpace(record.Destination))
                OpenNetworkInvestigation(record.Destination);
        }

        private void DetectionInvestigateSource_Click(object sender, RoutedEventArgs e)
        {
            if (AlertsGrid.SelectedItem is DetectionEvent detection && !string.IsNullOrWhiteSpace(detection.SourceIp))
                OpenNetworkInvestigation(detection.SourceIp);
        }

        private void DetectionInvestigateDestination_Click(object sender, RoutedEventArgs e)
        {
            if (AlertsGrid.SelectedItem is DetectionEvent detection && !string.IsNullOrWhiteSpace(detection.DestinationIp))
                OpenNetworkInvestigation(detection.DestinationIp);
        }
    }
}
