// SPDX-License-Identifier: MIT
// File: Views/NetworkInvestigationPage.xaml.cs
using System;
using System.Collections.Generic;
using System.Linq;
using System.Net;
using System.Windows;
using System.Windows.Controls;
using System.Windows.Input;
using Carthago.Models;

namespace Carthago.Views
{
    public partial class NetworkInvestigationPage : UserControl
    {
        public event RoutedEventHandler? SearchRequested;
        public event RoutedEventHandler? TrafficRequested;
        public event RoutedEventHandler? DetectionsRequested;
        public event RoutedEventHandler? AnalyticsRequested;
        public event RoutedEventHandler? IncidentQueueRequested;
        public event RoutedEventHandler? DetectionRulesRequested;

        public string SearchTerm => InvestigationSearchText.Text.Trim();

        public NetworkInvestigationPage()
        {
            InitializeComponent();
        }

        public void UpdateSnapshot(
            IEnumerable<TrafficRecord> traffic,
            IEnumerable<DetectionEvent> detections,
            string? searchTerm)
        {
            var term = (searchTerm ?? string.Empty).Trim();
            InvestigationSearchText.Text = term;
            var trafficSnapshot = traffic.Take(200).ToArray();
            var detectionSnapshot = detections.Take(500).ToArray();
            var isAddress = IPAddress.TryParse(term, out var searchedAddress);
            var isPortQuery = !isAddress && TryParsePortQuery(term, out var searchedPort);

            var trafficMatches = trafficSnapshot.Where(r =>
                term.Length == 0 || (isAddress
                    ? MatchesAddress(r.Source, searchedAddress!) || MatchesAddress(r.Destination, searchedAddress!)
                    : isPortQuery
                        ? r.SourcePort == searchedPort || r.DestinationPort == searchedPort
                    : Contains(r.Source, term) || Contains(r.Destination, term) || Contains(r.Protocol, term)
                      || Contains(r.ApplicationService, term) || Contains(r.ProcessName, term)
                      || Contains(r.WhoisCountry, term) || Contains(r.Sni, term) || Contains(r.HttpHost, term)))
                .ToArray();
            var detectionMatches = detectionSnapshot.Where(d =>
                term.Length == 0 || (isAddress
                    ? MatchesAddress(d.SourceIp, searchedAddress!) || MatchesAddress(d.DestinationIp, searchedAddress!)
                    : isPortQuery
                        ? d.SourcePort == searchedPort || d.DestinationPort == searchedPort
                    : Contains(d.SourceIp, term) || Contains(d.DestinationIp, term) || Contains(d.RuleId, term)
                      || Contains(d.RuleName, term) || Contains(d.Description, term) || Contains(d.Country, term)
                      || Contains(d.DestinationHost, term) || Contains(d.ProcessName, term)
                      || Contains(d.EventId, term) || Contains(d.FlowId, term) || Contains(d.CorrelationId, term)
                      || Contains(d.Protocol, term)))
                .ToArray();

            InvestigationTrafficGrid.ItemsSource = trafficMatches;
            InvestigationDetectionsGrid.ItemsSource = detectionMatches;
            TrafficCountText.Text = $"{trafficMatches.Length:N0} matching retained records";
            DetectionCountText.Text = $"{detectionMatches.Length:N0} matching retained detections";
            ScopeText.Text = term.Length == 0
                ? $"Local snapshot: {trafficSnapshot.Length:N0} traffic rows and {detectionSnapshot.Length:N0} detection events · showing all retained items"
                : $"Local snapshot: {trafficSnapshot.Length:N0} traffic rows and {detectionSnapshot.Length:N0} detection events · {(isAddress ? "exact IP" : isPortQuery ? "exact source/destination port" : "recorded text")} match for '{term}'";
        }

        private static bool TryParsePortQuery(string term, out int port)
        {
            port = 0;
            return term.StartsWith("port:", StringComparison.OrdinalIgnoreCase)
                && int.TryParse(term.AsSpan(5).Trim(), out port)
                && port is >= 1 and <= 65535;
        }

        private static bool MatchesAddress(string? value, IPAddress searchedAddress)
            => IPAddress.TryParse(value, out var parsed) && parsed.Equals(searchedAddress);

        private static bool Contains(string? value, string text)
            => value?.Contains(text, StringComparison.OrdinalIgnoreCase) == true;

        private void Investigate_Click(object sender, RoutedEventArgs e)
            => SearchRequested?.Invoke(this, e);

        private void Refresh_Click(object sender, RoutedEventArgs e)
            => SearchRequested?.Invoke(this, e);

        private void InvestigationSearchText_KeyDown(object sender, KeyEventArgs e)
        {
            if (e.Key != Key.Enter)
                return;
            SearchRequested?.Invoke(this, new RoutedEventArgs());
            e.Handled = true;
        }

        private void OpenTraffic_Click(object sender, RoutedEventArgs e)
            => TrafficRequested?.Invoke(this, e);

        private void OpenDetections_Click(object sender, RoutedEventArgs e)
            => DetectionsRequested?.Invoke(this, e);

        private void OpenAnalytics_Click(object sender, RoutedEventArgs e)
            => AnalyticsRequested?.Invoke(this, e);

        private void OpenIncidentQueue_Click(object sender, RoutedEventArgs e)
            => IncidentQueueRequested?.Invoke(this, e);

        private void OpenDetectionRules_Click(object sender, RoutedEventArgs e)
            => DetectionRulesRequested?.Invoke(this, e);
    }
}
