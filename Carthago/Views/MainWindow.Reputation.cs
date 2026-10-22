// SPDX-License-Identifier: MIT
// File: Views/MainWindow.Reputation.cs

using System;
using System.Windows;
using Carthago.Models;

namespace Carthago
{
    public partial class MainWindow
    {
        private async void LookupReputation_Click(object sender, RoutedEventArgs e)
        {
            if (TrafficGrid.SelectedItem is not TrafficRecord record) return;

            try
            {
                await _captureService.ManualReputationLookup(record);

                // Handle nullable fields defensively (model may expose bool? / int?)
                bool isMalicious = record.ReputationIsMalicious == true;
                int score = record.ReputationScore ?? 0;
                int reports = record.ReputationReports ?? 0;
                bool hasData = isMalicious || score > 0 || reports > 0 || record.ReputationLastSeen.HasValue;

                string msg = hasData
                    ? (isMalicious
                        ? $"⚠️ {record.Source} is malicious (Score: {score}, Reports: {reports})"
                        : $"{record.Source} Reputation Score: {score} (Reports: {reports})")
                    : $"No reputation data for {record.Source}";

                MessageBox.Show(
                    msg,
                    "Reputation Result",
                    MessageBoxButton.OK,
                    isMalicious ? MessageBoxImage.Warning : MessageBoxImage.Information);
            }
            catch (Exception ex)
            {
                MessageBox.Show($"Reputation lookup failed: {ex.Message}", "Error", MessageBoxButton.OK, MessageBoxImage.Error);
            }
        }

        private async void TestReputation_Click(object sender, RoutedEventArgs e)
        {
            try
            {
                // Known abusive IP (Tor exit node / commonly reported)
                var ip = "185.220.100.254";

                var test = new TrafficRecord
                {
                    Timestamp = DateTime.UtcNow.ToString("u"),
                    Source = ip,
                    Destination = "-",
                    Protocol = "IP",
                    Length = 0,
                    Info = "Synthetic test record for AbuseIPDB reputation lookup.",
                    ProcessName = "N/A",
                    ProcessId = 0 // keep non-nullable
                };

                await _captureService.ManualReputationLookup(test);

                _traffic.Insert(0, test);
                if (_traffic.Count > 200)
                    _traffic.RemoveAt(_traffic.Count - 1);

                bool isMalicious = test.ReputationIsMalicious == true;
                int score = test.ReputationScore ?? 0;
                int reports = test.ReputationReports ?? 0;

                MessageBox.Show(
                    $"IP: {test.Source}\n" +
                    $"Score: {score}\n" +
                    $"Reports: {reports}\n" +
                    $"Malicious: {isMalicious}\n" +
                    $"Last Seen: {test.ReputationLastSeen?.ToString("u") ?? "—"}",
                    "Reputation Test Result",
                    MessageBoxButton.OK,
                    isMalicious ? MessageBoxImage.Warning : MessageBoxImage.Information);
            }
            catch (Exception ex)
            {
                MessageBox.Show($"Test reputation failed: {ex.Message}", "Error", MessageBoxButton.OK, MessageBoxImage.Error);
            }
        }
    }
}
