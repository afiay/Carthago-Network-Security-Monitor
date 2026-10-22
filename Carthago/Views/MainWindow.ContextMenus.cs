using System;
using System.Text;
using System.Windows;
using Carthago.Models;

namespace Carthago
{
    public partial class MainWindow
    {
        private void Blacklist_10min_Click(object sender, RoutedEventArgs e)
        {
            if (TrafficGrid.SelectedItem is TrafficRecord record && !string.IsNullOrWhiteSpace(record.Source))
            {
                _blacklistService.Add(record.Source, TimeSpan.FromMinutes(10));
                MessageBox.Show($"{record.Source} blacklisted for 10 minutes.", "Blacklist");
            }
        }

        private void Blacklist_1h_Click(object sender, RoutedEventArgs e)
        {
            if (TrafficGrid.SelectedItem is TrafficRecord record && !string.IsNullOrWhiteSpace(record.Source))
            {
                _blacklistService.Add(record.Source, TimeSpan.FromHours(1));
                MessageBox.Show($"{record.Source} blacklisted for 1 hour.", "Blacklist");
            }
        }

        private void Blacklist_Indef_Click(object sender, RoutedEventArgs e)
        {
            if (TrafficGrid.SelectedItem is TrafficRecord record && !string.IsNullOrWhiteSpace(record.Source))
            {
                _blacklistService.Add(record.Source, null);
                MessageBox.Show($"{record.Source} blacklisted indefinitely.", "Blacklist");
            }
        }

        private void Alert_Blacklist_1h_Click(object sender, RoutedEventArgs e)
        {
            if (AlertsGrid.SelectedItem is DetectionEvent evt && !string.IsNullOrWhiteSpace(evt.SourceIp))
            {
                _blacklistService.Add(evt.SourceIp, TimeSpan.FromHours(1));
                MessageBox.Show($"{evt.SourceIp} blacklisted for 1 hour (from alert).", "Blacklist");
            }
        }

        private void Alert_Blacklist_Indef_Click(object sender, RoutedEventArgs e)
        {
            if (AlertsGrid.SelectedItem is DetectionEvent evt && !string.IsNullOrWhiteSpace(evt.SourceIp))
            {
                _blacklistService.Add(evt.SourceIp, null);
                MessageBox.Show($"{evt.SourceIp} blacklisted indefinitely (from alert).", "Blacklist");
            }
        }

        private void CopyAlert_Click(object sender, RoutedEventArgs e)
        {
            if (AlertsGrid.SelectedItem is DetectionEvent evt)
            {
                string dst = string.IsNullOrEmpty(evt.DestinationIp)
                    ? "N/A"
                    : (evt.DestinationPort.HasValue ? $"{evt.DestinationIp}:{evt.DestinationPort.Value}" : evt.DestinationIp);

                var sb = new StringBuilder()
                    .AppendLine(evt.Timestamp.ToString("u"))
                    .AppendLine($"{evt.Severity} - {evt.RuleId}")
                    .AppendLine(evt.Description)
                    .AppendLine($"Source: {evt.SourceIp}")
                    .AppendLine($"Destination: {dst}")
                    .AppendLine($"Protocol: {evt.Protocol}")
                    .AppendLine($"Count/Window: {evt.Count}/{evt.WindowSeconds}s");

                Clipboard.SetText(sb.ToString());
                MessageBox.Show("Alert copied to clipboard.", "Copied", MessageBoxButton.OK, MessageBoxImage.Information);
            }
        }
    }
}
