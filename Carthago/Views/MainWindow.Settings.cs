// File: Views/MainWindow.Settings.cs
// SPDX-License-Identifier: MIT
using System;
using System.Windows;
using System.Windows.Controls;
using Carthago.Models;
using Carthago.Services;

namespace Carthago
{
    public partial class MainWindow : Window
    {
        // ======== UI Handlers for Settings ========

        private void SaveSettings_Click(object sender, RoutedEventArgs e)
        {
            try
            {
                var sel = (SensitivityCombo.SelectedItem as ComboBoxItem)?.Content?.ToString() ?? "Balanced";
                if (!SensitivityExtensions.TryParse(sel, out var s))
                    s = Sensitivity.Balanced;

                string? defaultBpf = string.IsNullOrWhiteSpace(DefaultFilterText?.Text)
                    ? null
                    : DefaultFilterText.Text.Trim();
                bool enableWhois = EnableWhoisCheck?.IsChecked != false;
                bool enableReputation = EnableRepCheck?.IsChecked != false;
                bool autoStart = AutoStartCheck?.IsChecked == true;
                bool anomaliesOnly = AnomaliesOnlyToggle?.IsChecked != false;

                PreferencesService.Update(prefs =>
                {
                    prefs.Sensitivity = s;
                    prefs.AutoStartCapture = autoStart;
                    prefs.DefaultCaptureFilter = defaultBpf;
                    prefs.EnableWhois = enableWhois;
                    prefs.EnableReputation = enableReputation;
                    prefs.ShowAnomaliesOnly = anomaliesOnly;

                    ApplyDashboardSectionSettingsFromUi(prefs);
                });

                ApplyRuntimePreferences(PreferencesService.Current, applyActiveCaptureFilter: true);

                MessageBox.Show(
                    $"Settings saved.\nSensitivity: {s}\nAnomaly-first mode: {(anomaliesOnly ? "enabled" : "expanded telemetry")}",
                    "Settings",
                    MessageBoxButton.OK,
                    MessageBoxImage.Information);
            }
            catch (Exception ex)
            {
                MessageBox.Show($"Failed to save settings: {ex.Message}", "Settings", MessageBoxButton.OK, MessageBoxImage.Error);
            }
        }

        private void ResetSettings_Click(object sender, RoutedEventArgs e)
        {
            try
            {
                PreferencesService.Reset();
                ApplyRuntimePreferences(PreferencesService.Current, applyActiveCaptureFilter: true);
                MessageBox.Show("Settings reset to defaults.", "Settings", MessageBoxButton.OK, MessageBoxImage.Information);
            }
            catch (Exception ex)
            {
                MessageBox.Show($"Failed to reset settings: {ex.Message}", "Settings", MessageBoxButton.OK, MessageBoxImage.Error);
            }
        }

        private void DashboardSectionToggle_Changed(object sender, RoutedEventArgs e)
        {
            if (_syncingSettingsUi || !IsLoaded)
                return;

            PreferencesService.Update(prefs =>
            {
                ApplyDashboardSectionSettingsFromUi(prefs);
            });
        }

        private void ApplyDashboardSectionSettingsFromUi(AppPreferences prefs)
        {
            prefs.Dashboard ??= new DashboardPreferences();
            prefs.Dashboard.UseMinimalDashboard = DashboardMinimalModeCheck?.IsChecked != false;
            prefs.Dashboard.ShowEmptyDashboardByDefault = DashboardEmptyByDefaultCheck?.IsChecked != false;
            prefs.Dashboard.ShowIncidentsSection = DashboardShowIncidentsCheck?.IsChecked == true;
            prefs.Dashboard.ShowAnomaliesSection = DashboardShowAnomaliesCheck?.IsChecked == true;
            prefs.Dashboard.ShowStatisticsSection = DashboardShowStatisticsCheck?.IsChecked == true;
            prefs.Dashboard.ShowTimelineSection = DashboardShowTimelineCheck?.IsChecked == true;
            prefs.Dashboard.ShowBaselineSection = DashboardShowBaselineCheck?.IsChecked == true;
            prefs.Dashboard.ShowMlSection = DashboardShowMlCheck?.IsChecked == true;
            prefs.Dashboard.ShowRecommendedActionsSection = DashboardShowRecommendedActionsCheck?.IsChecked == true;
            prefs.Dashboard.ShowRawSummarySection = DashboardShowRawSummaryCheck?.IsChecked == true;
            prefs.Dashboard.ShowCiscoSection = DashboardShowCiscoCheck?.IsChecked == true;
            prefs.Dashboard.ShowSinkSection = DashboardShowSinkCheck?.IsChecked == true;
            prefs.Dashboard.ShowForensicsShortcutsSection = DashboardShowForensicsCheck?.IsChecked == true;
            prefs.Dashboard.ShowDemoSection = _demoModeEnabled && DashboardShowDemoCheck?.IsChecked == true;
        }

        private void SensitivityCombo_SelectionChanged(object sender, SelectionChangedEventArgs e)
        {
            // No-op by default (we persist on Save).
            // You can preview thresholds live here if you want.
        }

        private void ApplyApiKey_Click(object sender, RoutedEventArgs e)
        {
            try
            {
                var key = AbuseApiKeyBox?.Password?.Trim();
                if (string.IsNullOrEmpty(key))
                {
                    MessageBox.Show("Please paste a valid AbuseIPDB API key.", "API Key", MessageBoxButton.OK, MessageBoxImage.Warning);
                    return;
                }

                // Session-only override (does not persist to disk; clears cached client)
                _captureService.AbuseIpDbApiKey = key;
                UpdateApiKeyStatus();
                MessageBox.Show("API key applied for this session.", "API Key", MessageBoxButton.OK, MessageBoxImage.Information);
            }
            catch (Exception ex)
            {
                MessageBox.Show($"Failed to apply API key: {ex.Message}", "API Key", MessageBoxButton.OK, MessageBoxImage.Error);
            }
        }

        // ======== Helpers ========

        private void SelectSensitivityInCombo(Sensitivity s)
        {
            int idx = 1;
            switch (s)
            {
                case Sensitivity.Relaxed:
                    idx = 0;
                    break;
                case Sensitivity.Balanced:
                    idx = 1;
                    break;
                case Sensitivity.Aggressive:
                    idx = 2;
                    break;
            }

            if (SensitivityCombo != null)
                SensitivityCombo.SelectedIndex = idx;
        }

        private void UpdateApiKeyStatus()
        {
            if (ApiKeyStatusText == null) return;

            string envKey = Environment.GetEnvironmentVariable("ABUSEIPDB_API_KEY") ?? string.Empty;

            if (!string.IsNullOrWhiteSpace(_captureService.AbuseIpDbApiKey))
            {
                ApiKeyStatusText.Text = "Key status: session override active";
            }
            else if (!string.IsNullOrWhiteSpace(envKey))
            {
                ApiKeyStatusText.Text = "Key status: loaded from .env / environment";
            }
            else
            {
                ApiKeyStatusText.Text = "Key status: not configured";
            }
        }
    }
}
