// File: Views/MainWindow.Settings.cs
// SPDX-License-Identifier: MIT
using System;
using System.Windows;
using System.Windows.Controls;
using Carthago.Models;
using Carthago.Services;
using Carthago.Views;

namespace Carthago
{
    public partial class MainWindow : Window
    {
        // ======== UI Handlers for Settings ========

        // GA UI-94: Settings-only responsive presentation, preserving all preferences and handlers.
        private void ApplySettingsResponsiveLayout(ResponsiveLayoutMode mode, bool narrowKpis)
        {
            var wide = mode == ResponsiveLayoutMode.Wide;
            // GA UI-134: full-width signal policy above two balanced configuration workspaces.
            // Preserve existing controls, bindings and all preference/capture handlers.
            SettingsOpsLeftColumn.Width = new GridLength(wide ? 1.2 : 1, GridUnitType.Star);
            SettingsOpsRightColumn.Width = wide
                ? new GridLength(1, GridUnitType.Star) : new GridLength(0);

            Grid.SetRow(SettingsDetectionGroup, 0);
            Grid.SetColumn(SettingsDetectionGroup, 0);
            Grid.SetColumnSpan(SettingsDetectionGroup, wide ? 2 : 1);
            Grid.SetRow(SettingsCaptureGroup, 1);
            Grid.SetColumn(SettingsCaptureGroup, 0);
            Grid.SetRow(SettingsDashboardGroup, wide ? 1 : 2);
            Grid.SetColumn(SettingsDashboardGroup, wide ? 1 : 0);
            Grid.SetColumnSpan(SettingsDashboardGroup, 1);
            Grid.SetRow(DemoModeGroup, wide ? 2 : 3);
            Grid.SetColumn(DemoModeGroup, 0);
            Grid.SetColumnSpan(DemoModeGroup, wide ? 2 : 1);

            SettingsCaptureGroup.Margin = new Thickness(0, 0, wide ? 16 : 0, 14);
            SettingsDashboardSectionsGrid.Columns = narrowKpis ? 1 : 2;
            // GA UI-131: preserve the two-panel command header on Wide and stack it at smaller widths.
            SettingsHeroPrimaryColumn.Width = wide ? new GridLength(1.65, GridUnitType.Star) : new GridLength(1, GridUnitType.Star);
            SettingsHeroSecondaryColumn.Width = wide ? new GridLength(1, GridUnitType.Star) : new GridLength(0);
            Grid.SetRow(SettingsHeroGuidance, wide ? 0 : 1);
            Grid.SetColumn(SettingsHeroGuidance, wide ? 1 : 0);
            SettingsHeroIntro.Margin = wide ? new Thickness(0, 0, 16, 0) : new Thickness(0, 0, 0, 12);
            SettingsWorkspaceMap.Columns = wide ? 3 : 1;
            SettingsSensitivityProfiles.Columns = wide ? 3 : 1;
            foreach (var profile in SettingsSensitivityProfiles.Children)
            {
                if (profile is Border card)
                    card.Margin = wide ? new Thickness(0, 0, 10, 0) : new Thickness(0, 0, 0, 10);
            }
            foreach (var tile in SettingsWorkspaceMap.Children)
            {
                if (tile is Border border)
                    border.Margin = wide ? new Thickness(0, 0, 10, 0) : new Thickness(0, 0, 0, 10);
            }
            SettingsSensitivityLabelColumn.Width = new GridLength(narrowKpis ? 130 : 160);
            SettingsCaptureLabelColumn.Width = new GridLength(narrowKpis ? 104 : wide ? 160 : 136);
            // GA UI-133: credential actions stack vertically, while filter and masked input fill their column.
            // The existing settings values and session-only credential handler are unchanged.
        }


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
