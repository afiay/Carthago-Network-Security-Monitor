// SPDX-License-Identifier: MIT
// File: Views/MainWindow.Dashboard.cs
using System;
using System.Collections.Generic;
using System.Collections.ObjectModel;
using System.Globalization;
using System.Linq;
using System.Text.Json;
using System.Windows;
using System.Windows.Controls;
using System.Windows.Input;
using System.Windows.Media;
using System.Windows.Threading;
using Carthago.Analytics.Models;
using Carthago.Models;
using Carthago.Services;
using Carthago.Views;

namespace Carthago
{
    public partial class MainWindow
    {
        private readonly ObservableCollection<DashboardWidgetVm> _dashboardWidgets = new();
        private readonly ObservableCollection<SocKpiVm> _dashboardKpis = new();
        private readonly ObservableCollection<SocAnomalyVm> _dashboardAnomalyItems = new();
        private readonly ObservableCollection<SocHostVm> _dashboardHostRows = new();
        private readonly ObservableCollection<SocActionVm> _dashboardActionRows = new();
        private readonly ObservableCollection<string> _dashboardDetailReasons = new();
        private readonly ObservableCollection<string> _dashboardDetailTags = new();
        private readonly ObservableCollection<string> _dashboardDetailRules = new();
        private readonly ObservableCollection<DashboardWidgetDescriptor> _dashboardAvailableWidgets = new();
        private readonly ObservableCollection<StatisticsMetricDescriptor> _dashboardMetricOptions = new();
        private readonly ObservableCollection<DashboardPresetDescriptor> _dashboardAvailablePresets = new();

        private IReadOnlyList<Incident> _dashboardIncidentSnapshot = Array.Empty<Incident>();
        private IReadOnlyList<AnomalySignal> _dashboardAnomalySnapshot = Array.Empty<AnomalySignal>();
        private BaselineStatus _dashboardBaselineStatus = new();
        private readonly DispatcherTimer _dashboardHeaderTimer = new() { Interval = TimeSpan.FromSeconds(5) };
        private readonly DashboardCallbackGate _dashboardCallbackGate = new();
        private bool _dashboardInitialized;
        private bool _syncingAnomalyPreference;
        private bool _syncingDashboardWidgets;
        private string? _selectedDashboardIncidentId;
        private string? _selectedDashboardAnomalyId;
        private Point _dashboardDragStartPoint;
        private string? _dashboardDragWidgetId;

        private void InitializeDashboardExperience()
        {
            if (_dashboardInitialized || !_dashboardCallbackGate.IsOpen)
                return;

            _dashboardInitialized = true;

            EnsureSinkHost();
            DashboardWidgetItemsControl.ItemsSource = _dashboardWidgets;
            DashboardKpiItemsControl.ItemsSource = _dashboardKpis;
            DashboardAnomalyList.ItemsSource = _dashboardAnomalyItems;
            DashboardHostItemsControl.ItemsSource = _dashboardHostRows;
            DashboardActionItemsControl.ItemsSource = _dashboardActionRows;
            DashboardDetailReasonsItems.ItemsSource = _dashboardDetailReasons;
            DashboardDetailTagsItems.ItemsSource = _dashboardDetailTags;
            DashboardDetailRulesItems.ItemsSource = _dashboardDetailRules;
            DashboardWidgetPickerCombo.ItemsSource = _dashboardAvailableWidgets;
            DashboardMetricPickerCombo.ItemsSource = _dashboardMetricOptions;
            DashboardPresetCombo.ItemsSource = _dashboardAvailablePresets;

            ReplaceCollection(_dashboardMetricOptions, StatisticsMetricRegistry.All);

            if (_sinkHost != null)
            {
                var analytics = _sinkHost.Analytics;
                analytics.IncidentCreated += DashboardIncidentChanged;
                analytics.IncidentUpdated += DashboardIncidentChanged;
                analytics.AnomalyObserved += DashboardAnomalyObserved;
                analytics.BaselineStatusChanged += DashboardBaselineChanged;
                analytics.StateReset += DashboardStateReset;
            }

            PreferencesService.PreferencesChanged += DashboardPreferencesChanged;
            DeviceComboBox.SelectionChanged += DeviceComboBox_SelectionChanged;

            _dashboardHeaderTimer.Tick += (_, __) => UpdateMonitoringHeader();
            _dashboardHeaderTimer.Start();

            RefreshDashboardIncidents();
            RefreshDashboardAnomalies();
            RefreshDashboardBaseline();
            ApplyAnomalyPreferenceState(PreferencesService.Current);
            RefreshDashboardCustomizationSources();
            RefreshDashboardLayoutFromPreferences();
            UpdateMonitoringHeader();
        }

        private void DashboardIncidentChanged(Incident incident)
            => Dispatcher.BeginInvoke(new Action(() => _dashboardCallbackGate.RunIfOpen(() =>
            {
                RefreshDashboardIncidents();
                UpdateMonitoringHeader();
            })), DispatcherPriority.Background);

        private void DashboardAnomalyObserved(AnomalySignal anomaly)
            => Dispatcher.BeginInvoke(new Action(() => _dashboardCallbackGate.RunIfOpen(() =>
            {
                RefreshDashboardAnomalies();
                UpdateMonitoringHeader();
            })), DispatcherPriority.Background);

        private void DashboardBaselineChanged(BaselineStatus status)
            => Dispatcher.BeginInvoke(new Action(() => _dashboardCallbackGate.RunIfOpen(() =>
            {
                _dashboardBaselineStatus = status ?? new BaselineStatus();
                RefreshDashboardLayoutFromPreferences();
                UpdateMonitoringHeader();
            })), DispatcherPriority.Background);

        private void DashboardStateReset()
            => Dispatcher.BeginInvoke(new Action(() => _dashboardCallbackGate.RunIfOpen(() =>
            {
                RefreshDashboardIncidents();
                RefreshDashboardAnomalies();
                RefreshDashboardBaseline();
                UpdateMonitoringHeader();
            })), DispatcherPriority.Background);

        private void DashboardPreferencesChanged(AppPreferences prefs)
            => Dispatcher.BeginInvoke(new Action(() => _dashboardCallbackGate.RunIfOpen(() =>
            {
                ApplyAnomalyPreferenceState(prefs);
                RefreshDashboardCustomizationSources();
                RefreshDashboardLayoutFromPreferences();
                UpdateMonitoringHeader();
            })), DispatcherPriority.Background);

        private void ApplyAnomalyPreferenceState(AppPreferences prefs)
        {
            _syncingAnomalyPreference = true;
            try
            {
                var enabled = prefs?.ShowAnomaliesOnly ?? true;
                AnomaliesOnlyToggle.IsChecked = enabled;
                AnomalyModeText.Text = enabled ? "Anomalies only" : "Expanded telemetry";
            }
            finally
            {
                _syncingAnomalyPreference = false;
            }
        }

        private void DeviceComboBox_SelectionChanged(object sender, SelectionChangedEventArgs e)
            => UpdateMonitoringHeader();

        private void RefreshDashboardIncidents()
        {
            if (!_dashboardCallbackGate.IsOpen || _sinkHost == null)
                return;

            _dashboardIncidentSnapshot = _sinkHost.Analytics
                .GetRecentIncidents(150)
                .OrderBy(i => string.Equals(i.Status, "Resolved", StringComparison.OrdinalIgnoreCase) ? 1 : 0)
                .ThenByDescending(i => i.RiskScore)
                .ThenByDescending(i => i.UpdatedUtc)
                .ToArray();

            RefreshDashboardLayoutFromPreferences();
        }

        private void RefreshDashboardAnomalies()
        {
            if (!_dashboardCallbackGate.IsOpen || _sinkHost == null)
                return;

            _dashboardAnomalySnapshot = _sinkHost.Analytics.GetRecentAnomalies(160);
            RefreshDashboardLayoutFromPreferences();
        }

        private void RefreshDashboardBaseline()
        {
            if (!_dashboardCallbackGate.IsOpen || _sinkHost == null)
                return;

            _dashboardBaselineStatus = _sinkHost.Analytics.GetBaselineStatus();
            RefreshDashboardLayoutFromPreferences();
        }

        private void RefreshDashboardCustomizationSources()
        {
            var prefs = PreferencesService.Current.Dashboard ?? new DashboardPreferences();
            ReplaceCollection(_dashboardAvailableWidgets, DashboardWidgetRegistry.GetPickerOptions(_demoModeEnabled, includeAdvanced: true));
            ReplaceCollection(_dashboardAvailablePresets, DashboardPresetService.GetAvailable(_demoModeEnabled));

            if (DashboardWidgetPickerCombo.SelectedItem == null && _dashboardAvailableWidgets.Count > 0)
                DashboardWidgetPickerCombo.SelectedIndex = 0;
            if (DashboardMetricPickerCombo.SelectedItem == null && _dashboardMetricOptions.Count > 0)
                DashboardMetricPickerCombo.SelectedIndex = 0;
            if (DashboardPresetCombo.SelectedItem == null && _dashboardAvailablePresets.Count > 0)
                DashboardPresetCombo.SelectedIndex = 0;
        }

        private void RefreshDashboardLayoutFromPreferences()
        {
            if (!_dashboardCallbackGate.IsOpen || !_dashboardInitialized)
                return;

            var prefs = PreferencesService.Current.Dashboard?.Clone() ?? new DashboardPreferences();
            prefs.Normalize();

            var widgets = prefs.Widgets
                .Where(widget => widget.IsEnabled)
                .Where(widget => DashboardWidgetRegistry.IsAvailable(widget.WidgetType, prefs, _demoModeEnabled))
                .OrderBy(widget => widget.Order)
                .ThenBy(widget => widget.Row)
                .ThenBy(widget => widget.Column)
                .Select(BuildDashboardWidgetVm)
                .ToArray();

            _syncingDashboardWidgets = true;
            try
            {
                ReplaceCollection(_dashboardWidgets, widgets);
            }
            finally
            {
                _syncingDashboardWidgets = false;
            }

            var hasWorkspace = _dashboardWidgets.Count > 0;
            DashboardEmptyStateCard.Visibility = hasWorkspace ? Visibility.Collapsed : Visibility.Visible;
            SocDashboardWorkspace.Visibility = hasWorkspace ? Visibility.Visible : Visibility.Collapsed;
            DashboardWidgetItemsControl.Visibility = hasWorkspace ? Visibility.Visible : Visibility.Collapsed;
            RefreshSocDashboardWorkspace(prefs);
        }

        private DashboardWidgetVm BuildDashboardWidgetVm(DashboardWidgetConfig config)
        {
            var descriptor = DashboardWidgetRegistry.Find(config.WidgetType);
            var context = CreateMetricContext();
            var title = string.IsNullOrWhiteSpace(config.Title) ? descriptor?.DisplayName ?? "Dashboard widget" : config.Title;
            var category = descriptor?.Category ?? "Dashboard";
            var width = Math.Clamp((config.ColumnSpan <= 0 ? descriptor?.DefaultColumnSpan ?? 1 : config.ColumnSpan) * 360.0 + ((config.ColumnSpan <= 1) ? 0 : 12), 340, 760);

            var vm = new DashboardWidgetVm
            {
                Id = config.Id,
                WidgetType = config.WidgetType,
                Title = title,
                Category = category,
                Width = width,
                MinHeight = config.RowSpan > 1 ? 260 : 180,
                MetricOptions = StatisticsMetricRegistry.All,
                TimeWindowOptions = StatisticsTimeWindows.All
            };

            switch (config.WidgetType)
            {
                case DashboardWidgetTypes.StatisticsCard:
                    PopulateStatisticsCard(vm, config, context);
                    break;
                case DashboardWidgetTypes.StatisticsGrid:
                    PopulateStatisticsGrid(vm, context);
                    break;
                case DashboardWidgetTypes.IncidentQueue:
                    PopulateIncidentQueue(vm);
                    break;
                case DashboardWidgetTypes.IncidentSummary:
                    PopulateIncidentSummary(vm);
                    break;
                case DashboardWidgetTypes.AnomalyTimeline:
                    PopulateAnomalyTimeline(vm);
                    break;
                case DashboardWidgetTypes.BaselineStatus:
                    PopulateBaselineStatus(vm);
                    break;
                case DashboardWidgetTypes.MlStatus:
                    PopulateMlStatus(vm);
                    break;
                case DashboardWidgetTypes.HighRiskHosts:
                    PopulateHighRiskHosts(vm);
                    break;
                case DashboardWidgetTypes.ThreatFeedHits:
                    PopulateMetric(vm, "ThreatFeedHits", context);
                    break;
                case DashboardWidgetTypes.RecommendedActions:
                    PopulateRecommendedActions(vm);
                    break;
                case DashboardWidgetTypes.RawForensicsShortcuts:
                    vm.Value = "Advanced views";
                    vm.Subtitle = "Raw data is available without dominating the dashboard.";
                    vm.BodyLines = new[] { "Raw Traffic", "Raw Detections", "Sink Delivery", "Anomalies and Incident Queue" };
                    vm.PrimaryActionText = "Open Raw Traffic";
                    vm.SecondaryActionText = "Raw Detections";
                    break;
                case DashboardWidgetTypes.CiscoStatus:
                    vm.Value = "Cisco tools";
                    vm.Subtitle = "Syslog, discovery, and device workflows stay in the advanced workspace.";
                    vm.BodyLines = new[] { "Open Cisco Tools from the sidebar or this shortcut.", "No Cisco events are forced onto the main dashboard." };
                    vm.PrimaryActionText = "Open Cisco Tools";
                    break;
                case DashboardWidgetTypes.SinkDeliveryStatus:
                    vm.Value = "External delivery";
                    vm.Subtitle = "Review export/sink delivery without crowding the main workspace.";
                    vm.BodyLines = new[] { "Open Sink Delivery for detailed external delivery logs.", "Use Integrations to configure external targets." };
                    vm.PrimaryActionText = "Open Delivery";
                    vm.SecondaryActionText = "Integrations";
                    break;
                case DashboardWidgetTypes.DemoControls:
                    vm.Value = _demoModeEnabled ? "Demo ready" : "Hidden";
                    vm.Subtitle = _demoModeEnabled
                        ? "Generate one correlated compromised-laptop incident for host 192.168.1.44."
                        : "Start with --demo-mode to use developer demo controls.";
                    vm.BodyLines = new[] { "Demo data is labeled and can be cleared without removing real incidents.", "The scenario drives the real analytics pipeline." };
                    vm.PrimaryActionText = "Run demo";
                    vm.SecondaryActionText = "Clear demo";
                    break;
                default:
                    vm.Value = "—";
                    vm.Subtitle = descriptor?.Description ?? "Widget is not available.";
                    break;
            }

            return vm;
        }

        private StatisticsMetricContext CreateMetricContext()
            => new()
            {
                Incidents = _dashboardIncidentSnapshot,
                Anomalies = _dashboardAnomalySnapshot,
                Detections = _alerts.ToArray(),
                BaselineStatus = _dashboardBaselineStatus,
                DemoModeEnabled = _demoModeEnabled,
                NowUtc = DateTime.UtcNow
            };

        private void PopulateStatisticsCard(DashboardWidgetVm vm, DashboardWidgetConfig config, StatisticsMetricContext context)
        {
            config.Settings.TryGetValue("MetricKey", out var metricKey);
            metricKey = string.IsNullOrWhiteSpace(metricKey) ? "ActiveIncidents" : metricKey;
            var metric = StatisticsMetricRegistry.Find(metricKey) ?? StatisticsMetricRegistry.Find("ActiveIncidents")!;

            config.Settings.TryGetValue("TimeWindow", out var timeWindow);
            timeWindow = StatisticsTimeWindows.FindOrDefault(timeWindow, metric.DefaultTimeWindow).Key;
            var value = StatisticsMetricRegistry.Resolve(metric.Key, context, timeWindow);

            vm.ShowMetricPicker = true;
            vm.ShowTimeWindowPicker = true;
            vm.SelectedMetricKey = metric.Key;
            vm.SelectedTimeWindow = timeWindow;
            vm.Title = string.IsNullOrWhiteSpace(config.Title) ? metric.DisplayName : config.Title;
            vm.Category = metric.Category;
            vm.Value = value.Value;
            vm.Subtitle = value.Detail;
            vm.BodyLines = new[] { metric.Description };
        }

        private void PopulateStatisticsGrid(DashboardWidgetVm vm, StatisticsMetricContext context)
        {
            var metricKeys = new[] { "ActiveIncidents", "CriticalIncidents", "NewAnomalies15m", "HighestRiskHost" };
            vm.Value = "Selected metrics";
            vm.Subtitle = "A compact overview without raw tables.";
            vm.BodyLines = metricKeys
                .Select(key =>
                {
                    var metric = StatisticsMetricRegistry.Find(key)!;
                    var value = StatisticsMetricRegistry.Resolve(key, context);
                    return $"{metric.DisplayName}: {value.Value} — {value.Detail}";
                })
                .ToArray();
        }

        private void PopulateMetric(DashboardWidgetVm vm, string metricKey, StatisticsMetricContext context)
        {
            var metric = StatisticsMetricRegistry.Find(metricKey)!;
            var value = StatisticsMetricRegistry.Resolve(metricKey, context);
            vm.Title = metric.DisplayName;
            vm.Category = metric.Category;
            vm.Value = value.Value;
            vm.Subtitle = value.Detail;
            vm.BodyLines = new[] { metric.Description };
        }

        private void PopulateIncidentQueue(DashboardWidgetVm vm)
        {
            var unresolved = ActiveIncidents()
                .OrderByDescending(incident => incident.RiskScore)
                .ThenByDescending(incident => incident.UpdatedUtc)
                .Take(4)
                .ToArray();

            vm.Value = unresolved.Length.ToString(CultureInfo.InvariantCulture);
            vm.Subtitle = unresolved.Length == 0
                ? "No active incidents. Keep monitoring or add anomaly widgets."
                : "Correlated incidents sorted by risk score.";
            vm.BodyLines = unresolved.Length == 0
                ? new[] { "No correlated investigations are currently in queue." }
                : unresolved.Select(incident => $"Risk {incident.RiskScore} • {NormalizeSeverity(incident.Severity)} • {Safe(incident.PrimarySourceIp, "Unknown host")} • {Safe(incident.Title, "Incident")}").ToArray();
            vm.PrimaryActionText = "Open Queue";
        }

        private void PopulateIncidentSummary(DashboardWidgetVm vm)
        {
            var incident = HighestRiskIncident();
            if (incident == null)
            {
                vm.Value = "No incident";
                vm.Subtitle = "Carthago has not correlated a high-priority incident yet.";
                vm.BodyLines = new[] { "When an incident appears, this widget summarizes the affected host, evidence, and risk reasons." };
                return;
            }

            vm.Value = $"Risk {incident.RiskScore}";
            vm.Subtitle = $"{NormalizeSeverity(incident.Severity)} • {Safe(incident.PrimarySourceIp, "Unknown host")} • {Safe(incident.Title, "Incident")}";
            vm.BodyLines = incident.Evidence.Count > 0
                ? incident.Evidence.Take(4).ToArray()
                : incident.RiskReasons.Take(4).DefaultIfEmpty("Evidence is still being assembled.").ToArray();
            vm.PrimaryActionText = "Open Incident";
            _selectedDashboardIncidentId = incident.Id;
        }

        private void PopulateAnomalyTimeline(DashboardWidgetVm vm)
        {
            var anomalies = _dashboardAnomalySnapshot
                .OrderByDescending(anomaly => anomaly.CreatedUtc)
                .Take(6)
                .ToArray();

            vm.Value = anomalies.Length.ToString(CultureInfo.InvariantCulture);
            vm.Subtitle = anomalies.Length == 0
                ? "No recent anomaly signals."
                : "Recent anomaly-first activity.";
            vm.BodyLines = anomalies.Length == 0
                ? new[] { "Baseline learning continues as traffic is observed." }
                : anomalies.Select(anomaly => $"{anomaly.CreatedUtc.ToLocalTime():HH:mm:ss} • {Safe(anomaly.SourceIp, "Unknown host")} • {Safe(anomaly.Title, anomaly.Category)}").ToArray();
            vm.PrimaryActionText = "Open Anomalies";
        }

        private void PopulateBaselineStatus(DashboardWidgetVm vm)
        {
            vm.Value = Safe(_dashboardBaselineStatus.Confidence, "Learning");
            vm.Subtitle = _dashboardBaselineStatus.ObservedHosts == 0
                ? "Waiting for enough host observations."
                : $"{_dashboardBaselineStatus.ObservedHosts} hosts observed.";
            vm.BodyLines = new[]
            {
                $"Learning window: {_dashboardBaselineStatus.LearningWindowMinutes} minutes",
                $"Last update: {FormatTime(_dashboardBaselineStatus.LastUpdatedUtc)}"
            };
        }

        private void PopulateMlStatus(DashboardWidgetVm vm)
        {
            var mlCount = _dashboardAnomalySnapshot.Count(a =>
                Contains(a.Category, "ml") || a.Tags.Any(tag => Contains(tag, "ml")));
            vm.Value = mlCount.ToString(CultureInfo.InvariantCulture);
            vm.Subtitle = "ML-assisted behavior score signals.";
            vm.BodyLines = new[]
            {
                "Deterministic baseline anomalies remain the primary local-first signal.",
                "ML scoring is optional and never required for the minimal dashboard."
            };
        }

        private void PopulateHighRiskHosts(DashboardWidgetVm vm)
        {
            var hosts = ActiveIncidents()
                .Where(i => !string.IsNullOrWhiteSpace(i.PrimarySourceIp))
                .GroupBy(i => i.PrimarySourceIp!)
                .Select(group => new { Host = group.Key, Risk = group.Max(i => i.RiskScore), Count = group.Count() })
                .OrderByDescending(item => item.Risk)
                .Take(4)
                .ToArray();

            vm.Value = hosts.Length == 0 ? "Learning" : hosts[0].Host;
            vm.Subtitle = hosts.Length == 0 ? "No high-risk hosts yet." : $"Highest risk host • Risk {hosts[0].Risk}";
            vm.BodyLines = hosts.Length == 0
                ? new[] { "High-risk hosts appear after incident correlation assigns host-level risk." }
                : hosts.Select(item => $"{item.Host} • Risk {item.Risk} • {item.Count} incident(s)").ToArray();
        }

        private void PopulateRecommendedActions(DashboardWidgetVm vm)
        {
            var incident = HighestRiskIncident();
            if (incident == null)
            {
                vm.Value = "No action";
                vm.Subtitle = "No active incident requires response guidance.";
                vm.BodyLines = new[] { "Recommended actions appear when Carthago correlates an incident." };
                return;
            }

            var actions = incident.RecommendedActions.Count > 0
                ? incident.RecommendedActions.Take(5).ToArray()
                : new[] { "Review supporting telemetry and confirm whether the behavior is expected." };

            vm.Value = "Next steps";
            vm.Subtitle = $"For {Safe(incident.PrimarySourceIp, "the affected host")} • Risk {incident.RiskScore}";
            vm.BodyLines = actions;
            vm.PrimaryActionText = "Open Incident";
            _selectedDashboardIncidentId = incident.Id;
        }

        private IEnumerable<Incident> ActiveIncidents()
            => _dashboardIncidentSnapshot.Where(incident => !string.Equals(incident.Status, "Resolved", StringComparison.OrdinalIgnoreCase));

        private Incident? HighestRiskIncident()
            => ActiveIncidents()
                .OrderByDescending(incident => incident.RiskScore)
                .ThenByDescending(incident => incident.UpdatedUtc)
                .FirstOrDefault();

        private void UpdateCaptureToggleButtonState()
        {
            var isMonitoring = StopButton?.IsEnabled == true;

            StartButton.Content = isMonitoring ? "\u23F8  Pause" : "\u25B6  Start Monitoring";
            StartButton.Width = isMonitoring ? 116 : 164;
            StartButton.Style = (Style)(TryFindResource(isMonitoring ? "SecondaryButton" : "PrimaryButton")
                ?? TryFindResource("PrimaryButton")
                ?? StartButton.Style);

            if (!isMonitoring && DeviceComboBox != null && DeviceComboBox.Items.Count == 0)
                StartButton.IsEnabled = false;
        }

        private void UpdateMonitoringHeader()
        {
            if (!_dashboardCallbackGate.IsOpen)
                return;

            var captureError = _captureService.LastCaptureError;
            var flow = _captureService.GetCaptureFlowSnapshot();
            var sourceHealth = _captureService.GetCaptureSourceHealth();
            var status = !string.IsNullOrWhiteSpace(captureError)
                ? "Error"
                : StopButton.IsEnabled && (flow.State == Carthago.Services.CaptureFlowState.Stalled || flow.Dropped > 0)
                ? "Degraded"
                : _sinkHost == null
                ? "Offline"
                : StopButton.IsEnabled
                    ? "Monitoring"
                    : "Paused";

            UpdateCaptureToggleButtonState();

            CaptureStatusText.Text = status.ToUpperInvariant();

            switch (status)
            {
                case "Error":
                    MonitoringStatusBadge.Background = new SolidColorBrush(Color.FromRgb(65, 24, 33));
                    MonitoringStatusBadge.BorderBrush = Brushes.IndianRed;
                    break;
                case "Degraded":
                    MonitoringStatusBadge.Background = new SolidColorBrush(Color.FromRgb(54, 34, 15));
                    MonitoringStatusBadge.BorderBrush = Brushes.Orange;
                    break;
                case "Monitoring":
                    MonitoringStatusBadge.Background = (Brush)(TryFindResource("StatusMonitoringBgBrush") ?? new SolidColorBrush(Color.FromRgb(22, 49, 33)));
                    MonitoringStatusBadge.BorderBrush = (Brush)(TryFindResource("StatusMonitoringBorderBrush") ?? new SolidColorBrush(Color.FromRgb(34, 197, 94)));
                    break;
                case "Paused":
                    MonitoringStatusBadge.Background = (Brush)(TryFindResource("StatusPausedBgBrush") ?? new SolidColorBrush(Color.FromRgb(54, 34, 15)));
                    MonitoringStatusBadge.BorderBrush = (Brush)(TryFindResource("StatusPausedBorderBrush") ?? new SolidColorBrush(Color.FromRgb(245, 158, 11)));
                    break;
                default:
                    MonitoringStatusBadge.Background = (Brush)(TryFindResource("StatusOfflineBgBrush") ?? new SolidColorBrush(Color.FromRgb(51, 65, 85)));
                    MonitoringStatusBadge.BorderBrush = (Brush)(TryFindResource("StatusOfflineBorderBrush") ?? new SolidColorBrush(Color.FromRgb(100, 116, 139)));
                    break;
            }

            var selectedSource = (DeviceComboBox.SelectedItem as ComboBoxItem)?.Content?.ToString();
            HeaderCaptureSourceText.Text = string.IsNullOrWhiteSpace(selectedSource)
                ? "Source: waiting for selection"
                : $"Source: {selectedSource}";

            var lastAnalysis = _sinkHost?.Analytics.LastAnalysisUtc;
            HeaderLastAnalysisText.Text = status == "Error"
                ? $"Capture failed: {captureError}"
                : status == "Degraded"
                ? flow.State == Carthago.Services.CaptureFlowState.Stalled
                    ? $"Capture health: {flow.Captured} received, {flow.Displayed} displayed — UI delivery stalled"
                    : $"Capture health: {flow.Captured} received, {flow.Displayed} displayed, {flow.Dropped} UI records dropped"
                : status == "Monitoring" && flow.State == Carthago.Services.CaptureFlowState.Idle
                ? "Capture active · waiting for network traffic"
                : status == "Monitoring" && flow.State == Carthago.Services.CaptureFlowState.Starting
                ? "Capture starting · waiting for first events"
                : lastAnalysis.HasValue
                ? $"●  {lastAnalysis.Value.ToLocalTime():yyyy-MM-dd HH:mm:ss}    (Live)"
                : "Last analysis: waiting for traffic";
            HeaderLastAnalysisText.ToolTip = $"{sourceHealth.ToDisplayText()}\nFlow diagnostic: {flow.Reason}";

            if (status == "Monitoring" && sourceHealth.Running)
                HeaderLastAnalysisText.Text += $"\n{sourceHealth.ToDisplayText()}";

            FooterTelemetryStateText.Text = status switch
            {
                "Monitoring" => "On",
                "Paused" => "Paused",
                "Error" => "Error",
                "Degraded" => "Degraded",
                _ => "Offline"
            };
            FooterTelemetryStateText.Foreground = status switch
            {
                "Monitoring" => (Brush)(TryFindResource("OkBrush") ?? Brushes.LimeGreen),
                "Paused" => (Brush)(TryFindResource("WarningBrush") ?? Brushes.Orange),
                "Error" => Brushes.IndianRed,
                "Degraded" => Brushes.Orange,
                _ => (Brush)(TryFindResource("TextMutedBrush") ?? Brushes.LightSlateGray)
            };
            FooterUtcText.Text = $"UTC {DateTime.UtcNow:HH:mm:ss}";

            AnomalyModeText.Text = PreferencesService.Current.ShowAnomaliesOnly
                ? "Anomalies only"
                : "Expanded telemetry";

            AnomalyModeBadge.Background = PreferencesService.Current.ShowAnomaliesOnly
                ? (Brush)(TryFindResource("PillAccentBgBrush") ?? new SolidColorBrush(Color.FromRgb(23, 48, 77)))
                : (Brush)(TryFindResource("PillBgBrush") ?? new SolidColorBrush(Color.FromRgb(55, 48, 92)));
        }

        private void DashboardAddSelectedWidget_Click(object sender, RoutedEventArgs e)
        {
            var selectedDescriptor = DashboardWidgetPickerCombo.SelectedItem as DashboardWidgetDescriptor;
            var selectedMetric = DashboardMetricPickerCombo.SelectedItem as StatisticsMetricDescriptor ?? StatisticsMetricRegistry.Find("ActiveIncidents");

            PreferencesService.Update(prefs =>
            {
                prefs.Dashboard ??= new DashboardPreferences();
                prefs.Dashboard.Normalize();

                if (selectedDescriptor == null)
                {
                    prefs.Dashboard.ShowStatisticsSection = true;
                    selectedDescriptor = DashboardWidgetRegistry.Find(DashboardWidgetTypes.StatisticsCard);
                }

                if (selectedDescriptor == null)
                    return;

                EnableFeatureForWidget(prefs.Dashboard, selectedDescriptor);

                var widget = new DashboardWidgetConfig
                {
                    WidgetType = selectedDescriptor.WidgetType,
                    Title = selectedDescriptor.WidgetType == DashboardWidgetTypes.StatisticsCard
                        ? selectedMetric?.DisplayName ?? selectedDescriptor.DisplayName
                        : selectedDescriptor.DisplayName,
                    ColumnSpan = selectedDescriptor.DefaultColumnSpan,
                    RowSpan = selectedDescriptor.DefaultRowSpan,
                    Order = NextDashboardOrder(prefs.Dashboard),
                    IsEnabled = true
                };

                if (selectedDescriptor.WidgetType == DashboardWidgetTypes.StatisticsCard)
                {
                    widget.Settings["MetricKey"] = selectedMetric?.Key ?? "ActiveIncidents";
                    widget.Settings["TimeWindow"] = selectedMetric?.DefaultTimeWindow ?? "15m";
                }

                prefs.Dashboard.Widgets.Add(widget);
                prefs.Dashboard.ShowEmptyDashboardByDefault = false;
            });
        }

        private void DashboardUseRecommendedLayout_Click(object sender, RoutedEventArgs e)
            => ApplyDashboardPreset(DashboardPresetService.MinimalSecurityOverview);

        private void DashboardApplyPreset_Click(object sender, RoutedEventArgs e)
        {
            var preset = DashboardPresetCombo.SelectedItem as DashboardPresetDescriptor;
            ApplyDashboardPreset(preset?.Id ?? DashboardPresetService.MinimalSecurityOverview);
        }

        private void DashboardResetLayout_Click(object sender, RoutedEventArgs e)
        {
            PreferencesService.Update(prefs => prefs.Dashboard = DashboardPresetService.CreateEmptyMinimal());
        }

        private void DashboardOpenSettings_Click(object sender, RoutedEventArgs e)
            => Nav_Settings_Click(sender, e);

        private void ApplyDashboardPreset(string presetId)
        {
            PreferencesService.Update(prefs => prefs.Dashboard = DashboardPresetService.ApplyPreset(presetId, _demoModeEnabled));
        }

        private static int NextDashboardOrder(DashboardPreferences preferences)
            => preferences.Widgets.Count == 0 ? 0 : preferences.Widgets.Max(widget => widget.Order) + 1;

        private static void EnableFeatureForWidget(DashboardPreferences preferences, DashboardWidgetDescriptor descriptor)
        {
            switch (descriptor.RequiresFeature)
            {
                case "Incidents": preferences.ShowIncidentsSection = true; break;
                case "Anomalies": preferences.ShowAnomaliesSection = true; break;
                case "Statistics": preferences.ShowStatisticsSection = true; break;
                case "Timeline": preferences.ShowTimelineSection = true; break;
                case "Baseline": preferences.ShowBaselineSection = true; break;
                case "Ml": preferences.ShowMlSection = true; break;
                case "RecommendedActions": preferences.ShowRecommendedActionsSection = true; break;
                case "RawSummary": preferences.ShowRawSummarySection = true; preferences.ShowForensicsShortcutsSection = true; break;
                case "Cisco": preferences.ShowCiscoSection = true; break;
                case "Sink": preferences.ShowSinkSection = true; break;
                case "Demo": preferences.ShowDemoSection = true; break;
            }
        }

        private void DashboardWidgetRemove_Click(object sender, RoutedEventArgs e)
        {
            var id = (sender as Button)?.Tag as string;
            if (string.IsNullOrWhiteSpace(id))
                return;

            PreferencesService.Update(prefs =>
            {
                prefs.Dashboard ??= new DashboardPreferences();
                DashboardLayoutService.RemoveWidget(prefs.Dashboard, id);
            });
        }

        private void DashboardWidgetMoveLeft_Click(object sender, RoutedEventArgs e)
            => MoveDashboardWidget((sender as Button)?.Tag as string, -1);

        private void DashboardWidgetMoveRight_Click(object sender, RoutedEventArgs e)
            => MoveDashboardWidget((sender as Button)?.Tag as string, 1);

        private void MoveDashboardWidget(string? id, int delta)
        {
            if (string.IsNullOrWhiteSpace(id) || delta == 0)
                return;

            PreferencesService.Update(prefs =>
            {
                prefs.Dashboard ??= new DashboardPreferences();
                prefs.Dashboard.Normalize();
                DashboardLayoutService.MoveWidget(prefs.Dashboard, id, delta);
            });
        }

        private void DashboardWidgetCard_MouseLeftButtonDown(object sender, MouseButtonEventArgs e)
        {
            _dashboardDragStartPoint = e.GetPosition(null);
            _dashboardDragWidgetId = (sender as FrameworkElement)?.Tag as string;
        }

        private void DashboardWidgetCard_MouseMove(object sender, MouseEventArgs e)
        {
            if (e.LeftButton != MouseButtonState.Pressed || string.IsNullOrWhiteSpace(_dashboardDragWidgetId))
                return;

            var current = e.GetPosition(null);
            if (Math.Abs(current.X - _dashboardDragStartPoint.X) < SystemParameters.MinimumHorizontalDragDistance &&
                Math.Abs(current.Y - _dashboardDragStartPoint.Y) < SystemParameters.MinimumVerticalDragDistance)
                return;

            DragDrop.DoDragDrop((DependencyObject)sender, _dashboardDragWidgetId, DragDropEffects.Move);
        }

        private void DashboardWidgetCard_Drop(object sender, DragEventArgs e)
        {
            var sourceId = e.Data.GetData(typeof(string)) as string;
            var targetId = (sender as FrameworkElement)?.Tag as string;
            if (string.IsNullOrWhiteSpace(sourceId) || string.IsNullOrWhiteSpace(targetId) || string.Equals(sourceId, targetId, StringComparison.OrdinalIgnoreCase))
                return;

            PreferencesService.Update(prefs =>
            {
                prefs.Dashboard ??= new DashboardPreferences();
                prefs.Dashboard.Normalize();
                DashboardLayoutService.MoveWidgetBefore(prefs.Dashboard, sourceId, targetId);
            });
        }

        private void DashboardWidgetMetric_SelectionChanged(object sender, SelectionChangedEventArgs e)
        {
            if (_syncingDashboardWidgets)
                return;

            if (sender is not ComboBox combo || combo.DataContext is not DashboardWidgetVm vm || string.IsNullOrWhiteSpace(vm.Id))
                return;

            var metricKey = combo.SelectedValue as string;
            if (string.IsNullOrWhiteSpace(metricKey))
                return;

            PreferencesService.Update(prefs =>
            {
                prefs.Dashboard ??= new DashboardPreferences();
                var widget = prefs.Dashboard.Widgets.FirstOrDefault(item => string.Equals(item.Id, vm.Id, StringComparison.OrdinalIgnoreCase));
                if (widget == null)
                    return;

                widget.Settings["MetricKey"] = metricKey;
                var metric = StatisticsMetricRegistry.Find(metricKey);
                if (metric != null)
                {
                    widget.Title = metric.DisplayName;
                    widget.Settings.TryGetValue("TimeWindow", out var currentWindow);
                    widget.Settings["TimeWindow"] = StatisticsTimeWindows.FindOrDefault(currentWindow, metric.DefaultTimeWindow).Key;
                }
            });
        }

        private void DashboardWidgetTimeWindow_SelectionChanged(object sender, SelectionChangedEventArgs e)
        {
            if (_syncingDashboardWidgets)
                return;

            if (sender is not ComboBox combo || combo.DataContext is not DashboardWidgetVm vm || string.IsNullOrWhiteSpace(vm.Id))
                return;

            var timeWindow = combo.SelectedValue as string;
            if (string.IsNullOrWhiteSpace(timeWindow))
                return;

            PreferencesService.Update(prefs =>
            {
                prefs.Dashboard ??= new DashboardPreferences();
                var widget = prefs.Dashboard.Widgets.FirstOrDefault(item => string.Equals(item.Id, vm.Id, StringComparison.OrdinalIgnoreCase));
                if (widget == null)
                    return;

                widget.Settings["TimeWindow"] = StatisticsTimeWindows.FindOrDefault(timeWindow).Key;
            });
        }

        private void DashboardWidgetPrimaryAction_Click(object sender, RoutedEventArgs e)
        {
            var vm = FindDashboardWidgetVm((sender as Button)?.Tag as string);
            if (vm == null)
                return;

            switch (vm.WidgetType)
            {
                case DashboardWidgetTypes.IncidentQueue:
                case DashboardWidgetTypes.IncidentSummary:
                case DashboardWidgetTypes.RecommendedActions:
                    OpenSelectedIncidentWorkspace();
                    break;
                case DashboardWidgetTypes.AnomalyTimeline:
                    Nav_Anomalies_Click(sender, e);
                    break;
                case DashboardWidgetTypes.RawForensicsShortcuts:
                    Nav_LiveTraffic_Click(sender, e);
                    break;
                case DashboardWidgetTypes.CiscoStatus:
                    Nav_CiscoTools_Click(sender, e);
                    break;
                case DashboardWidgetTypes.SinkDeliveryStatus:
                    Nav_SinkEvents_Click(sender, e);
                    break;
                case DashboardWidgetTypes.DemoControls:
                    RunDemoIncident_Click(sender, e);
                    break;
            }
        }

        private void DashboardWidgetSecondaryAction_Click(object sender, RoutedEventArgs e)
        {
            var vm = FindDashboardWidgetVm((sender as Button)?.Tag as string);
            if (vm == null)
                return;

            switch (vm.WidgetType)
            {
                case DashboardWidgetTypes.RawForensicsShortcuts:
                    Nav_Alerts_Click(sender, e);
                    break;
                case DashboardWidgetTypes.SinkDeliveryStatus:
                    Nav_Integrations_Click(sender, e);
                    break;
                case DashboardWidgetTypes.DemoControls:
                    ClearDemoData_Click(sender, e);
                    break;
            }
        }

        private DashboardWidgetVm? FindDashboardWidgetVm(string? id)
            => _dashboardWidgets.FirstOrDefault(widget => string.Equals(widget.Id, id, StringComparison.OrdinalIgnoreCase));

        private void OpenSelectedIncidentWorkspace()
        {
            var incidentId = _selectedDashboardIncidentId;
            if (string.IsNullOrWhiteSpace(incidentId))
                incidentId = HighestRiskIncident()?.Id;

            OpenIncidentWorkspace(incidentId);
        }

        private static void ReindexDashboardWidgets(IList<DashboardWidgetConfig> widgets)
            => DashboardLayoutService.NormalizeOrder(widgets);

        private void DashboardCopyIncidentJson_Click(object sender, RoutedEventArgs e)
        {
            var incident = _dashboardIncidentSnapshot.FirstOrDefault(item =>
                string.Equals(item.Id, _selectedDashboardIncidentId, StringComparison.OrdinalIgnoreCase));
            if (incident == null)
                return;

            Clipboard.SetText(JsonSerializer.Serialize(incident, new JsonSerializerOptions { WriteIndented = true }));
        }

        private void AnomaliesOnlyToggle_Changed(object sender, RoutedEventArgs e)
        {
            if (_syncingAnomalyPreference)
                return;

            var enabled = AnomaliesOnlyToggle.IsChecked != false;
            PreferencesService.Update(prefs => prefs.ShowAnomaliesOnly = enabled);
            UpdateMonitoringHeader();
        }

        private static void ReplaceCollection<T>(ObservableCollection<T> target, IEnumerable<T> items)
        {
            target.Clear();
            foreach (var item in items)
                target.Add(item);
        }

        private static string FormatTime(DateTime? utc)
            => utc.HasValue ? utc.Value.ToLocalTime().ToString("HH:mm:ss") : "pending";

        private void RefreshSocDashboardWorkspace(DashboardPreferences prefs)
        {
            prefs ??= new DashboardPreferences();
            prefs.Normalize();

            var context = CreateMetricContext();
            ReplaceCollection(_dashboardKpis, BuildSocKpis(prefs, context));
            ReplaceCollection(_dashboardAnomalyItems, BuildSocAnomalyItems());
            ReplaceCollection(_dashboardHostRows, BuildSocHostRows());
            ReplaceCollection(_dashboardActionRows, BuildSocActionRows());

            if (_dashboardAnomalyItems.Count > 0)
            {
                if (string.IsNullOrWhiteSpace(_selectedDashboardAnomalyId) || !_dashboardAnomalyItems.Any(item => string.Equals(item.Id, _selectedDashboardAnomalyId, StringComparison.OrdinalIgnoreCase)))
                    _selectedDashboardAnomalyId = _dashboardAnomalyItems[0].Id;

                var selected = _dashboardAnomalyItems.FirstOrDefault(item => string.Equals(item.Id, _selectedDashboardAnomalyId, StringComparison.OrdinalIgnoreCase));
                if (selected != null && !Equals(DashboardAnomalyList.SelectedItem, selected))
                    DashboardAnomalyList.SelectedItem = selected;
            }
            else
            {
                _selectedDashboardAnomalyId = null;
                DashboardAnomalyList.SelectedItem = null;
            }

            DashboardAnomalyFooterText.Text = _dashboardAnomalySnapshot.Count == 0
                ? "No anomaly signals yet. Start monitoring or run demo mode."
                : $"Showing 1-{Math.Min(5, _dashboardAnomalySnapshot.Count)} of {_dashboardAnomalySnapshot.Count} anomalies";

            UpdateSocSignalDetails();
        }

        private IEnumerable<SocKpiVm> BuildSocKpis(DashboardPreferences prefs, StatisticsMetricContext context)
        {
            var active = ActiveIncidents().ToArray();
            var now = DateTime.UtcNow;

            if (prefs.ShowIncidentsSection)
            {
                yield return new SocKpiVm
                {
                    Title = "Active Incidents",
                    Value = active.Length.ToString(CultureInfo.InvariantCulture),
                    DeltaText = BuildDeltaText(active.Count(i => i.CreatedUtc >= now.AddMinutes(-15)), "15m"),
                    TrendText = BuildTrendText(active.Select(i => i.CreatedUtc), now, 60),
                    Icon = "!",
                    AccentBrush = BrushForScore(active.Length == 0 ? 0 : active.Max(i => i.RiskScore))
                };

                var highRiskHosts = active.Where(i => !string.IsNullOrWhiteSpace(i.PrimarySourceIp))
                    .GroupBy(i => i.PrimarySourceIp!)
                    .Count(group => group.Max(i => i.RiskScore) >= 50);
                yield return new SocKpiVm
                {
                    Title = "High Risk Hosts",
                    Value = highRiskHosts.ToString(CultureInfo.InvariantCulture),
                    DeltaText = BuildDeltaText(active.Count(i => i.UpdatedUtc >= now.AddMinutes(-15) && i.RiskScore >= 50), "15m"),
                    TrendText = BuildTrendText(active.Where(i => i.RiskScore >= 50).Select(i => i.UpdatedUtc), now, 60),
                    Icon = "⌘",
                    AccentBrush = BrushForScore(highRiskHosts > 0 ? 78 : 0)
                };
            }

            if (prefs.ShowAnomaliesSection)
            {
                var recentAnomalies = _dashboardAnomalySnapshot.Count(a => a.CreatedUtc >= now.AddMinutes(-15));
                var displayedAnomalies = recentAnomalies > 0 ? recentAnomalies : _dashboardAnomalySnapshot.Count;
                yield return new SocKpiVm
                {
                    Title = "New Anomalies (15m)",
                    Value = displayedAnomalies.ToString(CultureInfo.InvariantCulture),
                    DeltaText = recentAnomalies > 0 ? BuildDeltaText(recentAnomalies, "15m") : $"{_dashboardAnomalySnapshot.Count} total",
                    TrendText = BuildTrendText(_dashboardAnomalySnapshot.Select(a => a.CreatedUtc), now, 60),
                    Icon = "✧",
                    AccentBrush = (Brush)(TryFindResource("AccentBrush") ?? Brushes.DeepSkyBlue)
                };
            }

            if (prefs.ShowStatisticsSection)
            {
                var threatHits = _dashboardAnomalySnapshot.Count(IsThreatSignal);
                var recentThreatHits = _dashboardAnomalySnapshot.Count(a => a.CreatedUtc >= now.AddMinutes(-15) && IsThreatSignal(a));
                yield return new SocKpiVm
                {
                    Title = "Threat Feed Hits",
                    Value = (recentThreatHits > 0 ? recentThreatHits : threatHits).ToString(CultureInfo.InvariantCulture),
                    DeltaText = recentThreatHits > 0 ? BuildDeltaText(recentThreatHits, "15m") : $"{threatHits} total",
                    TrendText = BuildTrendText(_dashboardAnomalySnapshot.Where(IsThreatSignal).Select(a => a.CreatedUtc), now, 60),
                    Icon = "◎",
                    AccentBrush = (Brush)(TryFindResource("AccentAltBrush") ?? Brushes.MediumPurple)
                };
            }

            if (prefs.ShowBaselineSection)
            {
                yield return new SocKpiVm
                {
                    Title = "Baseline Confidence",
                    Value = Safe(_dashboardBaselineStatus.Confidence, "Learning"),
                    DeltaText = _dashboardBaselineStatus.ObservedHosts == 0 ? "collecting" : $"{_dashboardBaselineStatus.ObservedHosts} hosts",
                    TrendText = BuildConfidenceBars(_dashboardBaselineStatus.Confidence),
                    Icon = "✓",
                    AccentBrush = BrushForBaseline(_dashboardBaselineStatus.Confidence)
                };
            }
        }

        private IEnumerable<SocAnomalyVm> BuildSocAnomalyItems()
            => _dashboardAnomalySnapshot
                .OrderByDescending(NormalizeAnomalyScore)
                .ThenByDescending(anomaly => anomaly.CreatedUtc)
                .Take(5)
                .Select(anomaly => new SocAnomalyVm
                {
                    Id = anomaly.Id,
                    RiskScore = NormalizeAnomalyScore(anomaly),
                    Title = Safe(anomaly.Title, Safe(anomaly.Category, "Anomaly signal")),
                    Subtitle = BuildAnomalySubtitle(anomaly),
                    Severity = NormalizeSeverity(anomaly.Severity).ToUpperInvariant(),
                    TimeText = anomaly.CreatedUtc.ToLocalTime().ToString("HH:mm:ss", CultureInfo.InvariantCulture),
                    AccentBrush = BrushForSeverity(anomaly.Severity)
                });

        private static string CompactHostLabel(string? value)
        {
            var host = Safe(value, "Unknown host").Trim();
            if (host.Length <= 22)
                return host;

            // Keep the SOC table stable: long IPv6 addresses and reverse-DNS names must
            // never force one-character vertical wrapping. The full value is still kept
            // in the tooltip via SocHostVm.Host.
            if (host.Contains(':', StringComparison.Ordinal))
            {
                var segments = host.Split(':', StringSplitOptions.RemoveEmptyEntries);
                if (segments.Length >= 4)
                    return $"{segments[0]}:{segments[1]}:{segments[2]}…{segments[^1]}";
            }

            if (host.Contains('.', StringComparison.Ordinal))
            {
                var parts = host.Split('.', StringSplitOptions.RemoveEmptyEntries);
                if (parts.Length >= 3)
                    return $"{parts[0]}…{parts[^2]}.{parts[^1]}";
            }

            return $"{host[..12]}…{host[^6..]}";
        }

        private IEnumerable<SocHostVm> BuildSocHostRows()
        {
            var incidentHosts = ActiveIncidents()
                .Where(i => !string.IsNullOrWhiteSpace(i.PrimarySourceIp))
                .GroupBy(i => i.PrimarySourceIp!)
                .Select(group => new SocHostVm
                {
                    Host = group.Key,
                    HostDisplay = CompactHostLabel(group.Key),
                    RiskScore = group.Max(i => i.RiskScore),
                    ActiveIncidents = group.Count(),
                    TrendText = BuildTrendText(group.Select(i => i.UpdatedUtc), DateTime.UtcNow, 60),
                    AccentBrush = BrushForScore(group.Max(i => i.RiskScore))
                })
                .OrderByDescending(item => item.RiskScore)
                .ThenByDescending(item => item.ActiveIncidents)
                .Take(5)
                .ToArray();

            if (incidentHosts.Length > 0)
                return incidentHosts;

            return _dashboardAnomalySnapshot
                .Where(a => !string.IsNullOrWhiteSpace(a.SourceIp))
                .GroupBy(a => a.SourceIp)
                .Select(group => new SocHostVm
                {
                    Host = group.Key,
                    HostDisplay = CompactHostLabel(group.Key),
                    RiskScore = group.Max(NormalizeAnomalyScore),
                    ActiveIncidents = group.Count(),
                    TrendText = BuildTrendText(group.Select(a => a.CreatedUtc), DateTime.UtcNow, 60),
                    AccentBrush = BrushForScore(group.Max(NormalizeAnomalyScore))
                })
                .OrderByDescending(item => item.RiskScore)
                .Take(5)
                .ToArray();
        }

        private IEnumerable<SocActionVm> BuildSocActionRows()
        {
            var incident = HighestRiskIncident();
            if (incident != null)
            {
                var actions = incident.RecommendedActions.Count > 0
                    ? incident.RecommendedActions.Take(4).ToArray()
                    : new[] { "Review supporting telemetry and confirm whether this behavior is expected." };

                var index = 0;
                foreach (var action in actions)
                {
                    index++;
                    yield return new SocActionVm
                    {
                        Icon = index switch { 1 => "⌕", 2 => "▣", 3 => "◇", _ => "›" },
                        Title = action,
                        Subtitle = $"{Safe(incident.PrimarySourceIp, "Affected host")} • Risk {incident.RiskScore}",
                        CountText = index.ToString(CultureInfo.InvariantCulture),
                        AccentBrush = BrushForScore(incident.RiskScore)
                    };
                }

                yield break;
            }

            if (_dashboardAnomalySnapshot.Count > 0)
            {
                var top = _dashboardAnomalySnapshot.OrderByDescending(NormalizeAnomalyScore).First();
                yield return new SocActionVm
                {
                    Icon = "⌕",
                    Title = "Review highest-risk anomaly",
                    Subtitle = BuildAnomalySubtitle(top),
                    CountText = NormalizeAnomalyScore(top).ToString(CultureInfo.InvariantCulture),
                    AccentBrush = BrushForScore(NormalizeAnomalyScore(top))
                };
                yield break;
            }

            yield return new SocActionVm
            {
                Icon = "✓",
                Title = "Continue baseline learning",
                Subtitle = "No correlated incident currently requires action.",
                CountText = "0",
                AccentBrush = (Brush)(TryFindResource("OkBrush") ?? Brushes.LimeGreen)
            };
        }

        private void DashboardAnomalyList_SelectionChanged(object sender, SelectionChangedEventArgs e)
        {
            if (DashboardAnomalyList.SelectedItem is SocAnomalyVm selected)
                _selectedDashboardAnomalyId = selected.Id;
            UpdateSocSignalDetails();
        }

        private void DashboardOpenSignalDetail_Click(object sender, RoutedEventArgs e)
        {
            var detail = CreateDashboardSignalDetailModel();
            var dialog = new DashboardSignalDetailDialog(detail)
            {
                Owner = this
            };

            dialog.ShowDialog();

            switch (dialog.RequestedAction)
            {
                case DashboardSignalDetailDialogAction.OpenIncident:
                    OpenIncidentWorkspace(detail.IncidentId);
                    break;
                case DashboardSignalDetailDialogAction.OpenAnomalies:
                    Nav_Anomalies_Click(sender, e);
                    break;
            }
        }

        private void UpdateSocSignalDetails()
        {
            var detail = CreateDashboardSignalDetailModel();

            _selectedDashboardIncidentId = detail.IncidentId;

            DashboardDetailRiskRing.BorderBrush = detail.RiskBrush;
            DashboardDetailSeverityStripe.BorderBrush = detail.RiskBrush;
            DashboardDetailRiskBadgeText.Foreground = detail.RiskBrush;
            DashboardDetailRiskText.Text = detail.RiskText;
            DashboardDetailRiskBadgeText.Text = detail.RiskLabel;
            DashboardDetailTitleText.Text = detail.Title;
            DashboardDetailSubtitleText.Text = detail.Subtitle;
            DashboardDetailSourceText.Text = detail.Source;
            DashboardDetailDestinationText.Text = detail.Destination;
            DashboardDetailProtocolText.Text = detail.Protocol;
            DashboardDetailCategoryText.Text = detail.Category;
            DashboardDetailDetectedText.Text = detail.Detected;
            DashboardDetailRelatedIncidentText.Text = detail.RelatedIncident;

            ReplaceCollection(_dashboardDetailReasons, detail.Reasons.Take(3).Select(reason => $"- {reason}"));
            ReplaceCollection(_dashboardDetailTags, detail.Tags.Take(5));
            ReplaceCollection(_dashboardDetailRules, detail.Rules.Take(5));

            DashboardInvestigateHostButton.IsEnabled = detail.CanOpenIncident || detail.CanOpenAnomalies;
            DashboardViewRelatedIncidentButton.IsEnabled = detail.CanOpenIncident;
            DashboardOpenSignalDetailButton.IsEnabled = detail.CanOpenIncident || detail.CanOpenAnomalies || detail.RiskText != "—";
        }

        private DashboardSignalDetailDialogModel CreateDashboardSignalDetailModel()
        {
            var selected = string.IsNullOrWhiteSpace(_selectedDashboardAnomalyId)
                ? _dashboardAnomalySnapshot.OrderByDescending(NormalizeAnomalyScore).FirstOrDefault()
                : _dashboardAnomalySnapshot.FirstOrDefault(a => string.Equals(a.Id, _selectedDashboardAnomalyId, StringComparison.OrdinalIgnoreCase));

            var incident = selected != null
                ? FindRelatedIncident(selected)
                : HighestRiskIncident();

            if (selected == null && incident == null)
            {
                var learningBrush = BrushForBaseline(_dashboardBaselineStatus.Confidence);
                return new DashboardSignalDetailDialogModel
                {
                    Title = "No selected signal",
                    Subtitle = "Start monitoring or run demo mode to populate the workspace.",
                    RiskText = "—",
                    RiskLabel = "Learning",
                    RiskBrush = learningBrush,
                    Reasons = new[] { "No anomaly signal has been observed yet." },
                    Tags = new[] { Safe(_dashboardBaselineStatus.Confidence, "Baseline learning") },
                    Rules = new[] { "No linked rules yet." },
                    RecommendedActions = new[] { "Continue monitoring so Carthago can learn the local traffic baseline." }
                };
            }

            if (selected != null)
            {
                var risk = NormalizeAnomalyScore(selected);
                return new DashboardSignalDetailDialogModel
                {
                    Title = Safe(selected.Title, Safe(selected.Category, "Anomaly signal")),
                    Subtitle = Safe(selected.Description, BuildAnomalySubtitle(selected)),
                    Source = Safe(selected.SourceIp, "—"),
                    Destination = Safe(selected.DestinationHost, Safe(selected.DestinationIp, "—")),
                    Protocol = BuildProtocolText(selected),
                    Category = Safe(selected.Category, "—"),
                    Detected = selected.CreatedUtc.ToLocalTime().ToString("yyyy-MM-dd HH:mm:ss", CultureInfo.InvariantCulture),
                    RelatedIncident = incident == null ? "Not correlated yet" : Safe(incident.Title, incident.Id),
                    RiskText = risk.ToString(CultureInfo.InvariantCulture),
                    RiskLabel = RiskBandLabel(risk),
                    RiskBrush = BrushForScore(risk),
                    Reasons = selected.Reasons.Count > 0
                        ? selected.Reasons.Take(8).ToArray()
                        : new[] { "Signal produced by anomaly scoring or rule correlation." },
                    Tags = BuildSignalTags(selected, incident)
                        .DefaultIfEmpty("No tags linked to this signal.")
                        .Take(10)
                        .ToArray(),
                    Rules = selected.RelatedRuleIds
                        .Where(rule => !string.IsNullOrWhiteSpace(rule))
                        .Distinct(StringComparer.OrdinalIgnoreCase)
                        .DefaultIfEmpty("No linked rules.")
                        .Take(12)
                        .ToArray(),
                    RecommendedActions = BuildDashboardSignalActions(selected, incident),
                    IncidentId = incident?.Id,
                    AnomalyId = selected.Id
                };
            }

            var incidentReasons = incident!.RiskReasons.Count > 0
                ? incident.RiskReasons.Take(8).ToArray()
                : incident.Evidence.Take(8).DefaultIfEmpty("Evidence is still being assembled.").ToArray();

            return new DashboardSignalDetailDialogModel
            {
                Title = Safe(incident.Title, "Incident"),
                Subtitle = Safe(incident.Summary, "Highest-risk correlated incident."),
                Source = Safe(incident.PrimarySourceIp, "—"),
                Destination = Safe(incident.PrimaryDestinationHost, Safe(incident.PrimaryDestinationIp, "—")),
                Protocol = incident.RelatedEvents.FirstOrDefault()?.Protocol ?? "—",
                Category = Safe(incident.Category, "—"),
                Detected = incident.LastSeenUtc.ToLocalTime().ToString("yyyy-MM-dd HH:mm:ss", CultureInfo.InvariantCulture),
                RelatedIncident = Safe(incident.Title, incident.Id),
                RiskText = incident.RiskScore.ToString(CultureInfo.InvariantCulture),
                RiskLabel = RiskBandLabel(incident.RiskScore),
                RiskBrush = BrushForScore(incident.RiskScore),
                Reasons = incidentReasons,
                Tags = incident.Tags.Count > 0
                    ? incident.Tags.Take(10).ToArray()
                    : new[] { NormalizeSeverity(incident.Severity), Safe(incident.Category, "Incident") },
                Rules = incident.RelatedEvents
                    .Select(item => item.RuleId)
                    .Where(rule => !string.IsNullOrWhiteSpace(rule))
                    .Distinct(StringComparer.OrdinalIgnoreCase)
                    .DefaultIfEmpty("No linked rules.")
                    .Take(12)
                    .ToArray(),
                RecommendedActions = incident.RecommendedActions.Count > 0
                    ? incident.RecommendedActions.Take(8).ToArray()
                    : new[] { "Review supporting telemetry and confirm whether this behavior is expected." },
                IncidentId = incident.Id,
                AnomalyId = incident.RelatedAnomalies.FirstOrDefault()?.Id
            };
        }

        private IReadOnlyList<string> BuildDashboardSignalActions(AnomalySignal signal, Incident? incident)
        {
            if (incident != null && incident.RecommendedActions.Count > 0)
                return incident.RecommendedActions.Take(8).ToArray();

            return new[]
            {
                $"Review recent telemetry for {Safe(signal.SourceIp, "the source host")}.",
                "Compare the destination and protocol against the local baseline.",
                incident == null
                    ? "Promote the signal to incident triage if the behavior continues or expands."
                    : "Confirm whether related detections support the linked incident."
            };
        }

        private static string RiskBandLabel(int score)
        {
            if (score >= 80)
                return "High";
            if (score >= 50)
                return "Medium";
            if (score > 0)
                return "Low";

            return "Learning";
        }

        private void UpdateSocSignalDetailsLegacy()
        {
            var selected = string.IsNullOrWhiteSpace(_selectedDashboardAnomalyId)
                ? _dashboardAnomalySnapshot.OrderByDescending(NormalizeAnomalyScore).FirstOrDefault()
                : _dashboardAnomalySnapshot.FirstOrDefault(a => string.Equals(a.Id, _selectedDashboardAnomalyId, StringComparison.OrdinalIgnoreCase));

            var incident = FindRelatedIncident(selected) ?? HighestRiskIncident();

            if (selected == null && incident == null)
            {
                var learningBrush = BrushForBaseline(_dashboardBaselineStatus.Confidence);
                DashboardDetailRiskRing.BorderBrush = learningBrush;
                DashboardDetailSeverityStripe.BorderBrush = learningBrush;
                DashboardDetailRiskBadgeText.Foreground = learningBrush;
                DashboardDetailRiskText.Text = "—";
                DashboardDetailRiskBadgeText.Text = "Learning";
                DashboardDetailTitleText.Text = "No selected signal";
                DashboardDetailSubtitleText.Text = "Start monitoring or run demo mode to populate the workspace.";
                DashboardDetailSourceText.Text = "—";
                DashboardDetailDestinationText.Text = "—";
                DashboardDetailProtocolText.Text = "—";
                DashboardDetailCategoryText.Text = "—";
                DashboardDetailDetectedText.Text = "—";
                DashboardDetailRelatedIncidentText.Text = "—";
                ReplaceCollection(_dashboardDetailReasons, new[] { "No anomaly signal has been observed yet." });
                ReplaceCollection(_dashboardDetailTags, Array.Empty<string>());
                ReplaceCollection(_dashboardDetailRules, Array.Empty<string>());
                return;
            }

            var risk = selected != null ? NormalizeAnomalyScore(selected) : incident?.RiskScore ?? 0;
            var riskBrush = BrushForScore(risk);
            DashboardDetailRiskRing.BorderBrush = riskBrush;
            DashboardDetailSeverityStripe.BorderBrush = riskBrush;
            DashboardDetailRiskBadgeText.Foreground = riskBrush;
            DashboardDetailRiskText.Text = risk.ToString(CultureInfo.InvariantCulture);
            DashboardDetailRiskBadgeText.Text = risk >= 80 ? "High" : risk >= 50 ? "Medium" : "Low";

            if (selected != null)
            {
                DashboardDetailTitleText.Text = Safe(selected.Title, Safe(selected.Category, "Anomaly signal"));
                DashboardDetailSubtitleText.Text = Safe(selected.Description, BuildAnomalySubtitle(selected));
                DashboardDetailSourceText.Text = Safe(selected.SourceIp, "—");
                DashboardDetailDestinationText.Text = Safe(selected.DestinationHost, Safe(selected.DestinationIp, "—"));
                DashboardDetailProtocolText.Text = BuildProtocolText(selected);
                DashboardDetailCategoryText.Text = Safe(selected.Category, "—");
                DashboardDetailDetectedText.Text = selected.CreatedUtc.ToLocalTime().ToString("yyyy-MM-dd HH:mm:ss", CultureInfo.InvariantCulture);
                DashboardDetailRelatedIncidentText.Text = incident == null ? "Not correlated yet" : Safe(incident.Title, incident.Id);

                var reasons = selected.Reasons.Count > 0
                    ? selected.Reasons.Select(reason => "• " + reason).Take(5).ToArray()
                    : new[] { "• Signal produced by anomaly scoring or rule correlation." };
                ReplaceCollection(_dashboardDetailReasons, reasons);
                ReplaceCollection(_dashboardDetailTags, BuildSignalTags(selected, incident));
                ReplaceCollection(_dashboardDetailRules, selected.RelatedRuleIds.Count > 0 ? selected.RelatedRuleIds.Take(8) : new[] { "No linked rule" });
            }
            else if (incident != null)
            {
                DashboardDetailTitleText.Text = Safe(incident.Title, "Incident");
                DashboardDetailSubtitleText.Text = Safe(incident.Summary, "Highest-risk correlated incident.");
                DashboardDetailSourceText.Text = Safe(incident.PrimarySourceIp, "—");
                DashboardDetailDestinationText.Text = Safe(incident.PrimaryDestinationHost, Safe(incident.PrimaryDestinationIp, "—"));
                DashboardDetailProtocolText.Text = incident.RelatedEvents.FirstOrDefault()?.Protocol ?? "—";
                DashboardDetailCategoryText.Text = Safe(incident.Category, "—");
                DashboardDetailDetectedText.Text = incident.LastSeenUtc.ToLocalTime().ToString("yyyy-MM-dd HH:mm:ss", CultureInfo.InvariantCulture);
                DashboardDetailRelatedIncidentText.Text = Safe(incident.Title, incident.Id);
                ReplaceCollection(_dashboardDetailReasons, incident.RiskReasons.Count > 0 ? incident.RiskReasons.Select(reason => "• " + reason).Take(5) : incident.Evidence.Select(e => "• " + e).Take(5));
                ReplaceCollection(_dashboardDetailTags, incident.Tags.Count > 0 ? incident.Tags.Take(8) : new[] { NormalizeSeverity(incident.Severity), Safe(incident.Category, "Incident") });
                ReplaceCollection(_dashboardDetailRules, incident.RelatedEvents.Select(e => e.RuleId).Where(r => !string.IsNullOrWhiteSpace(r)).Distinct().Take(8).DefaultIfEmpty("No linked rule"));
            }
        }

        private Incident? FindRelatedIncident(AnomalySignal? signal)
        {
            if (signal == null)
                return null;

            return ActiveIncidents()
                .Where(incident => incident.RelatedAnomalies.Any(anomaly => string.Equals(anomaly.Id, signal.Id, StringComparison.OrdinalIgnoreCase))
                                   || (!string.IsNullOrWhiteSpace(signal.SourceIp) && string.Equals(incident.PrimarySourceIp, signal.SourceIp, StringComparison.OrdinalIgnoreCase)))
                .OrderByDescending(incident => incident.RiskScore)
                .ThenByDescending(incident => incident.UpdatedUtc)
                .FirstOrDefault();
        }

        private IEnumerable<string> BuildSignalTags(AnomalySignal signal, Incident? incident)
        {
            var tags = new List<string>();
            if (!string.IsNullOrWhiteSpace(signal.Category)) tags.Add(signal.Category);
            if (!string.IsNullOrWhiteSpace(signal.Protocol)) tags.Add(signal.Protocol);
            if (!string.IsNullOrWhiteSpace(signal.Severity)) tags.Add(NormalizeSeverity(signal.Severity));
            tags.AddRange(signal.Tags.Where(tag => !string.IsNullOrWhiteSpace(tag)));
            if (incident != null && !string.IsNullOrWhiteSpace(incident.Status)) tags.Add(incident.Status);
            return tags.Distinct(StringComparer.OrdinalIgnoreCase).Take(8);
        }

        private string BuildAnomalySubtitle(AnomalySignal signal)
        {
            var flow = BuildProtocolText(signal);
            var destination = Safe(signal.DestinationHost, Safe(signal.DestinationIp, "unknown destination"));
            return $"{Safe(signal.Category, "Anomaly")} • {flow} • {Safe(signal.SourceIp, "unknown host")} → {destination}";
        }

        private static string BuildProtocolText(AnomalySignal signal)
        {
            var protocol = Safe(signal.Protocol, "unknown");
            return string.IsNullOrWhiteSpace(signal.DestinationPort) ? protocol : $"{protocol} / {signal.DestinationPort}";
        }

        private static int NormalizeAnomalyScore(AnomalySignal signal)
        {
            if (signal == null || double.IsNaN(signal.Score) || double.IsInfinity(signal.Score))
                return 0;

            var score = signal.Score <= 1.0 ? signal.Score * 100.0 : signal.Score;
            return Math.Clamp((int)Math.Round(score), 0, 100);
        }

        private bool IsThreatSignal(AnomalySignal signal)
            => Contains(signal.Category, "Threat")
               || Contains(signal.Category, "Reputation")
               || signal.Tags.Any(tag => Contains(tag, "threat") || Contains(tag, "ioc") || Contains(tag, "reputation"))
               || signal.RelatedRuleIds.Any(rule => string.Equals(rule, "R003", StringComparison.OrdinalIgnoreCase)
                                                 || string.Equals(rule, "R016", StringComparison.OrdinalIgnoreCase));

        private string BuildDeltaText(int count, string window)
            => count <= 0 ? $"0 vs {window} ago" : $"↑ {count} vs {window} ago";

        private static string BuildTrendText(IEnumerable<DateTime> timestamps, DateTime nowUtc, int windowMinutes)
        {
            const int buckets = 8;
            var counts = new int[buckets];
            var start = nowUtc.AddMinutes(-windowMinutes);
            var bucketMinutes = Math.Max(1.0, windowMinutes / (double)buckets);

            foreach (var timestamp in timestamps)
            {
                if (timestamp < start || timestamp > nowUtc.AddMinutes(1))
                    continue;

                var index = (int)Math.Floor((timestamp - start).TotalMinutes / bucketMinutes);
                index = Math.Clamp(index, 0, buckets - 1);
                counts[index]++;
            }

            var max = counts.Max();
            if (max <= 0)
                return "▁▁▁▁▁▁▁▁";

            var chars = new[] { '▁', '▂', '▃', '▄', '▅', '▆', '▇', '█' };
            return new string(counts.Select(count => chars[Math.Clamp((int)Math.Round((count / (double)max) * (chars.Length - 1)), 0, chars.Length - 1)]).ToArray());
        }

        private static string BuildConfidenceBars(string? confidence)
        {
            if (Contains(confidence, "high")) return "▰▰▰▰▰";
            if (Contains(confidence, "medium")) return "▰▰▰▱▱";
            if (Contains(confidence, "low")) return "▰▰▱▱▱";
            return "▰▱▱▱▱";
        }

        private Brush BrushForSeverity(string? severity)
        {
            if (Contains(severity, "critical")) return (Brush)(TryFindResource("SeverityCriticalBrush") ?? Brushes.Red);
            if (Contains(severity, "high")) return (Brush)(TryFindResource("SeverityHighBrush") ?? Brushes.OrangeRed);
            if (Contains(severity, "medium")) return (Brush)(TryFindResource("SeverityMediumBrush") ?? Brushes.Orange);
            if (Contains(severity, "low")) return (Brush)(TryFindResource("SeverityLowBrush") ?? Brushes.LimeGreen);
            return (Brush)(TryFindResource("SeverityUnknownBrush") ?? Brushes.LightSlateGray);
        }

        private Brush BrushForScore(int score)
        {
            if (score >= 85) return (Brush)(TryFindResource("SeverityCriticalBrush") ?? Brushes.Red);
            if (score >= 65) return (Brush)(TryFindResource("SeverityHighBrush") ?? Brushes.OrangeRed);
            if (score >= 40) return (Brush)(TryFindResource("SeverityMediumBrush") ?? Brushes.Orange);
            return (Brush)(TryFindResource("SeverityLowBrush") ?? Brushes.LimeGreen);
        }

        private Brush BrushForBaseline(string? confidence)
        {
            if (Contains(confidence, "high")) return (Brush)(TryFindResource("OkBrush") ?? Brushes.LimeGreen);
            if (Contains(confidence, "medium")) return (Brush)(TryFindResource("WarningBrush") ?? Brushes.Orange);
            return (Brush)(TryFindResource("TextMutedBrush") ?? Brushes.LightSlateGray);
        }

        private void DashboardInvestigateHost_Click(object sender, RoutedEventArgs e)
        {
            if (!string.IsNullOrWhiteSpace(_selectedDashboardIncidentId))
            {
                OpenSelectedIncidentWorkspace();
                return;
            }

            Nav_Anomalies_Click(sender, e);
        }

        private void DashboardViewRelatedIncident_Click(object sender, RoutedEventArgs e)
        {
            if (string.IsNullOrWhiteSpace(_selectedDashboardIncidentId))
                return;

            OpenSelectedIncidentWorkspace();
        }

        private void DashboardRawTraffic_Click(object sender, RoutedEventArgs e)
            => Nav_LiveTraffic_Click(sender, e);

        private void DashboardRawDetections_Click(object sender, RoutedEventArgs e)
            => Nav_Alerts_Click(sender, e);

        private void DashboardPcapExplorer_Click(object sender, RoutedEventArgs e)
            => Nav_LiveTraffic_Click(sender, e);

        private void DashboardForensicsWorkspace_Click(object sender, RoutedEventArgs e)
            => Nav_Alerts_Click(sender, e);

        private void CleanupDashboardExperience()
        {
            _dashboardCallbackGate.Close();
            PreferencesService.PreferencesChanged -= DashboardPreferencesChanged;
            DeviceComboBox.SelectionChanged -= DeviceComboBox_SelectionChanged;
            _dashboardHeaderTimer.Stop();

            if (_sinkHost != null)
            {
                var analytics = _sinkHost.Analytics;
                analytics.IncidentCreated -= DashboardIncidentChanged;
                analytics.IncidentUpdated -= DashboardIncidentChanged;
                analytics.AnomalyObserved -= DashboardAnomalyObserved;
                analytics.BaselineStatusChanged -= DashboardBaselineChanged;
                analytics.StateReset -= DashboardStateReset;
            }
        }

        private bool SelectDashboardIncident(string? incidentId)
        {
            if (string.IsNullOrWhiteSpace(incidentId))
                return false;

            _selectedDashboardIncidentId = incidentId;
            var exists = _dashboardIncidentSnapshot.Any(item => string.Equals(item.Id, incidentId, StringComparison.OrdinalIgnoreCase));
            RefreshDashboardLayoutFromPreferences();
            return exists;
        }

        private static string NormalizeSeverity(string? severity)
        {
            if (string.IsNullOrWhiteSpace(severity))
                return "Low";
            return char.ToUpperInvariant(severity[0]) + severity[1..].ToLowerInvariant();
        }

        private static string Safe(string? value, string fallback)
            => string.IsNullOrWhiteSpace(value) ? fallback : value;

        private static bool Contains(string? value, string needle)
            => !string.IsNullOrWhiteSpace(value) && value.IndexOf(needle, StringComparison.OrdinalIgnoreCase) >= 0;

        private sealed class SocKpiVm
        {
            public string Title { get; init; } = "";
            public string Value { get; init; } = "—";
            public string DeltaText { get; init; } = "";
            public string TrendText { get; init; } = "▁▁▁▁▁▁▁▁";
            public string Icon { get; init; } = "•";
            public Brush AccentBrush { get; init; } = Brushes.DeepSkyBlue;
        }

        private sealed class SocAnomalyVm
        {
            public string Id { get; init; } = "";
            public int RiskScore { get; init; }
            public string Title { get; init; } = "";
            public string Subtitle { get; init; } = "";
            public string Severity { get; init; } = "MEDIUM";
            public string TimeText { get; init; } = "";
            public Brush AccentBrush { get; init; } = Brushes.Orange;
        }

        private sealed class SocHostVm
        {
            public string Host { get; init; } = "—";
            public string HostDisplay { get; init; } = "—";
            public int RiskScore { get; init; }
            public int ActiveIncidents { get; init; }
            public string TrendText { get; init; } = "▁▁▁▁▁▁▁▁";
            public Brush AccentBrush { get; init; } = Brushes.Orange;
        }

        private sealed class SocActionVm
        {
            public string Icon { get; init; } = "›";
            public string Title { get; init; } = "";
            public string Subtitle { get; init; } = "";
            public string CountText { get; init; } = "";
            public Brush AccentBrush { get; init; } = Brushes.DeepSkyBlue;
        }

        private sealed class DashboardWidgetVm
        {
            public string Id { get; init; } = "";
            public string WidgetType { get; init; } = "";
            public string Title { get; set; } = "";
            public string Category { get; set; } = "";
            public string Value { get; set; } = "—";
            public string Subtitle { get; set; } = "";
            public IReadOnlyList<string> BodyLines { get; set; } = Array.Empty<string>();
            public double Width { get; init; } = 360;
            public double MinHeight { get; init; } = 180;
            public bool ShowMetricPicker { get; set; }
            public bool ShowTimeWindowPicker { get; set; }
            public string SelectedMetricKey { get; set; } = "ActiveIncidents";
            public string SelectedTimeWindow { get; set; } = "15m";
            public IReadOnlyList<StatisticsMetricDescriptor> MetricOptions { get; set; } = Array.Empty<StatisticsMetricDescriptor>();
            public IReadOnlyList<StatisticsTimeWindowOption> TimeWindowOptions { get; set; } = Array.Empty<StatisticsTimeWindowOption>();
            public string PrimaryActionText { get; set; } = "";
            public string SecondaryActionText { get; set; } = "";
            public bool HasPrimaryAction => !string.IsNullOrWhiteSpace(PrimaryActionText);
            public bool HasSecondaryAction => !string.IsNullOrWhiteSpace(SecondaryActionText);
        }
    }
}
