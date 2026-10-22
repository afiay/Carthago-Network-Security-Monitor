// File: Views/MainWindow.Core.cs
using System;
using System.Collections.Generic;
using System.Collections.ObjectModel;
using System.Linq;
using System.Threading.Tasks;
using System.Windows;
using System.Windows.Controls;
using Carthago.Models;
using Carthago.Services;

namespace Carthago
{
    public partial class MainWindow : Window
    {
        // ===== Data collections =====
        private readonly ObservableCollection<TrafficRecord> _traffic = new();
        private readonly ObservableCollection<DetectionEvent> _alerts = new();

        // ===== Services (assigned in MainWindow.xaml.cs ctor) =====
        private readonly TrafficCaptureService _captureService;
        private readonly BlacklistService _blacklistService;

        // ===== Timers / Counters =====
        private readonly System.Windows.Threading.DispatcherTimer _ppsTimer =
            new() { Interval = TimeSpan.FromSeconds(1) };
        private bool _startupAutoCaptureQueued;
        private bool _syncingSettingsUi;

        private int _ppsBucket = 0;
        private long _bytesBucket = 0;
        private const int TrafficWindowSeconds = 120;

        // rolling data for "Traffic over time"
        private readonly List<double> _trafficXs = new();
        private readonly List<double> _trafficYs = new();

        // protocol / talkers / severity
        private readonly Dictionary<string, int> _protocolCounts = new(StringComparer.OrdinalIgnoreCase);
        private readonly Dictionary<string, int> _talkerCounts = new();
        private readonly Dictionary<string, int> _severityCounts = new()
        {
            ["Info"] = 0,
            ["Low"] = 0,
            ["Medium"] = 0,
            ["High"] = 0,
            ["Critical"] = 0
        };

        // KPI state
        private readonly List<double> _ppsSeries = new();
        private readonly List<double> _mbpsSeries = new();
        private const int KpiWindowPoints = 120;

        private readonly Dictionary<string, DateTime> _hostLastSeen = new();
        private readonly Dictionary<string, DateTime> _connLastSeen = new(); // key: "src>dst:port"
        private readonly TimeSpan ActiveWindow = TimeSpan.FromMinutes(2);

        // === This replaces the old constructor body ===
        partial void AfterInitialize()
        {
            // Reflect persisted preferences in the operator UI/runtime
            try
            {
                PreferencesService.PreferencesChanged += MainWindowPreferencesChanged;
                ApplyRuntimePreferences(PreferencesService.Current, applyActiveCaptureFilter: false);
            }
            catch
            {
                // ignore
            }

            // Hook capture service events
            _captureService.TrafficRecordReceived += CaptureService_TrafficRecordReceived;
            _captureService.DetectionEventRaised += CaptureService_DetectionEventRaised;

            // Bind grids
            TrafficGrid.ItemsSource = _traffic;
            AlertsGrid.ItemsSource = _alerts;

             // Populate UI & plots
             LoadDevices();       // wrapper defined below
             InitAllPlots();
             UpdateApiKeyStatus();
             InitializeDashboardExperience();
             InitializeDemoMode();
             QueueAutoStartCaptureIfConfigured();

             // PPS / throughput ticker
             _ppsTimer.Tick += (_, __) =>
            {
                double x = DateTime.Now.ToOADate();
                _trafficXs.Add(x);
                _trafficYs.Add(_ppsBucket);

                _ppsSeries.Add(_ppsBucket);
                double mbps = (_bytesBucket * 8.0) / 1_000_000.0;
                _mbpsSeries.Add(mbps);

                _ppsBucket = 0;
                _bytesBucket = 0;

                TrimSeries(_ppsSeries, KpiWindowPoints);
                TrimSeries(_mbpsSeries, KpiWindowPoints);

                while (_trafficXs.Count > TrafficWindowSeconds)
                {
                    _trafficXs.RemoveAt(0);
                    _trafficYs.RemoveAt(0);
                }

                DateTime cutoff = DateTime.UtcNow - ActiveWindow;
                foreach (var key in _hostLastSeen.Where(kv => kv.Value < cutoff).Select(kv => kv.Key).ToList())
                    _hostLastSeen.Remove(key);
                foreach (var key in _connLastSeen.Where(kv => kv.Value < cutoff).Select(kv => kv.Key).ToList())
                    _connLastSeen.Remove(key);

                RenderTraffic();
                UpdateKpis();
            };
            _ppsTimer.Start();
        }

        private void MainWindowPreferencesChanged(AppPreferences prefs)
        {
            Dispatcher.BeginInvoke(new Action(() =>
                ApplyRuntimePreferences(prefs, applyActiveCaptureFilter: false)));
        }

        private void ApplyRuntimePreferences(AppPreferences prefs, bool applyActiveCaptureFilter)
        {
            ApplyPrefsToSettingsUi(prefs);
            _captureService.SetDefaultFilter(prefs.DefaultCaptureFilter);

            if (applyActiveCaptureFilter && StopButton?.IsEnabled == true && IsNpcapSelection())
                _captureService.ApplyFilter(prefs.DefaultCaptureFilter);
        }

        private void ApplyPrefsToSettingsUi(AppPreferences? prefs = null)
        {
            _syncingSettingsUi = true;
            try
            {
                prefs ??= PreferencesService.Current;

                // 0=Relaxed,1=Balanced,2=Aggressive
                var idx = prefs.Sensitivity switch
                {
                    Sensitivity.Relaxed => 0,
                    Sensitivity.Aggressive => 2,
                    _ => 1
                };
                if (SensitivityCombo != null)
                    SensitivityCombo.SelectedIndex = idx;
                if (AutoStartCheck != null)
                    AutoStartCheck.IsChecked = prefs.AutoStartCapture;
                if (EnableWhoisCheck != null)
                    EnableWhoisCheck.IsChecked = prefs.EnableWhois;
                if (EnableRepCheck != null)
                    EnableRepCheck.IsChecked = prefs.EnableReputation;
                if (DefaultFilterText != null)
                    DefaultFilterText.Text = prefs.DefaultCaptureFilter ?? string.Empty;

                var dashboard = prefs.Dashboard ?? new DashboardPreferences();
                if (DashboardMinimalModeCheck != null)
                    DashboardMinimalModeCheck.IsChecked = dashboard.UseMinimalDashboard;
                if (DashboardEmptyByDefaultCheck != null)
                    DashboardEmptyByDefaultCheck.IsChecked = dashboard.ShowEmptyDashboardByDefault;
                if (DashboardShowIncidentsCheck != null)
                    DashboardShowIncidentsCheck.IsChecked = dashboard.ShowIncidentsSection;
                if (DashboardShowAnomaliesCheck != null)
                    DashboardShowAnomaliesCheck.IsChecked = dashboard.ShowAnomaliesSection;
                if (DashboardShowStatisticsCheck != null)
                    DashboardShowStatisticsCheck.IsChecked = dashboard.ShowStatisticsSection;
                if (DashboardShowTimelineCheck != null)
                    DashboardShowTimelineCheck.IsChecked = dashboard.ShowTimelineSection;
                if (DashboardShowBaselineCheck != null)
                    DashboardShowBaselineCheck.IsChecked = dashboard.ShowBaselineSection;
                if (DashboardShowMlCheck != null)
                    DashboardShowMlCheck.IsChecked = dashboard.ShowMlSection;
                if (DashboardShowRecommendedActionsCheck != null)
                    DashboardShowRecommendedActionsCheck.IsChecked = dashboard.ShowRecommendedActionsSection;
                if (DashboardShowRawSummaryCheck != null)
                    DashboardShowRawSummaryCheck.IsChecked = dashboard.ShowRawSummarySection;
                if (DashboardShowCiscoCheck != null)
                    DashboardShowCiscoCheck.IsChecked = dashboard.ShowCiscoSection;
                if (DashboardShowSinkCheck != null)
                    DashboardShowSinkCheck.IsChecked = dashboard.ShowSinkSection;
                if (DashboardShowForensicsCheck != null)
                    DashboardShowForensicsCheck.IsChecked = dashboard.ShowForensicsShortcutsSection;
                if (DashboardShowDemoCheck != null)
                {
                    DashboardShowDemoCheck.IsEnabled = _demoModeEnabled;
                    DashboardShowDemoCheck.IsChecked = _demoModeEnabled && dashboard.ShowDemoSection;
                }
            }
            finally
            {
                _syncingSettingsUi = false;
            }
        }

        private void QueueAutoStartCaptureIfConfigured()
        {
            if (_startupAutoCaptureQueued || !PreferencesService.Current.AutoStartCapture)
                return;

            _startupAutoCaptureQueued = true;
            Dispatcher.BeginInvoke(new Action(() =>
            {
                try
                {
                    if (DeviceComboBox?.Items.Count > 0 && StartButton?.IsEnabled == true)
                    {
                        _captureService.StartCapture(DeviceComboBox, StartButton, StopButton);
                        StartButton.IsEnabled = true;
                        UpdateCaptureToggleButtonState();
                        UpdateMonitoringHeader();
                    }
                }
                catch (Exception ex)
                {
                    Console.Error.WriteLine($"Auto-start capture failed: {ex.Message}");
                }
            }), System.Windows.Threading.DispatcherPriority.Background);
        }

        private bool IsNpcapSelection()
        {
            var selectedSource = (DeviceComboBox?.SelectedItem as ComboBoxItem)?.Content?.ToString();
            return !string.IsNullOrWhiteSpace(selectedSource)
                   && selectedSource.StartsWith("Npcap:", StringComparison.OrdinalIgnoreCase);
        }

        private static void TrimSeries(List<double> series, int max)
        {
            while (series.Count > max) series.RemoveAt(0);
        }

        private static string FormatThroughput(double mbps)
        {
            if (mbps >= 1000) return $"{mbps / 1000.0:0.##} Gbps";
            if (mbps >= 1) return $"{mbps:0.##} Mbps";
            if (mbps >= 0.001) return $"{mbps * 1000.0:0.#} kbps";
            return $"{mbps * 1_000_000.0:0} bps";
        }

        private static DateTime ParseIso(string? s) =>
            DateTime.TryParse(s, out var dt) ? DateTime.SpecifyKind(dt, DateTimeKind.Utc) : DateTime.UtcNow;

        private (string name, long bytes) GetTopProcess2Min()
        {
            DateTime cutoff = DateTime.UtcNow - ActiveWindow;

            var byProc = _traffic
                .Where(r => ParseIso(r.Timestamp) >= cutoff && !string.IsNullOrWhiteSpace(r.ProcessName))
                .GroupBy(r => r.ProcessName ?? "Unknown")
                .Select(g => new { Name = g.Key, Bytes = (long)g.Sum(x => Math.Max(0, x.Length)) })
                .OrderByDescending(x => x.Bytes)
                .FirstOrDefault();

            return byProc == null ? ("N/A", 0) : (byProc.Name ?? "Unknown", byProc.Bytes);
        }

        private void UpdateKpis()
        {
            double ppsNow = _ppsSeries.LastOrDefault();
            PpsValueText.Text = $"{ppsNow:0}";

            double mbpsNow = _mbpsSeries.LastOrDefault();
            ThroughputValueText.Text = FormatThroughput(mbpsNow);

            ActiveHostsText.Text = _hostLastSeen.Count.ToString();
            ActiveConnsText.Text = _connLastSeen.Count.ToString();

            var (pname, pbytes) = GetTopProcess2Min();
            TopProcessText.Text = pname.Equals("N/A", StringComparison.OrdinalIgnoreCase)
                ? "N/A"
                : $"{pname} ({(pbytes / 1_000_000.0):0.##} MB)";

            DateTime cutoff60 = DateTime.UtcNow.AddSeconds(-60);
            var recent = _alerts.Where(a => a.Timestamp >= cutoff60).ToList();
            int cnt = recent.Count;
            int hi = recent.Count(a => a.Severity.ToString().Equals("High", StringComparison.OrdinalIgnoreCase));
            int crit = recent.Count(a => a.Severity.ToString().Equals("Critical", StringComparison.OrdinalIgnoreCase));
            Alerts60sText.Text = cnt == 0 ? "0" : $"{cnt}  (C:{crit}  H:{hi})";

            RenderSpark(PpsSpark, _ppsSeries);
            RenderSpark(ThroughputSpark, _mbpsSeries);
        }

        protected override void OnClosed(EventArgs e)
        {
            base.OnClosed(e);
            PreferencesService.PreferencesChanged -= MainWindowPreferencesChanged;
            CleanupDashboardExperience();
            _captureService.Dispose();
            _ppsTimer?.Stop();
            _dashboardHeaderTimer?.Stop();
        }

        // ===== Added to replace deleted handlers from MainWindow.Commands.cs =====

        // Wrapper used by AfterInitialize()
        private void LoadDevices()
        {
            try
            {
                _captureService.LoadDevices(DeviceComboBox, StartButton);
                UpdateCaptureToggleButtonState();
            }
            catch (Exception ex)
            {
                MessageBox.Show($"Failed to enumerate capture devices:\n{ex.Message}", "Carthago",
                    MessageBoxButton.OK, MessageBoxImage.Error);
            }
        }

        // Start/Stop button handlers referenced in XAML
        private void StartButton_Click(object sender, RoutedEventArgs e)
        {
            if (StopButton.IsEnabled)
                _captureService.StopCapture(StartButton, StopButton, DeviceComboBox);
            else
                _captureService.StartCapture(DeviceComboBox, StartButton, StopButton);

            StartButton.IsEnabled = StopButton.IsEnabled || DeviceComboBox.Items.Count > 0;
            UpdateCaptureToggleButtonState();
            UpdateMonitoringHeader();
        }

        private void StopButton_Click(object sender, RoutedEventArgs e)
        {
            _captureService.StopCapture(StartButton, StopButton, DeviceComboBox);
            StartButton.IsEnabled = DeviceComboBox.Items.Count > 0;
            UpdateCaptureToggleButtonState();
            UpdateMonitoringHeader();
        }

    }
}
