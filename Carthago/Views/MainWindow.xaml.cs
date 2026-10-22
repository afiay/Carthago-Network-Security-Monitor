// SPDX-License-Identifier: MIT
// File: Views/MainWindow.xaml.cs
using System;
using System.Collections.Generic;
using System.IO;
using System.Net.Http;
using System.Text.Json.Nodes;
using System.Threading.Tasks;
using System.Windows;
using System.Windows.Media;
using Carthago.Controls;     // WorldMapControl
using Carthago.Services;
using Carthago.Sinks;
using Carthago.Views;

namespace Carthago
{
    public partial class MainWindow : Window
    {
        private SinkHost? _sinkHost;

        // NOTE: _blacklistService and _captureService are declared in another partial.
        // We intentionally DO NOT redeclare them here to avoid CS0102 duplicates.

        // Implemented in your other partial
        partial void AfterInitialize();

        public MainWindow()
        {
            InitializeComponent();

            // These fields are declared in another partial; we only assign here.
            _blacklistService = new BlacklistService();
            _captureService = new TrafficCaptureService(_blacklistService, this.Dispatcher);

            // Load persisted preferences before building sink runtime state.
            PreferencesService.Load();

            // pass capture into SinkHost
            _sinkHost = new SinkHost(() => PreferencesService.Current, _captureService);

            WireAllSidebarEvents();
            this.Loaded += (_, __) => WireAllSidebarEvents();

            this.Closed -= MainWindow_Closed_DisposeSinks;
            this.Closed += MainWindow_Closed_DisposeSinks;

            AfterInitialize();
        }

        private void MainWindow_Closed_DisposeSinks(object? sender, EventArgs e)
        {
            try { _sinkHost?.Dispose(); } catch { /* ignore on shutdown */ }
        }

        private void WireAllSidebarEvents()
        {
            if (SidebarPanel == null) return;

            SidebarPanel.DashboardRequested -= Nav_Dashboard_Click;
            SidebarPanel.DashboardRequested += Nav_Dashboard_Click;

            SidebarPanel.AnomaliesRequested -= Nav_Anomalies_Click;
            SidebarPanel.AnomaliesRequested += Nav_Anomalies_Click;

            SidebarPanel.LiveTrafficRequested -= Nav_LiveTraffic_Click;
            SidebarPanel.LiveTrafficRequested += Nav_LiveTraffic_Click;

            SidebarPanel.AlertsRequested -= Nav_Alerts_Click;
            SidebarPanel.AlertsRequested += Nav_Alerts_Click;

            // Analytics -> use Nav_Analytics_Click2 ONLY
            SidebarPanel.AnalyticsRequested -= Nav_Analytics_Click2;
            SidebarPanel.AnalyticsRequested += Nav_Analytics_Click2;

            SidebarPanel.SettingsRequested -= Nav_Settings_Click;
            SidebarPanel.SettingsRequested += Nav_Settings_Click;

            SidebarPanel.IntegrationsRequested -= Nav_Integrations_Click;
            SidebarPanel.IntegrationsRequested += Nav_Integrations_Click;

            SidebarPanel.SinkEventsRequested -= Nav_SinkEvents_Click;
            SidebarPanel.SinkEventsRequested += Nav_SinkEvents_Click;

            SidebarPanel.IncidentsRequested -= Nav_Incidents_Click;
            SidebarPanel.IncidentsRequested += Nav_Incidents_Click;

            SidebarPanel.IncidentQueueRequested -= Nav_IncidentQueue_Click;
            SidebarPanel.IncidentQueueRequested += Nav_IncidentQueue_Click;

            SidebarPanel.ThreatFeedRequested -= Nav_ThreatFeed_Click;
            SidebarPanel.ThreatFeedRequested += Nav_ThreatFeed_Click;

            // NEW: Host Integrity + Cisco Tools wiring
            SidebarPanel.HostIntegrityRequested -= Nav_HostIntegrity_Click;
            SidebarPanel.HostIntegrityRequested += Nav_HostIntegrity_Click;

            SidebarPanel.CiscoToolsRequested -= Nav_CiscoTools_Click;
            SidebarPanel.CiscoToolsRequested += Nav_CiscoTools_Click;

            // Filters
            SidebarPanel.TrafficFilterApplyRequested -= TF_Apply_Click;
            SidebarPanel.TrafficFilterApplyRequested += TF_Apply_Click;
            SidebarPanel.TrafficFilterClearRequested -= TF_Clear_Click;
            SidebarPanel.TrafficFilterClearRequested += TF_Clear_Click;

            SidebarPanel.AlertsFilterApplyRequested -= AF_Apply_Click;
            SidebarPanel.AlertsFilterApplyRequested += AF_Apply_Click;
            SidebarPanel.AlertsFilterClearRequested -= AF_Clear_Click;
            SidebarPanel.AlertsFilterClearRequested += AF_Clear_Click;

            SidebarPanel.SinkEventsFilterApplyRequested -= SE_Apply_Click;
            SidebarPanel.SinkEventsFilterApplyRequested += SE_Apply_Click;
            SidebarPanel.SinkEventsFilterClearRequested -= SE_Clear_Click;
            SidebarPanel.SinkEventsFilterClearRequested += SE_Clear_Click;
        }

        // ======== SIDE-PANE NAV (replaces popups) ========

        private void Nav_Integrations_Click(object? sender, RoutedEventArgs e)
        {
            EnsureSinkHost();
            ShowView(IntegrationsView);
            SidebarPanel?.ActivateNav("Integrations");
            if (IntegrationsFrame.Content is not IntegrationsPage)
                IntegrationsFrame.Content = new IntegrationsPage(_sinkHost!);
        }

        private void Nav_Incidents_Click(object? sender, RoutedEventArgs e)
        {
            EnsureSinkHost();
            ShowView(IncidentsView);
            SidebarPanel?.ActivateNav("Incidents");
            if (IncidentsFrame.Content is not IncidentsPage)
                IncidentsFrame.Content = new IncidentsPage(_sinkHost!, "Incidents");
        }

        private void Nav_IncidentQueue_Click(object? sender, RoutedEventArgs e)
        {
            EnsureSinkHost();
            ShowView(IncidentsView);
            SidebarPanel?.ActivateNav("IncidentQueue");
            if (IncidentsFrame.Content is not IncidentQueuePage)
                IncidentsFrame.Content = new IncidentQueuePage(_sinkHost!);
        }

        private void Nav_ThreatFeed_Click(object? sender, RoutedEventArgs e)
        {
            EnsureSinkHost();
            ShowView(ThreatFeedView);
            SidebarPanel?.ActivateNav("ThreatFeed");
            ThreatFeedFrame.Content = new ThreatFeedPage(
                _sinkHost!,
                _alerts,
                openRawTraffic: () => Nav_LiveTraffic_Click(this, new RoutedEventArgs()),
                openRawDetections: () => Nav_Alerts_Click(this, new RoutedEventArgs()),
                openIncidentQueue: () => Nav_IncidentQueue_Click(this, new RoutedEventArgs()));
        }

        private void Nav_Anomalies_Click(object? sender, RoutedEventArgs e)
        {
            EnsureSinkHost();
            ShowView(AnomaliesView);
            SidebarPanel?.ActivateNav("Anomalies");
            if (AnomaliesFrame.Content is not AnomaliesPage)
            {
                AnomaliesFrame.Content = new AnomaliesPage(
                    _sinkHost!,
                    openRawTraffic: () => Nav_LiveTraffic_Click(this, new RoutedEventArgs()),
                    openRawDetections: () => Nav_Alerts_Click(this, new RoutedEventArgs()),
                    openIncidentQueue: () => Nav_IncidentQueue_Click(this, new RoutedEventArgs()),
                    openIncidentWorkspace: incidentId => OpenIncidentWorkspace(incidentId),
                    openHostIntegrity: () => Nav_HostIntegrity_Click(this, new RoutedEventArgs()),
                    openAnalytics: () => Nav_Analytics_Click2(this, new RoutedEventArgs()),
                    openDetectionRules: () => OpenDetectionRulesWorkspace());
            }
        }

        private void Nav_SinkEvents_Click(object? sender, RoutedEventArgs e)
        {
            EnsureSinkHost();
            ShowView(SinkEventsView);
            SidebarPanel?.ActivateNav("SinkEvents");
            if (SinkEventsFrame.Content is not SinkEventsPage)
                SinkEventsFrame.Content = new SinkEventsPage(_sinkHost!);
        }

        // (optional) wire filter buttons for Sink Events – placeholders for now
        private void SE_Apply_Click(object? s, RoutedEventArgs e) { /* add filtering later if desired */ }
        private void SE_Clear_Click(object? s, RoutedEventArgs e) { /* add filtering later if desired */ }

        private void EnsureSinkHost()
        {
            if (_sinkHost == null)
                _sinkHost = new SinkHost(() => PreferencesService.Current, _captureService);
        }

        // ======== ANALYTICS / MAP ========
        // New handler name to avoid CS0111 duplicate with existing Nav_Analytics_Click.
        private async void Nav_Analytics_Click2(object? sender, RoutedEventArgs e)
        {
            ShowView(AnalyticsView);
            SidebarPanel?.ActivateNav("Analytics");

            if (WorldMap != null)
            {
                var subtle = TryFindResource("TextSubtleBrush") as Brush ?? Brushes.White;
                WorldMap.Stroke = subtle;
                if (WorldMap.Background == null)
                    WorldMap.Background = Brushes.Transparent;
            }

            try
            {
                if (!await LoadWorldMapIfAvailableAsync().ConfigureAwait(true))
                {
                    await EnsureWorldGeoJsonAsync().ConfigureAwait(true);
                    await LoadWorldMapIfAvailableAsync().ConfigureAwait(true);
                }
            }
            catch
            {
                // fall back to graticule only
            }

            WorldMap?.InvalidateVisual();
        }

        private string GetWorldGeoJsonPath()
            => Path.Combine(AppDomain.CurrentDomain.BaseDirectory, "Data", "world.geojson");

        /// <summary>Loads polygons from Data/world.geojson if present.</summary>
        private async Task<bool> LoadWorldMapIfAvailableAsync()
        {
            if (WorldMap == null) return false;

            var path = GetWorldGeoJsonPath();
            if (!File.Exists(path))
                return false;

            try
            {
                string json = await File.ReadAllTextAsync(path).ConfigureAwait(true);
                var root = JsonNode.Parse(json);
                var features = root?["features"]?.AsArray();
                if (features == null || features.Count == 0)
                    return false;

                var polys = new List<IList<Point>>();

                foreach (var f in features)
                {
                    var geom = f?["geometry"];
                    var type = geom?["type"]?.ToString();
                    if (type is "Polygon")
                    {
                        foreach (var ring in geom!["coordinates"]!.AsArray())
                        {
                            var list = new List<Point>();
                            foreach (var pt in ring!.AsArray())
                            {
                                double lon = pt![0]!.GetValue<double>();
                                double lat = pt![1]!.GetValue<double>();
                                list.Add(new Point(lon, lat));
                            }
                            polys.Add(list);
                        }
                    }
                    else if (type is "MultiPolygon")
                    {
                        foreach (var poly in geom!["coordinates"]!.AsArray())
                        {
                            foreach (var ring in poly!.AsArray())
                            {
                                var list = new List<Point>();
                                foreach (var pt in ring!.AsArray())
                                {
                                    double lon = pt![0]!.GetValue<double>();
                                    double lat = pt![1]!.GetValue<double>();
                                    list.Add(new Point(lon, lat));
                                }
                                polys.Add(list);
                            }
                        }
                    }
                }

                if (polys.Count > 0)
                {
                    await WorldMap.SetPolygons(polys).ConfigureAwait(true);
                    WorldMap.Stroke = new SolidColorBrush(Color.FromRgb(200, 220, 255));
                    return true;
                }
            }
            catch
            {
                // ignore and let graticule render
            }

            return false;
        }

        /// <summary>
        /// Ensures Data/world.geojson exists by downloading a small public world outline.
        /// If offline, this no-ops and the map will still show its graticule.
        /// </summary>
        private async Task EnsureWorldGeoJsonAsync()
        {
            var path = GetWorldGeoJsonPath();
            try
            {
                var dir = Path.GetDirectoryName(path);
                if (!string.IsNullOrWhiteSpace(dir) && !Directory.Exists(dir))
                    Directory.CreateDirectory(dir!);

                if (File.Exists(path))
                    return;

                var urls = new[]
                {
                    // Natural Earth 110m admin 0
                    new Uri("https://raw.githubusercontent.com/nvkelso/natural-earth-vector/master/geojson/ne_110m_admin_0_countries.geojson"),
                    // Mirror dataset
                    new Uri("https://raw.githubusercontent.com/datasets/geo-countries/master/data/countries.geojson"),
                };

                using var http = new HttpClient { Timeout = TimeSpan.FromSeconds(10) };

                foreach (var url in urls)
                {
                    try
                    {
                        var data = await http.GetByteArrayAsync(url).ConfigureAwait(true);
                        if (data is { Length: > 0 })
                        {
                            await File.WriteAllBytesAsync(path, data).ConfigureAwait(true);
                            return;
                        }
                    }
                    catch
                    {
                        // try next mirror
                    }
                }
            }
            catch
            {
                // ignore; graticule fallback still works
            }
        }

        // ======== Other nav handlers (Dashboard, LiveTraffic, Alerts, Settings, etc.)
        // are implemented in your other partial(s).
    }
}
