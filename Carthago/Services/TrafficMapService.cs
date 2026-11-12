// SPDX-License-Identifier: MIT
// File: Services/TrafficMapService.cs
using System;
using System.Net;
using System.Threading;
using System.Threading.Tasks;
using System.Windows.Threading;
using Carthago.Controls;
using Carthago.Models;
using Carthago.Services.Geo;

namespace Carthago.Services
{
    /// <summary>
    /// Subscribes to TrafficCaptureService and paints on WorldMapControl.
    /// Draws markers when either endpoint geolocates; draws a line when both do.
    /// </summary>
    public sealed class TrafficMapService : IDisposable
    {
        private readonly WorldMapControl _map;
        private readonly TrafficCaptureService _capture;
        private readonly GeoIpService _geo;
        private readonly Dispatcher _ui;
        private readonly int _maxMarkers;

        // The geographic overlay is best-effort visualization, never a capture
        // queue. Bounds prevent a busy sensor from flooding the WPF dispatcher.
        private const int MaxPendingOverlayDraws = 64;
        private int _pendingOverlayDraws;
        private int _visualizationActive = 1;
        private long _skippedOverlayDraws;

        private int _drawn;

        public bool IgnorePrivateIp { get; set; } = true;
        public long SkippedOverlayDraws => Interlocked.Read(ref _skippedOverlayDraws);

        public void SetVisualizationActive(bool active)
            => Volatile.Write(ref _visualizationActive, active ? 1 : 0);

        public TrafficMapService(WorldMapControl map,
                                 TrafficCaptureService capture,
                                 GeoIpService geo,
                                 Dispatcher ui,
                                 int maxMarkers = 2500)
        {
            _map = map ?? throw new ArgumentNullException(nameof(map));
            _capture = capture ?? throw new ArgumentNullException(nameof(capture));
            _geo = geo ?? throw new ArgumentNullException(nameof(geo));
            _ui = ui ?? throw new ArgumentNullException(nameof(ui));
            _maxMarkers = Math.Max(200, maxMarkers);

            _capture.TrafficRecordReceived += OnRecord;
        }

        public void Dispose()
        {
            SetVisualizationActive(false);
            _capture.TrafficRecordReceived -= OnRecord;
        }

        private void OnRecord(TrafficRecord r)
            => UiOperationProfiler.Measure("MapOverlaySchedule", () => OnRecordCore(r));

        private void OnRecordCore(TrafficRecord r)
        {
            if (Volatile.Read(ref _visualizationActive) == 0)
                return;

            if (Interlocked.Increment(ref _pendingOverlayDraws) > MaxPendingOverlayDraws)
            {
                Interlocked.Decrement(ref _pendingOverlayDraws);
                Interlocked.Increment(ref _skippedOverlayDraws);
                return;
            }

            try
            {
                Func<Task> render = async () =>
                {
                    if (Volatile.Read(ref _visualizationActive) != 0)
                        await DrawAsync(r);
                };
                var request = _ui.InvokeAsync(render, DispatcherPriority.Background);

                // Decrement also on dispatcher shutdown/cancellation, when the
                // scheduled action might never run. Keep the queue slot until
                // the underlying WebView2 render requests have completed.
                _ = request.Task.Unwrap().ContinueWith(completed =>
                {
                    _ = completed.Exception; // observe any asynchronous failure
                    Interlocked.Decrement(ref _pendingOverlayDraws);
                }, TaskScheduler.Default);
            }
            catch (Exception)
            {
                // A disposed or shutting-down UI dispatcher must not throw back
                // into the capture producer. Only this optional overlay is lost.
                Interlocked.Decrement(ref _pendingOverlayDraws);
                Interlocked.Increment(ref _skippedOverlayDraws);
            }
        }

        private async Task DrawAsync(TrafficRecord r)
        {
            bool srcOk = TryGetCoords(r.Source, r.SrcLat, r.SrcLon, out var sLat, out var sLon, out var sCity, out var sIso);
            bool dstOk = TryGetCoords(r.Destination, r.DstLat, r.DstLon, out var dLat, out var dLon, out var dCity, out var dIso);

            var proto = (r.Protocol ?? string.Empty).ToUpperInvariant();
            var color = proto switch
            {
                "TCP" => "#27ae60",
                "UDP" => "#2980b9",
                "ICMP" => "#f39c12",
                _ => "#ffcc00"
            };

            if (srcOk)
            {
                string lbl = $"Approximate IP geography • {r.Source} • {(sCity ?? r.SrcCountry ?? sIso ?? "")}".Trim();
                await _map.AddMarker(sLat, sLon, lbl, 4, r.Source);
            }
            if (dstOk)
            {
                string lbl = $"Approximate IP geography • {r.Destination} • {(dCity ?? r.DstCountry ?? dIso ?? "")}".Trim();
                await _map.AddMarker(dLat, dLon, lbl, 4, r.Destination);
            }

            if (srcOk && dstOk)
            {
                string lbl = $"{r.Source} → {r.Destination} ({proto})";
                await _map.AddConnection(sLat, sLon, dLat, dLon, lbl, color, 1.8, 0.85);
            }

            if (++_drawn >= _maxMarkers)
            {
                await _map.ClearMarkers();
                await _map.ClearConnections();
                _drawn = 0;
            }
        }

        private bool TryGetCoords(string? ip, double? preLat, double? preLon,
                                  out double lat, out double lon,
                                  out string? city, out string? iso2)
        {
            lat = lon = 0; city = iso2 = null;
            if (string.IsNullOrWhiteSpace(ip)) return false;

            if (IgnorePrivateIp && IsPrivate(ip)) return false;

            if (preLat is double la && preLon is double lo && IsValidCoordinates(la, lo))
            {
                lat = la; lon = lo;
                return true;
            }

            var g = _geo.Lookup(ip);
            if (g?.Latitude is not double geoLat || g.Longitude is not double geoLon
                || !IsValidCoordinates(geoLat, geoLon)) return false;

            lat = geoLat; lon = geoLon;
            city = g.CityName; iso2 = g.CountryIso2;
            return true;
        }

        private static bool IsValidCoordinates(double latitude, double longitude)
            => double.IsFinite(latitude) && double.IsFinite(longitude)
                && latitude is >= -90 and <= 90 && longitude is >= -180 and <= 180;

        private static bool IsPrivate(string ip)
            => EndpointIpEnrichment.Classify(ip) != "Public";
    }
}
