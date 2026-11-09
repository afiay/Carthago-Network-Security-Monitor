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
            if (g is null || !IsValidCoordinates(g.Latitude, g.Longitude)) return false;

            lat = g.Latitude; lon = g.Longitude;
            city = g.CityName; iso2 = g.CountryIso2;
            return true;
        }

        private static bool IsValidCoordinates(double latitude, double longitude)
            => double.IsFinite(latitude) && double.IsFinite(longitude)
                && latitude is >= -90 and <= 90 && longitude is >= -180 and <= 180;

        private static bool IsPrivate(string ip)
        {
            if (!IPAddress.TryParse(ip, out var a)) return false;
            if (a.IsIPv4MappedToIPv6)
                a = a.MapToIPv4();

            if (a.AddressFamily == System.Net.Sockets.AddressFamily.InterNetwork)
            {
                var b = a.GetAddressBytes();
                if (b[0] == 0 || b[0] >= 224) return true;        // unspecified, multicast, reserved
                if (b[0] == 10) return true;                           // 10/8
                if (b[0] == 100 && b[1] >= 64 && b[1] <= 127) return true; // shared CGNAT /10
                if (b[0] == 172 && b[1] >= 16 && b[1] <= 31) return true; // 172.16/12
                if (b[0] == 192 && b[1] == 168) return true;           // 192.168/16
                if (b[0] == 127) return true;                          // loopback
                if (b[0] == 169 && b[1] == 254) return true;           // link-local
                if (b[0] == 192 && b[1] == 0 && b[2] == 2) return true; // TEST-NET-1
                if (b[0] == 198 && (b[1] == 18 || b[1] == 19)) return true; // benchmark /15
                if (b[0] == 198 && b[1] == 51 && b[2] == 100) return true; // TEST-NET-2
                if (b[0] == 203 && b[1] == 0 && b[2] == 113) return true; // TEST-NET-3
            }
            else if (a.AddressFamily == System.Net.Sockets.AddressFamily.InterNetworkV6)
            {
                if (IPAddress.IsLoopback(a) || a.Equals(IPAddress.IPv6Any) || a.Equals(IPAddress.IPv6None)) return true;
                if (a.IsIPv6LinkLocal || a.IsIPv6Multicast || a.IsIPv6SiteLocal) return true;
                var b = a.GetAddressBytes();
                if ((b[0] & 0xFE) == 0xFC) return true; // fc00::/7 (unique local)
                if (b[0] == 0x20 && b[1] == 0x01 && b[2] == 0x0D && b[3] == 0xB8) return true; // documentation prefix
            }
            return false;
        }
    }
}
