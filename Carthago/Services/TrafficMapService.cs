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

        private int _drawn;

        public bool IgnorePrivateIp { get; set; } = true;

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
            _capture.TrafficRecordReceived -= OnRecord;
        }

        private void OnRecord(TrafficRecord r)
        {
            // Keep the CPU light: schedule on UI
            _ = _ui.InvokeAsync(() => Draw(r), DispatcherPriority.Background);
        }

        private void Draw(TrafficRecord r)
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
                string lbl = $"{r.Source} • {(sCity ?? r.SrcCountry ?? sIso ?? "")}".Trim();
                _ = _map.AddMarker(sLat, sLon, lbl, 4);
            }
            if (dstOk)
            {
                string lbl = $"{r.Destination} • {(dCity ?? r.DstCountry ?? dIso ?? "")}".Trim();
                _ = _map.AddMarker(dLat, dLon, lbl, 4);
            }

            if (srcOk && dstOk)
            {
                string lbl = $"{r.Source} → {r.Destination} ({proto})";
                _ = _map.AddConnection(sLat, sLon, dLat, dLon, lbl, color, 1.8, 0.85);
            }

            if (++_drawn >= _maxMarkers)
            {
                _ = _map.ClearMarkers();
                _ = _map.ClearConnections();
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

            if (preLat is double la && preLon is double lo)
            {
                lat = la; lon = lo;
                return true;
            }

            var g = _geo.Lookup(ip);
            if (g is null) return false;

            lat = g.Latitude; lon = g.Longitude;
            city = g.CityName; iso2 = g.CountryIso2;
            return true;
        }

        private static bool IsPrivate(string ip)
        {
            if (!IPAddress.TryParse(ip, out var a)) return false;

            if (a.AddressFamily == System.Net.Sockets.AddressFamily.InterNetwork)
            {
                var b = a.GetAddressBytes();
                if (b[0] == 10) return true;                           // 10/8
                if (b[0] == 172 && b[1] >= 16 && b[1] <= 31) return true; // 172.16/12
                if (b[0] == 192 && b[1] == 168) return true;           // 192.168/16
                if (b[0] == 127) return true;                          // loopback
                if (b[0] == 169 && b[1] == 254) return true;           // link-local
            }
            else if (a.AddressFamily == System.Net.Sockets.AddressFamily.InterNetworkV6)
            {
                if (a.IsIPv6LinkLocal || a.IsIPv6Multicast || a.IsIPv6SiteLocal) return true;
                var b = a.GetAddressBytes();
                if ((b[0] & 0xFE) == 0xFC) return true; // fc00::/7 (unique local)
            }
            return false;
        }
    }
}
