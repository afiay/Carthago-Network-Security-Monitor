// SPDX-License-Identifier: MIT
// File: Views/Controls/WorldMapControl.xaml.cs

using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Globalization;
using System.IO;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using System.Web;
using System.Windows;
using System.Windows.Controls;
using System.Windows.Media;
using Microsoft.Web.WebView2.Core;

namespace Carthago.Controls
{
    public partial class WorldMapControl : UserControl
    {
        private bool _initialized;
        private bool _useLocalLeaflet;                 // true when Data/leaflet/* is present
        private string _localLeafletDir = string.Empty;

        // For callers that used a nested marker type previously
        public readonly record struct GeoMarker(double Lat, double Lon, string Label, int Radius = 4);

        public WorldMapControl()
        {
            InitializeComponent();
            Loaded += OnLoaded;
        }

        #region DependencyProperties

        public static readonly DependencyProperty ShowGraticuleProperty =
            DependencyProperty.Register(nameof(ShowGraticule), typeof(bool), typeof(WorldMapControl),
                new PropertyMetadata(false));
        public bool ShowGraticule
        {
            get => (bool)GetValue(ShowGraticuleProperty);
            set => SetValue(ShowGraticuleProperty, value);
        }

        // Stroke used for polygon outlines (world shapes, etc.)
        public static readonly DependencyProperty StrokeProperty =
            DependencyProperty.Register(nameof(Stroke), typeof(Brush), typeof(WorldMapControl),
                new PropertyMetadata(Brushes.LightSteelBlue, OnStrokeChanged));
        public Brush Stroke
        {
            get => (Brush)GetValue(StrokeProperty);
            set => SetValue(StrokeProperty, value);
        }

        private static async void OnStrokeChanged(DependencyObject d, DependencyPropertyChangedEventArgs e)
        {
            var ctrl = (WorldMapControl)d;
            if (ctrl.MapView?.CoreWebView2 is null) return;
            var css = BrushToCss(ctrl.Stroke);
            try
            {
                await ctrl.MapView.CoreWebView2.ExecuteScriptAsync(
                    $"window.__carthago && __carthago.setPolygonStyle && __carthago.setPolygonStyle(\"{css}\", 0.9, 0.8, 0.6);");
            }
            catch { /* ignore */ }
        }

        // Debug toggle (opens DevTools in DEBUG only)
        public static readonly DependencyProperty DebugModeProperty =
            DependencyProperty.Register(nameof(DebugMode), typeof(bool), typeof(WorldMapControl),
                new PropertyMetadata(false, OnDebugModeChanged));
        public bool DebugMode
        {
            get => (bool)GetValue(DebugModeProperty);
            set => SetValue(DebugModeProperty, value);
        }

        private static void OnDebugModeChanged(DependencyObject d, DependencyPropertyChangedEventArgs e)
        {
            var ctrl = (WorldMapControl)d;
            if (ctrl.MapView?.CoreWebView2 is null) return;
#if DEBUG
            if ((bool)e.NewValue)
                ctrl.MapView.CoreWebView2.OpenDevToolsWindow();
#endif
        }

        #endregion

        private async void OnLoaded(object? sender, RoutedEventArgs e)
        {
            if (_initialized) return;

            try
            {
                // Status overlay above the WebView
                Panel.SetZIndex(StatusOverlay, 99);

                // Detect local Leaflet bundle (Data/leaflet/leaflet.{js,css})
                _localLeafletDir = Path.Combine(AppContext.BaseDirectory, "Data", "leaflet");
                _useLocalLeaflet = File.Exists(Path.Combine(_localLeafletDir, "leaflet.js")) &&
                                   File.Exists(Path.Combine(_localLeafletDir, "leaflet.css"));

                await MapView.EnsureCoreWebView2Async();

                // Serve local leaflet via virtual host if present
                if (_useLocalLeaflet)
                {
                    MapView.CoreWebView2.SetVirtualHostNameToFolderMapping(
                        "app.local", _localLeafletDir, CoreWebView2HostResourceAccessKind.Allow);
                }

                // Dev/diagnostics
                MapView.CoreWebView2.Settings.AreDevToolsEnabled = true;
                MapView.CoreWebView2.Settings.IsWebMessageEnabled = true;

                // Navigation status
                MapView.CoreWebView2.NavigationCompleted += (_, e2) =>
                {
                    if (!e2.IsSuccess)
                        ShowStatus($"Navigation error: 0x{e2.WebErrorStatus:X} ({e2.WebErrorStatus})");
                };

                // Portable console/error bridge via WebMessageReceived (works across SDKs)
                MapView.CoreWebView2.WebMessageReceived += (_, e3) =>
                {
                    try
                    {
                        var s = e3.TryGetWebMessageAsString();
                        if (string.IsNullOrWhiteSpace(s)) return;

                        Debug.WriteLine("[Map JS] " + s);

                        if (s.StartsWith("ERR:", StringComparison.OrdinalIgnoreCase))
                            ShowStatus(s.Substring(4).Trim());
                        else if (s.StartsWith("WARN:", StringComparison.OrdinalIgnoreCase))
                            ShowStatus(s.Substring(5).Trim());
                    }
                    catch { /* ignore */ }
                };

                MapView.NavigateToString(BuildHtml(_useLocalLeaflet));
                _initialized = true;

#if DEBUG
                if (DebugMode) MapView.CoreWebView2.OpenDevToolsWindow();
#endif

                // Probe Leaflet readiness
                if (!await IsLeafletAvailableAsync().ConfigureAwait(true))
                {
                    ShowStatus(_useLocalLeaflet
                        ? "Leaflet failed to load from local bundle (Data/leaflet). Check files."
                        : "Leaflet failed to load from CDN. Network/CSP issue?");
                }
                else
                {
                    HideStatus();
                    // Apply current stroke once JS is ready
                    await MapView.CoreWebView2.ExecuteScriptAsync(
                        $"window.__carthago && __carthago.setPolygonStyle && __carthago.setPolygonStyle(\"{BrushToCss(Stroke)}\", 0.9, 0.8, 0.6);");
                }
            }
            catch (Exception ex)
            {
                ShowStatus("Map init error: " + ex.Message);
            }
        }

        private async Task<bool> IsLeafletAvailableAsync()
        {
            try
            {
                for (int i = 0; i < 12; i++)
                {
                    var t = await MapView.CoreWebView2.ExecuteScriptAsync("typeof L");
                    if (t.Contains("object", StringComparison.OrdinalIgnoreCase))
                        return true;
                    await Task.Delay(150);
                }
            }
            catch { }
            return false;
        }

        private void ShowStatus(string msg)
        {
            StatusText.Text = msg;
            StatusOverlay.Visibility = Visibility.Visible;
        }
        private void HideStatus() => StatusOverlay.Visibility = Visibility.Collapsed;

        private static string D(double v) => v.ToString(CultureInfo.InvariantCulture);
        private static string Escape(string? s) => HttpUtility.JavaScriptStringEncode(s ?? "");

        private async Task EvalAsync(string js)
        {
            try
            {
                if (MapView?.CoreWebView2 is null) return;
                await MapView.CoreWebView2.ExecuteScriptAsync(js);
            }
            catch { /* ignore transient eval errors */ }
        }

        private static string BrushToCss(Brush b)
        {
            if (b is SolidColorBrush scb)
                return $"#{scb.Color.R:X2}{scb.Color.G:X2}{scb.Color.B:X2}";
            return "#C8DCFF"; // default
        }

        // ===== Public API (used by your services / MainWindow) =====

        public Task AddMarker(GeoMarker g) => AddMarker(g.Lat, g.Lon, g.Label, g.Radius);

        public Task AddMarker(double lat, double lon, string? label = null, int radius = 4)
            => EvalAsync($"window.__carthago && __carthago.addMarker({D(lat)},{D(lon)},\"{Escape(label)}\",{radius});");

        public Task AddConnection(double lat1, double lon1, double lat2, double lon2, string? label = null, string? color = null, double weight = 1.8, double opacity = 0.85)
            => EvalAsync($"window.__carthago && __carthago.addConnection({D(lat1)},{D(lon1)},{D(lat2)},{D(lon2)},\"{Escape(label)}\",\"{Escape(color)}\",{D(weight)},{D(opacity)});");

        public Task ClearMarkers() => EvalAsync("window.__carthago && __carthago.clearMarkers();");
        public Task ClearConnections() => EvalAsync("window.__carthago && __carthago.clearConnections();");

        public Task SetTileUrl(string tileUrl)
            => EvalAsync($"window.__carthago && __carthago.setTileUrl(\"{Escape(tileUrl)}\");");

        // Draw/clear polygon overlays (e.g., world coastlines from GeoJSON preprocessed in C#)
        // Each IList<Point> is a ring (lon=x, lat=y). We’ll render each as a Leaflet polygon.
        public Task SetPolygons(IEnumerable<IList<Point>> polygons, double weight = 0.6, double opacity = 0.9)
        {
            // Build JS array: [ [ [lat,lon], ... ], [ ... ], ... ]
            var sb = new StringBuilder();
            sb.Append("[");
            bool firstRing = true;
            foreach (var ring in polygons ?? Enumerable.Empty<IList<Point>>())
            {
                if (!firstRing) sb.Append(",");
                firstRing = false;

                sb.Append("[");
                bool firstPt = true;
                foreach (var p in ring)
                {
                    if (!firstPt) sb.Append(",");
                    firstPt = false;
                    // Leaflet expects [lat, lon]
                    sb.Append("[");
                    sb.Append(D(p.Y)); sb.Append(","); sb.Append(D(p.X));
                    sb.Append("]");
                }
                sb.Append("]");
            }
            sb.Append("]");

            var color = BrushToCss(Stroke);
            var js = $"window.__carthago && __carthago.setPolygons({sb}, \"{color}\", {D(weight)}, {D(opacity)}, 0.4);";
            return EvalAsync(js);
        }

        public Task ClearPolygons()
            => EvalAsync("window.__carthago && __carthago.clearPolygons();");

        // ====== HTML/JS (Leaflet + API) ======
        private string BuildHtml(bool preferLocal)
        {
            var leafletCss = preferLocal
                ? "https://app.local/leaflet.css"
                : "https://unpkg.com/leaflet@1.9.4/dist/leaflet.css";

            var primaryJs = preferLocal ? "https://app.local/leaflet.js" : "https://unpkg.com/leaflet@1.9.4/dist/leaflet.js";
            var fallback1Js = "https://unpkg.com/leaflet@1.9.4/dist/leaflet.js";
            var fallback2Js = "https://cdn.jsdelivr.net/npm/leaflet@1.9.4/dist/leaflet.js";

            var html = $@"
<!doctype html>
<html>
<head>
<meta charset=""utf-8""/>
<meta http-equiv=""Content-Security-Policy""
      content=""default-src 'self' https: data: blob:;
               script-src  'self' 'unsafe-inline' https://app.local https://unpkg.com https://cdn.jsdelivr.net;
               style-src   'self' 'unsafe-inline' https://app.local https://unpkg.com https://cdn.jsdelivr.net;
               img-src     * data: blob:;"">
<meta name=""viewport"" content=""width=device-width, initial-scale=1""/>
<style>
html, body, #map {{ height: 100%; margin: 0; padding: 0; }}
.leaflet-tooltip {{ font: 12px/1.2 sans-serif; }}
</style>
<link id=""leaflet-css"" rel=""stylesheet"" href=""{leafletCss}""
      onerror=""this.href='https://cdn.jsdelivr.net/npm/leaflet@1.9.4/dist/leaflet.css'"">
</head>
<body>
<div id=""map""></div>
<script>
(function(){{
  function loadScript(src, onload, onerror){{
    var s=document.createElement('script');
    s.src=src; s.async=true; s.onload=onload; s.onerror=onerror||function(){{}};
    document.head.appendChild(s);
  }}
  function loadSeries(urls, done){{
    if (!urls || !urls.length) return;
    var i = 0;
    function next(){{ if (++i < urls.length) loadScript(urls[i], done, next); }}
    loadScript(urls[0], done, next);
  }}

  function init(){{
    if (typeof L === 'undefined') return setTimeout(init, 150);

    var map = L.map('map', {{ worldCopyJump: true, zoomSnap: 0.5 }}).setView([25, 10], 2.2);

    var tiles = L.tileLayer('https://{{s}}.tile.openstreetmap.org/{{z}}/{{x}}/{{y}}.png', {{
      maxZoom: 6, attribution: '&copy; OpenStreetMap'
    }}).addTo(map);

    var markers = [];
    var lines   = [];
    var polys   = [];
    var polyStyle = {{ color:'#C8DCFF', weight:0.6, opacity:0.9, fillOpacity:0.4 }};

    function setPolygonStyle(color, opacity, fillOpacity, weight){{
      if (color) polyStyle.color = color;
      if (typeof opacity==='number') polyStyle.opacity = opacity;
      if (typeof fillOpacity==='number') polyStyle.fillOpacity = fillOpacity;
      if (typeof weight==='number') polyStyle.weight = weight;
      for (var i=0;i<polys.length;i++) polys[i].setStyle(polyStyle);
    }}

    function addMarker(lat, lon, label, radius){{
      try{{
        var m = L.circleMarker([lat, lon], {{ radius: radius||4, weight: 1, opacity: 0.9, fillOpacity: 0.8 }});
        if (label) m.bindTooltip(label, {{permanent:false, direction:'top', opacity:0.9}});
        m.addTo(map); markers.push(m);
      }}catch(e){{ post('ERR: addMarker ' + (e && e.message ? e.message : e)); }}
    }}
    function addConnection(lat1, lon1, lat2, lon2, label, color, weight, opacity){{
      try{{
        var line = L.polyline([[lat1, lon1], [lat2, lon2]], {{
          color: color || '#ffcc00', weight: weight || 2, opacity: opacity || 0.8
        }}).addTo(map);
        if (label) line.bindTooltip(label, {{sticky:true}});
        lines.push(line);
      }}catch(e){{ post('ERR: addConnection ' + (e && e.message ? e.message : e)); }}
    }}
    function clearMarkers()     {{ for (var i=0;i<markers.length;i++) map.removeLayer(markers[i]); markers = []; }}
    function clearConnections() {{ for (var i=0;i<lines.length;i++)   map.removeLayer(lines[i]);   lines   = []; }}
    function clearPolygons()    {{ for (var i=0;i<polys.length;i++)   map.removeLayer(polys[i]);   polys   = []; }}

    // rings: [ [ [lat,lon], ... ], [ ... ], ... ]
    function setPolygons(rings, color, weight, opacity, fillOpacity){{
      try{{
        clearPolygons();
        if (color) polyStyle.color = color;
        if (typeof weight==='number') polyStyle.weight = weight;
        if (typeof opacity==='number') polyStyle.opacity = opacity;
        if (typeof fillOpacity==='number') polyStyle.fillOpacity = fillOpacity;

        for (var i=0;i<rings.length;i++){{
          var poly = L.polygon(rings[i], polyStyle).addTo(map);
          polys.push(poly);
        }}
      }}catch(e){{ post('ERR: setPolygons ' + (e && e.message ? e.message : e)); }}
    }}

    // ===== Debug bridge to C# via WebMessageReceived =====
    function post(msg){{
      try{{ if (window.chrome && window.chrome.webview && window.chrome.webview.postMessage) window.chrome.webview.postMessage(msg); }}catch(_){{
        /* ignore */
      }}
    }}
    window.addEventListener('error', function(e){{ post('ERR: ' + e.message); }});
    (function wrapConsole(){{
      ['error','warn'].forEach(function(fn){{
        var orig = console[fn];
        console[fn] = function(){{
          try{{ post((fn==='error'?'ERR: ':'WARN: ')+Array.prototype.join.call(arguments,' ')); }}catch(_){{
            /* ignore */
          }}
          if (orig) return orig.apply(console, arguments);
        }};
      }});
    }})();

    // Minimal API for C#
    window.__carthago = {{
      addMarker, addConnection, clearMarkers, clearConnections,
      setTileUrl: function(u){{ try{{ map.removeLayer(tiles); tiles = L.tileLayer(u, {{ maxZoom: 6 }}).addTo(map); }}catch(e){{ post('ERR: setTileUrl ' + (e && e.message ? e.message : e)); }} }},
      setPolygons, clearPolygons, setPolygonStyle
    }};
  }}

  loadSeries(
    ['{primaryJs}', '{fallback1Js}', '{fallback2Js}'],
    init
  );
}})();
</script>
</body>
</html>";
            return html;
        }
    }
}
