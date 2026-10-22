// SPDX-License-Identifier: MIT
// File: Services/MapUpdateService.cs

using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading;
using System.Threading.Channels;
using System.Threading.Tasks;
using System.Windows;
using System.Windows.Threading;
using Carthago.Controls;
using Carthago.Models;
using Carthago.Services.Geo;

namespace Carthago.Services
{
    /// <summary>
    /// Bridges capture -> geo -> map. Collects TrafficRecords, fills missing geo via GeoIpService,
    /// and updates WorldMapControl on the UI thread using a throttled batch.
    /// </summary>
    public sealed class MapUpdateService : IDisposable
    {
        private const int MAX_MARKERS_ON_MAP = 800;
        private const int BATCH_SIZE = 150;
        private static readonly TimeSpan TICK = TimeSpan.FromMilliseconds(250);

        private readonly WorldMapControl _map;
        private readonly TrafficCaptureService _capture;
        private readonly GeoIpService _geo;
        private readonly Dispatcher _dispatcher;
        private readonly Channel<TrafficRecord> _ch;
        private readonly CancellationTokenSource _cts = new();
        private readonly DispatcherTimer _timer;

        // rolling window of candidate markers
        private readonly LinkedList<(double lat, double lon, string label)> _recent = new();

        public MapUpdateService(WorldMapControl map,
                                TrafficCaptureService capture,
                                GeoIpService geo,
                                Dispatcher? dispatcher = null)
        {
            _map = map ?? throw new ArgumentNullException(nameof(map));
            _capture = capture ?? throw new ArgumentNullException(nameof(capture));
            _geo = geo ?? throw new ArgumentNullException(nameof(geo));
            _dispatcher = dispatcher ?? (Application.Current?.Dispatcher ?? Dispatcher.CurrentDispatcher);

            _ch = Channel.CreateBounded<TrafficRecord>(new BoundedChannelOptions(4096)
            {
                FullMode = BoundedChannelFullMode.Wait,
                SingleReader = true,
                SingleWriter = false
            });

            _capture.TrafficRecordReceived += OnRecord;

            _timer = new DispatcherTimer(DispatcherPriority.Background, _dispatcher)
            {
                Interval = TICK
            };
            _timer.Tick += async (_, __) => await DrainAsync();
            _timer.Start();

            _ = Task.Run(BackgroundPumpAsync, _cts.Token);
        }

        public void Dispose()
        {
            try { _timer.Stop(); } catch { }
            _capture.TrafficRecordReceived -= OnRecord;
            _cts.Cancel();
        }

        private void OnRecord(TrafficRecord r)
        {
            _ = _ch.Writer.WriteAsync(r, _cts.Token).AsTask();
        }

        private async Task BackgroundPumpAsync()
        {
            var reader = _ch.Reader;
            while (await reader.WaitToReadAsync(_cts.Token).ConfigureAwait(false))
            {
                while (reader.TryRead(out var rec))
                {
                    EnsureGeo(rec);
                    // ✅ append to rolling window so DrainAsync has something to render
                    OfferToRecent(rec);
                }
            }
        }

        /// <summary>One-shot snapshot render (e.g., buffered history).</summary>
        public void RenderSnapshot(IEnumerable<TrafficRecord> records, int max = 500)
        {
            if (records is null) return;

            int added = 0;
            foreach (var r in records)
            {
                if (added >= max) break;
                EnsureGeo(r);
                OfferToRecent(r);
                added++;
            }
        }

        private void EnsureGeo(TrafficRecord r)
        {
            // look up both sides if missing
            if ((r.SrcLat is null || r.SrcLon is null || string.IsNullOrEmpty(r.SrcCountryIso2)) && !string.IsNullOrWhiteSpace(r.Source))
            {
                var g = _geo.Lookup(r.Source);
                if (g is not null)
                {
                    r.SrcCountry ??= g.CountryName;
                    r.SrcCountryIso2 ??= g.CountryIso2;
                    r.SrcLat ??= g.Latitude;
                    r.SrcLon ??= g.Longitude;
                }
            }
            if ((r.DstLat is null || r.DstLon is null || string.IsNullOrEmpty(r.DstCountryIso2)) && !string.IsNullOrWhiteSpace(r.Destination))
            {
                var g = _geo.Lookup(r.Destination);
                if (g is not null)
                {
                    r.DstCountry ??= g.CountryName;
                    r.DstCountryIso2 ??= g.CountryIso2;
                    r.DstLat ??= g.Latitude;
                    r.DstLon ??= g.Longitude;
                }
            }
        }

        public void OfferToRecent(TrafficRecord r)
        {
            if (r.SrcLat is double sla && r.SrcLon is double slo)
            {
                var label = BuildLabel(r.Source, r.SrcCountryIso2, r.SrcCountry);
                _recent.AddLast((sla, slo, label));
            }

            if (r.DstLat is double dla && r.DstLon is double dlo)
            {
                var label = BuildLabel(r.Destination, r.DstCountryIso2, r.DstCountry);
                _recent.AddLast((dla, dlo, label));
            }

            while (_recent.Count > MAX_MARKERS_ON_MAP * 2)
                _recent.RemoveFirst();
        }

        private static string BuildLabel(string? ip, string? iso2, string? country)
        {
            var cc = string.IsNullOrWhiteSpace(iso2) ? "?" : iso2;
            return string.IsNullOrWhiteSpace(country) ? $"{ip} • {cc}" : $"{ip} • {cc} • {country}";
        }

        private async Task DrainAsync()
        {
            if (_recent.Count == 0) return;

            // take the newest up to BATCH_SIZE
            var take = Math.Min(BATCH_SIZE, _recent.Count);
            var items = new List<(double lat, double lon, string label)>(take);

            var node = _recent.Last;
            for (int i = 0; i < take && node != null; i++, node = node.Previous)
                items.Add(node.Value);

            items.Reverse();

            await _dispatcher.InvokeAsync(() =>
            {
                // thin hard when too many
                if (_recent.Count > MAX_MARKERS_ON_MAP)
                {
                    _map.ClearMarkers();
                    // don’t clear _recent; we’ll re-add from it progressively
                }

                foreach (var (lat, lon, label) in items)
                    _map.AddMarker(new WorldMapControl.GeoMarker(lat, lon, label, 6));
            }, DispatcherPriority.Background);
        }
    }
}
