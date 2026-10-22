// SPDX-License-Identifier: MIT
// File: Views/MainWindow.AnalyticsMap.cs
using Carthago.Services;
using Carthago.Services.Geo;

namespace Carthago
{
    public partial class MainWindow
    {
        private TrafficMapService? _trafficMapSvc;
        private GeoIpService? _geo;

        /// Call when the Analytics view/tab becomes visible (or right after the window is loaded).
        public void OnAnalyticsShown()
        {
            TryInitMapService();
        }

        // Bring up the streaming overlay once WorldMap and the (already-created) _captureService exist.
        private void TryInitMapService()
        {
            // _captureService is the readonly field you already have in MainWindow.Core.cs
            if (WorldMap is null || _captureService is null || _trafficMapSvc is not null)
                return;

            _geo ??= new GeoIpService(); // expects ./Data/GeoLite2-City.mmdb (ASN optional)
            _trafficMapSvc = new TrafficMapService(
                map: WorldMap,
                capture: _captureService,
                geo: _geo,
                ui: Dispatcher,
                maxMarkers: 2500);

            WorldMap.ShowGraticule = true;
        }
    }
}
