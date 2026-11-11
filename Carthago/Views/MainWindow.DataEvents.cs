using System;
using System.Linq;
using System.Collections.Generic;
using System.Windows;
using Carthago.Models;
using Carthago.Services;

namespace Carthago
{
    public partial class MainWindow
    {
        private void CaptureService_TrafficBatchReceived(IReadOnlyList<TrafficRecord> records)
            => UiOperationProfiler.Measure("TrafficGridBatch", () => ApplyTrafficBatch(records));

        private void ApplyTrafficBatch(IReadOnlyList<TrafficRecord> records)
        {
            if (records.Count == 0)
                return;

            // Keep all record aggregation independent of the grid redraw cadence.
            // Capture batches are delivered on the UI dispatcher.
            UiOperationProfiler.Measure("TrafficBatchAggregate", () =>
            {
                foreach (var record in records)
                {
                    _ppsBucket++;
                    _bytesBucket += Math.Max(0, record.Length);

                    var proto = string.IsNullOrWhiteSpace(record.Protocol) ? "Unknown" : record.Protocol.ToUpperInvariant();
                    if (!_protocolCounts.ContainsKey(proto))
                        _protocolCounts[proto] = 0;
                    _protocolCounts[proto]++;
                    _protocolChartDirty = true;

                    if (!string.IsNullOrWhiteSpace(record.Source))
                    {
                        if (!_talkerCounts.ContainsKey(record.Source))
                            _talkerCounts[record.Source] = 0;
                        _talkerCounts[record.Source]++;

                        _hostLastSeen[record.Source] = DateTime.UtcNow;
                        string connKey = $"{record.Source}>{record.Destination}:{(record.DestinationPort?.ToString() ?? "-")}";
                        _connLastSeen[connKey] = DateTime.UtcNow;

                        _talkerChartDirty = true;
                    }
                }
            });

            // Preserve the newest 200 rows on every batch, even while hidden.
            // Only the WPF collection-reset notification is rate-limited.
            UiOperationProfiler.Measure("TrafficGridRetain", () =>
                _traffic.PrependBatch(records, 200, notifyCollectionChanged: false));

            if (_trafficGridRefresh.Request(LiveTrafficView.Visibility == Visibility.Visible))
                _trafficGridRefreshTimer.Start();
        }

        private void TrafficGridRefreshTimerTick(object? sender, EventArgs e)
        {
            _trafficGridRefreshTimer.Stop();
            if (_trafficGridRefresh.OnTimer(LiveTrafficView.Visibility == Visibility.Visible))
                UiOperationProfiler.Measure("TrafficGridNotify", _traffic.NotifyReset);
        }

        private void SuspendTrafficGridRefresh()
        {
            _trafficGridRefreshTimer.Stop();
            _trafficGridRefresh.Hide();
        }

        private void RefreshTrafficGridOnShow()
        {
            _trafficGridRefreshTimer.Stop();
            if (_trafficGridRefresh.Show())
                UiOperationProfiler.Measure("TrafficGridNotify", _traffic.NotifyReset);
        }

        private void CaptureService_DetectionEventRaised(DetectionEvent evt)
        {
            Dispatcher.Invoke(() =>
            {
                _alerts.Insert(0, evt);
                if (_alerts.Count > 500)
                    _alerts.RemoveAt(_alerts.Count - 1);

                var sev = evt.Severity.ToString();
                if (!_severityCounts.ContainsKey(sev))
                    _severityCounts[sev] = 0;
                _severityCounts[sev]++;
                _severityChartDirty = true;
                RequestDashboardAnalyticsRefresh(DashboardAnalyticsRefreshKind.All);
            });
        }
    }
}
