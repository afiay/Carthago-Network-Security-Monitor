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
            // The capture service delivers this on the UI dispatcher once per bounded batch.
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
            _traffic.PrependBatch(
                records,
                200,
                notifyCollectionChanged: LiveTrafficView.Visibility == Visibility.Visible);
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
