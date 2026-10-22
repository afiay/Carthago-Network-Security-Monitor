using System;
using System.Linq;
using System.Windows;
using Carthago.Models;

namespace Carthago
{
    public partial class MainWindow
    {
        private void CaptureService_TrafficRecordReceived(TrafficRecord record)
        {
            Dispatcher.Invoke(() =>
            {
                _traffic.Insert(0, record);
                if (_traffic.Count > 200)
                    _traffic.RemoveAt(_traffic.Count - 1);

                _ppsBucket++;
                _bytesBucket += Math.Max(0, record.Length);

                var proto = string.IsNullOrWhiteSpace(record.Protocol) ? "Unknown" : record.Protocol.ToUpperInvariant();
                if (!_protocolCounts.ContainsKey(proto))
                    _protocolCounts[proto] = 0;
                _protocolCounts[proto]++;
                RenderProtocol();

                if (!string.IsNullOrWhiteSpace(record.Source))
                {
                    if (!_talkerCounts.ContainsKey(record.Source))
                        _talkerCounts[record.Source] = 0;
                    _talkerCounts[record.Source]++;

                    _hostLastSeen[record.Source] = DateTime.UtcNow;
                    string connKey = $"{record.Source}>{record.Destination}:{(record.DestinationPort?.ToString() ?? "-")}";
                    _connLastSeen[connKey] = DateTime.UtcNow;

                    RenderTopTalkers();
                }
            });
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
                RenderSeverity();
                RefreshDashboardLayoutFromPreferences();
            });
        }
    }
}
