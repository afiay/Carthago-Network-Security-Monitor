// SPDX-License-Identifier: MIT
// SOURCE CANDIDATE — UNVERIFIED; TESTS AUTHORED — 0 EXECUTED.
using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Threading.Tasks;
using System.Windows;
using System.Windows.Input;
using Carthago.Analytics.Models;
using Carthago.Models;
using Carthago.Services.SessionFiles;
using Microsoft.Win32;

namespace Carthago;

public partial class MainWindow
{
    private readonly CarthagoSessionArchiveService _sessionArchiveService = new();
    private readonly CarthagoExcelExportService _excelExportService = new();
    private string? _lastSavedLiveSessionPath;
    private bool _fileOperationInProgress;

    private void MainWindow_SessionFileKeyDown(object sender, KeyEventArgs e)
    {
        if (e.Key == Key.O && Keyboard.Modifiers == ModifierKeys.Control)
        {
            e.Handled = true;
            FileOpen_Click(sender, e);
        }
        else if (e.Key == Key.S && Keyboard.Modifiers == ModifierKeys.Control)
        {
            e.Handled = true;
            FileSave_Click(sender, e);
        }
        else if (e.Key == Key.S && Keyboard.Modifiers == (ModifierKeys.Control | ModifierKeys.Shift))
        {
            e.Handled = true;
            FileSaveAs_Click(sender, e);
        }
    }

    private async void FileOpen_Click(object sender, RoutedEventArgs e)
    {
        var dialog = new OpenFileDialog
        {
            Title = "Open Carthago analysis session",
            Filter = "Carthago Session Archive (*.csa)|*.csa",
            CheckFileExists = true
        };
        if (dialog.ShowDialog(this) != true) return;
        await RunFileOperationAsync(async () =>
        {
            var snapshot = await _sessionArchiveService.OpenAsync(dialog.FileName);
            // Opened session becomes the active manual Save destination.
            // Historical rows are retained by the merger, never trusted as live evidence.
            _lastSavedLiveSessionPath = dialog.FileName;
            SessionArchiveContent.Content = new CarthagoSessionViewerControl(
                snapshot,
                Path.GetFileName(dialog.FileName));
            ShowView(SessionArchiveView);
            SidebarPanel?.HideAllFilters();
            // Opening never imports archived telemetry into the live rule engine.
        });
    }

    private async void FileSave_Click(object sender, RoutedEventArgs e)
    {
        string? path = _lastSavedLiveSessionPath ?? AskSessionSavePath();
        if (path != null) await SaveLiveSessionAsync(path);
    }

    private async void FileSaveAs_Click(object sender, RoutedEventArgs e)
    {
        string? path = AskSessionSavePath();
        if (path != null) await SaveLiveSessionAsync(path);
    }

    private async void FileExportExcel_Click(object sender, RoutedEventArgs e)
    {
        var consent = MessageBox.Show(this,
            "Export the available local analysis snapshot to Excel?\n\n" +
            "The workbook can include IP addresses, detection descriptions, incident notes and other sensitive free text. " +
            "Known marked-sensitive evidence is redacted, but automatic redaction cannot guarantee that all free text is safe to share. " +
            "Traffic and detections are limited to retained UI rows; this is not a complete capture or incident archive.\n\n" +
            "Review the workbook before distributing it.",
            "Review local analysis export scope", MessageBoxButton.YesNo, MessageBoxImage.Warning,
            MessageBoxResult.No);
        if (consent != MessageBoxResult.Yes) return;

        var dialog = new SaveFileDialog
        {
            Title = "Export Carthago analysis to Excel",
            Filter = "Excel workbook (*.xlsx)|*.xlsx",
            DefaultExt = ".xlsx",
            AddExtension = true,
            FileName = $"carthago-analysis-{DateTime.UtcNow:yyyyMMdd-HHmmss}.xlsx"
        };
        if (dialog.ShowDialog(this) != true) return;
        await RunFileOperationAsync(async () =>
        {
            var snapshot = await CaptureAvailableAnalysisAsync();
            await _excelExportService.ExportAsync(dialog.FileName, snapshot);
            MessageBox.Show(this,
                "Excel export saved with a separate worksheet for each analysis category. " +
                "It contains available analyzed data, not raw packets or a complete capture history. " +
                "Review the Overview sheet for coverage limitations.",
                "Carthago export", MessageBoxButton.OK, MessageBoxImage.Information);
        });
    }

    internal void OpenAvailableAnalysisExport()
        => FileExportExcel_Click(this, new RoutedEventArgs());

    private string? AskSessionSavePath()
    {
        var dialog = new SaveFileDialog
        {
            Title = "Save Carthago analysis session",
            Filter = "Carthago Session Archive (*.csa)|*.csa",
            DefaultExt = ".csa",
            AddExtension = true,
            FileName = $"carthago-session-{DateTime.UtcNow:yyyyMMdd-HHmmss}.csa"
        };
        return dialog.ShowDialog(this) == true ? dialog.FileName : null;
    }

    private async Task SaveLiveSessionAsync(string destination)
    {
        await RunFileOperationAsync(async () =>
        {
            var snapshot = await CaptureAvailableAnalysisAsync();
            string? activePath = _lastSavedLiveSessionPath;
            if (activePath is not null && File.Exists(activePath))
            {
                var existing = await _sessionArchiveService.OpenAsync(activePath);
                snapshot = await Task.Run(() => CarthagoSessionSnapshotMerger.Merge(existing, snapshot));
            }
            await _sessionArchiveService.SaveAsync(destination, snapshot);
            _lastSavedLiveSessionPath = destination;
            MessageBox.Show(this,
                "Session saved as .csa, preserving distinct records from the active session. " +
                "It is not a raw PCAP or proof of lossless packet history. " +
                "Coverage limitations are recorded in the archive.",
                "Carthago session", MessageBoxButton.OK, MessageBoxImage.Information);
        });
    }

    private async Task RunFileOperationAsync(Func<Task> operation)
    {
        if (_fileOperationInProgress)
        {
            MessageBox.Show(this, "Another file operation is still running.", "Carthago", MessageBoxButton.OK, MessageBoxImage.Information);
            return;
        }
        _fileOperationInProgress = true;
        try { await operation(); }
        catch (Exception exception)
        {
            MessageBox.Show(this, $"File operation failed: {exception.Message}", "Carthago", MessageBoxButton.OK, MessageBoxImage.Error);
        }
        finally { _fileOperationInProgress = false; }
    }

    private Task<CarthagoSessionSnapshot> CaptureAvailableAnalysisAsync()
    {
        // Must be called on the WPF dispatcher. Snapshot source collections only;
        // never replay them as trusted producer events or mutate active capture.
        Dispatcher.VerifyAccess();
        TrafficRecord[] traffic = _traffic.GetRetainedSnapshot().ToArray();
        DetectionEvent[] alerts = _alerts.ToArray();
        Incident[] incidents = _sinkHost?.Analytics.GetRecentIncidents(1000).ToArray() ?? Array.Empty<Incident>();
        AnomalySignal[] anomalies = _sinkHost?.Analytics.GetRecentAnomalies(1000).ToArray() ?? Array.Empty<AnomalySignal>();
        var stats = _captureService.GetStats();
        var baseline = _sinkHost?.Analytics.GetBaselineStatus();
        var hosts = _hostLastSeen.Select(kv => new { Host = kv.Key, LastSeenUtc = kv.Value }).ToArray();

        // JSON conversion and redaction happen off the dispatcher. No per-packet
        // persistence hooks or expensive work are added to the capture hot path.
        return Task.Run(() =>
        {
            var snapshot = CarthagoSessionSnapshot.CreateEmpty();
            snapshot.Limitations.Add("Traffic comes from the 200-row live UI window, not a raw PCAP or a lossless packet archive.");
            snapshot.Limitations.Add("Alerts come from the 500-row live UI window; older journal entries are not included.");
            snapshot.Limitations.Add("Incidents and anomalies are limited to up to 1,000 cached records each.");
            snapshot.Limitations.Add("Baselines include current aggregate status, not the complete historical per-host baseline database.");
            snapshot.Limitations.Add("Rules contains the full registered detection catalog; ObservedEvents/MostRecentUtc are limited to the retained recent-alert window.");
            snapshot.Limitations.Add("Blank Excel cells mean the source value was null, empty or absent. Protocol-specific blanks are often not applicable; Unknown/0 process attribution means unavailable; [REDACTED] means intentionally removed.");
            snapshot.Limitations.Add("The exported analysis is a point-in-time snapshot; in-flight queues may not yet be reflected.");
            snapshot.Limitations.Add("Known sensitive fields and explicitly marked sensitive evidence values are redacted; inspect free-text fields before sharing.");
            CarthagoRuleCatalogRow[] ruleRows = CarthagoRuleCatalogExport.Build(alerts).ToArray();
            snapshot.AddRows("Overview", new[]
            {
                new
                {
                    CapturedAtUtc = snapshot.CreatedUtc,
                    Source = snapshot.Origin,
                    FileFormat = "CSA v1 / XLSX",
                    TrafficRows = traffic.Length,
                    AlertRows = alerts.Length,
                    IncidentRows = incidents.Length,
                    AnomalyRows = anomalies.Length,
                    RegisteredRuleRows = ruleRows.Length,
                    stats.PacketsCaptured,
                    stats.PacketsParsedOk,
                    stats.PacketsParseErrors,
                    stats.PacketsDroppedByQueue,
                    stats.RuleEventsRaised,
                    Coverage = "Recent UI and analytics-cache snapshot; not exhaustive history",
                    Limitations = string.Join(" | ", snapshot.Limitations)
                }
            });
            snapshot.AddRows("Traffic", traffic);
            snapshot.AddRows("Alerts", alerts);
            snapshot.AddRows("Incidents", incidents);
            snapshot.AddRows("Anomalies", anomalies);
            snapshot.AddRows("Hosts", hosts);
            if (baseline != null) snapshot.AddRows("Baselines", new[] { baseline });
            snapshot.AddRows("Evidence", alerts
                .Where(a => a.StructuredEvidence != null)
                .SelectMany(a => a.StructuredEvidence!.Items.Select(item => new
                {
                    a.EventId, a.RuleId, item.Key, item.Value, item.Source, item.IsSensitive
                })));
            snapshot.AddRows("Timeline", incidents.SelectMany(i => i.TimelineItems.Select(t => new
            {
                IncidentId = i.Id,
                t.Id, t.TimestampUtc, t.Type, t.Title, t.Description, t.Severity,
                t.RiskScoreAfter, t.SourceIp, t.DestinationIp, t.DestinationHost,
                t.Category, t.Tags, t.Details
            })));
            snapshot.AddRows("Rules", ruleRows);
            snapshot.AddRows("Enrichment", traffic.Where(t =>
                t.ProcessId > 0
                || !string.IsNullOrWhiteSpace(t.ProcessName)
                || !string.IsNullOrWhiteSpace(t.NetworkType)
                || t.IsVpn != null
                || t.IsProxy != null
                || !string.IsNullOrWhiteSpace(t.SrcCountry)
                || !string.IsNullOrWhiteSpace(t.SrcCountryIso2)
                || t.SrcLat != null
                || t.SrcLon != null
                || !string.IsNullOrWhiteSpace(t.DstCountry)
                || !string.IsNullOrWhiteSpace(t.DstCountryIso2)
                || t.DstLat != null
                || t.DstLon != null
                || !string.IsNullOrWhiteSpace(t.WhoisOrganization)
                || t.ReputationScore != null)
                .Select(t => new
            {
                t.Id, t.Source, t.Destination,
                t.ProcessName, t.ProcessId, t.NetworkType, t.IsVpn, t.IsProxy,
                t.SrcCountry, t.SrcCountryIso2, t.SrcLat, t.SrcLon,
                t.DstCountry, t.DstCountryIso2, t.DstLat, t.DstLon,
                t.WhoisRegistrar, t.WhoisOrganization, t.WhoisCountry, t.WhoisASN, t.WhoisAbuseContact,
                t.ReputationIsMalicious, t.ReputationScore, t.ReputationReports, t.ReputationLastSeen
            }));
            return snapshot;
        });
    }
}
