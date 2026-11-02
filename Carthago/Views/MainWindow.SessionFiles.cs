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
            var viewer = new CarthagoSessionViewerWindow(snapshot)
            {
                Owner = this,
                Title = $"Carthago Session — {Path.GetFileName(dialog.FileName)}"
            };
            viewer.Show(); // Opening never imports archived telemetry into the live rule engine.
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
            await _sessionArchiveService.SaveAsync(destination, snapshot);
            _lastSavedLiveSessionPath = destination;
            MessageBox.Show(this,
                "Session saved as .csa. This is a snapshot of available analyzed data; " +
                "it is not a raw PCAP or a guarantee of complete capture history. " +
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
        TrafficRecord[] traffic = _traffic.ToArray();
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
            snapshot.Limitations.Add("Rules lists only rules present in recent alerts, not the full registered detection catalog.");
            snapshot.Limitations.Add("The exported analysis is a point-in-time snapshot; in-flight queues may not yet be reflected.");
            snapshot.Limitations.Add("Known sensitive fields and explicitly marked sensitive evidence values are redacted; inspect free-text fields before sharing.");
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
            snapshot.AddRows("Rules", alerts.GroupBy(a => a.RuleId, StringComparer.OrdinalIgnoreCase)
                .Select(group => new
                {
                    RuleId = group.Key,
                    RuleName = group.First().RuleName,
                    ObservedEvents = group.Count(),
                    MostRecentUtc = group.Max(a => a.TimestampUtc),
                    AlertEmissionsNotIndependentlyVerified = true
                }));
            snapshot.AddRows("Enrichment", traffic.Where(t =>
                !string.IsNullOrWhiteSpace(t.WhoisOrganization) || t.ReputationScore != null)
                .Select(t => new
            {
                t.Id, t.Source, t.Destination, t.WhoisRegistrar, t.WhoisOrganization,
                t.WhoisCountry, t.WhoisASN, t.WhoisAbuseContact,
                t.ReputationIsMalicious, t.ReputationScore, t.ReputationReports, t.ReputationLastSeen
            }));
            return snapshot;
        });
    }
}
