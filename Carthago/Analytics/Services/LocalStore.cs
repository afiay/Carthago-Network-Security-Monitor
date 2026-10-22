// SPDX-License-Identifier: MIT
// File: Analytics/Services/LocalStore.cs
using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using Carthago.Analytics.Models;
using Carthago.Models;
using LiteDB;

namespace Carthago.Analytics.Services
{
    public sealed class LocalStore : IDisposable
    {
        private const int DefaultIncidentRetentionCount = 400;
        private const int DefaultAnomalyRetentionCount = 4000;
        private const int DefaultBaselineRetentionDays = 30;

        private readonly LiteDatabase _db;
        private readonly ILiteCollection<BaselineSnapshot> _baselines;
        private readonly ILiteCollection<Incident> _incidents;
        private readonly ILiteCollection<AnomalySignal> _anomalies;
        private static readonly IncidentTimelineBuilder TimelineBuilder = new();
        private DateTime _lastIncidentPruneUtc = DateTime.MinValue;
        private DateTime _lastAnomalyPruneUtc = DateTime.MinValue;
        private DateTime _lastBaselinePruneUtc = DateTime.MinValue;

        public LocalStore(string? path = null)
        {
            path ??= Path.Combine(
                Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData),
                "Carthago",
                "analytics.db");

            Directory.CreateDirectory(Path.GetDirectoryName(path)!);
            _db = OpenDatabase(path);
            _baselines = _db.GetCollection<BaselineSnapshot>("baseline_snapshots");
            _incidents = _db.GetCollection<Incident>("incidents");
            _anomalies = _db.GetCollection<AnomalySignal>("anomalies");

            _baselines.EnsureIndex(x => x.HostId, true);
            _baselines.EnsureIndex(x => x.LastUpdatedUtc);
            _incidents.EnsureIndex(x => x.Id, true);
            _incidents.EnsureIndex(x => x.UpdatedUtc);
            _incidents.EnsureIndex(x => x.LastSeenUtc);
            _anomalies.EnsureIndex(x => x.Id, true);
            _anomalies.EnsureIndex(x => x.UpdatedUtc);
            _anomalies.EnsureIndex(x => x.CreatedUtc);
        }

        public IReadOnlyList<Incident> LoadIncidents(int limit = 200)
        {
            try
            {
                return _incidents.Query()
                    .OrderByDescending(x => x.UpdatedUtc)
                    .Limit(Math.Max(1, limit))
                    .ToList()
                    .Select(NormalizeIncident)
                    .ToList();
            }
            catch (Exception ex)
            {
                Console.Error.WriteLine($"[LocalStore] Failed to load incidents: {ex.Message}");
                return Array.Empty<Incident>();
            }
        }

        public IReadOnlyList<AnomalySignal> LoadAnomalies(int limit = 500)
        {
            try
            {
                return _anomalies.Query()
                    .OrderByDescending(x => x.UpdatedUtc)
                    .Limit(Math.Max(1, limit))
                    .ToList()
                    .Select(NormalizeAnomaly)
                    .ToList();
            }
            catch (Exception ex)
            {
                Console.Error.WriteLine($"[LocalStore] Failed to load anomalies: {ex.Message}");
                return Array.Empty<AnomalySignal>();
            }
        }

        public IReadOnlyList<BaselineSnapshot> LoadBaselineSnapshots()
        {
            try
            {
                return _baselines.Query()
                    .OrderByDescending(x => x.LastUpdatedUtc)
                    .ToList()
                    .Select(NormalizeBaselineSnapshot)
                    .ToList();
            }
            catch (Exception ex)
            {
                Console.Error.WriteLine($"[LocalStore] Failed to load baselines: {ex.Message}");
                return Array.Empty<BaselineSnapshot>();
            }
        }

        public void SaveIncident(Incident incident)
        {
            if (incident == null) return;

            try
            {
                _incidents.Upsert(NormalizeIncident(incident));
                PruneIncidentsIfNeeded();
            }
            catch (Exception ex)
            {
                Console.Error.WriteLine($"[LocalStore] Failed to save incident {incident.Id}: {ex.Message}");
            }
        }

        public void SaveAnomaly(AnomalySignal anomaly)
        {
            if (anomaly == null) return;

            try
            {
                _anomalies.Upsert(NormalizeAnomaly(anomaly));
                PruneAnomaliesIfNeeded();
            }
            catch (Exception ex)
            {
                Console.Error.WriteLine($"[LocalStore] Failed to save anomaly {anomaly.Id}: {ex.Message}");
            }
        }

        public void SaveBaselineSnapshots(IEnumerable<BaselineSnapshot> snapshots)
        {
            if (snapshots == null) return;

            try
            {
                foreach (var snapshot in snapshots)
                {
                    if (snapshot == null || string.IsNullOrWhiteSpace(snapshot.HostId))
                        continue;

                    _baselines.Upsert(NormalizeBaselineSnapshot(snapshot));
                }

                PruneBaselinesIfNeeded();
            }
            catch (Exception ex)
            {
                Console.Error.WriteLine($"[LocalStore] Failed to save baseline snapshots: {ex.Message}");
            }
        }

        public void UpdateIncidentSummary(string id, string summary)
        {
            try
            {
                var incident = _incidents.FindById(id);
                if (incident == null) return;

                incident.Summary = summary;
                incident.UpdatedUtc = DateTime.UtcNow;
                incident.IsAnalyzing = false;
                _incidents.Update(incident);
            }
            catch (Exception ex)
            {
                Console.Error.WriteLine($"[LocalStore] Failed to update summary for {id}: {ex.Message}");
            }
        }

        public void UpdateIncidentStatus(string id, string status)
        {
            try
            {
                var incident = _incidents.FindById(id);
                if (incident == null) return;

                incident.Status = status;
                incident.UpdatedUtc = DateTime.UtcNow;
                _incidents.Update(incident);
            }
            catch (Exception ex)
            {
                Console.Error.WriteLine($"[LocalStore] Failed to update status for {id}: {ex.Message}");
            }
        }

        public void DeleteIncidents(Func<Incident, bool> predicate)
        {
            if (predicate == null)
                return;

            try
            {
                foreach (var incident in _incidents.Query().ToList().Where(predicate).ToList())
                    _incidents.Delete(incident.Id);
            }
            catch (Exception ex)
            {
                Console.Error.WriteLine($"[LocalStore] Failed to delete incidents: {ex.Message}");
            }
        }

        public void DeleteAnomalies(Func<AnomalySignal, bool> predicate)
        {
            if (predicate == null)
                return;

            try
            {
                foreach (var anomaly in _anomalies.Query().ToList().Where(predicate).ToList())
                    _anomalies.Delete(anomaly.Id);
            }
            catch (Exception ex)
            {
                Console.Error.WriteLine($"[LocalStore] Failed to delete anomalies: {ex.Message}");
            }
        }

        public void Dispose()
        {
            try
            {
                _db.Dispose();
            }
            catch (Exception ex)
            {
                Console.Error.WriteLine($"[LocalStore] Dispose failed: {ex.Message}");
            }
        }

        private void PruneIncidentsIfNeeded()
        {
            if (DateTime.UtcNow - _lastIncidentPruneUtc < TimeSpan.FromMinutes(5))
                return;

            PruneIncidents();
            _lastIncidentPruneUtc = DateTime.UtcNow;
        }

        private void PruneIncidents()
        {
            var items = _incidents.Query()
                .OrderByDescending(x => x.UpdatedUtc)
                .ToList();

            foreach (var stale in items.Skip(DefaultIncidentRetentionCount))
                _incidents.Delete(stale.Id);
        }

        private void PruneAnomaliesIfNeeded()
        {
            if (DateTime.UtcNow - _lastAnomalyPruneUtc < TimeSpan.FromMinutes(5))
                return;

            PruneAnomalies();
            _lastAnomalyPruneUtc = DateTime.UtcNow;
        }

        private void PruneAnomalies()
        {
            var items = _anomalies.Query()
                .OrderByDescending(x => x.UpdatedUtc)
                .ToList();

            foreach (var stale in items.Skip(DefaultAnomalyRetentionCount))
                _anomalies.Delete(stale.Id);
        }

        private void PruneBaselinesIfNeeded()
        {
            if (DateTime.UtcNow - _lastBaselinePruneUtc < TimeSpan.FromHours(6))
                return;

            PruneBaselines();
            _lastBaselinePruneUtc = DateTime.UtcNow;
        }

        private void PruneBaselines()
        {
            var cutoff = DateTime.UtcNow.AddDays(-DefaultBaselineRetentionDays);
            foreach (var stale in _baselines.Query().Where(x => x.LastUpdatedUtc < cutoff).ToList())
                _baselines.Delete(stale.HostId);
        }

        private static Incident NormalizeIncident(Incident incident)
        {
            incident.Id = string.IsNullOrWhiteSpace(incident.Id) ? Guid.NewGuid().ToString("N") : incident.Id;
            incident.Title ??= string.Empty;
            incident.Severity = string.IsNullOrWhiteSpace(incident.Severity) ? "Low" : incident.Severity;
            incident.Category = string.IsNullOrWhiteSpace(incident.Category) ? "Behavior" : incident.Category;
            incident.Status = string.IsNullOrWhiteSpace(incident.Status) ? "New" : incident.Status;
            incident.FirstSeenUtc = NormalizeUtc(incident.FirstSeenUtc == default ? incident.CreatedUtc : incident.FirstSeenUtc);
            incident.CreatedUtc = NormalizeUtc(incident.CreatedUtc);
            incident.UpdatedUtc = NormalizeUtc(incident.UpdatedUtc == default ? incident.CreatedUtc : incident.UpdatedUtc);
            incident.LastSeenUtc = NormalizeUtc(incident.LastSeenUtc == default ? incident.UpdatedUtc : incident.LastSeenUtc);
            incident.OccurrenceCount = Math.Max(1, incident.OccurrenceCount);
            incident.RelatedEvents ??= new List<DetectionEvent>();
            incident.RelatedAnomalies = (incident.RelatedAnomalies ?? new List<AnomalySignal>())
                .Select(NormalizeAnomaly)
                .ToList();
            incident.Evidence = (incident.Evidence ?? new List<string>())
                .Where(value => !string.IsNullOrWhiteSpace(value))
                .Distinct(StringComparer.OrdinalIgnoreCase)
                .ToList();
            incident.RecommendedActions = (incident.RecommendedActions ?? new List<string>())
                .Where(value => !string.IsNullOrWhiteSpace(value))
                .Distinct(StringComparer.OrdinalIgnoreCase)
                .ToList();
            incident.Tags = (incident.Tags ?? new List<string>())
                .Where(value => !string.IsNullOrWhiteSpace(value))
                .Distinct(StringComparer.OrdinalIgnoreCase)
                .ToList();
            incident.RiskReasons = (incident.RiskReasons ?? new List<string>())
                .Where(value => !string.IsNullOrWhiteSpace(value))
                .Distinct(StringComparer.OrdinalIgnoreCase)
                .ToList();
            incident.TimelineItems = (incident.TimelineItems ?? new List<IncidentTimelineItem>())
                .Where(item => item != null)
                .ToList();
            incident.FeedbackAppliedReasons = (incident.FeedbackAppliedReasons ?? new List<string>())
                .Where(value => !string.IsNullOrWhiteSpace(value))
                .Distinct(StringComparer.OrdinalIgnoreCase)
                .ToList();
            incident.AnalystFeedbackType = string.IsNullOrWhiteSpace(incident.AnalystFeedbackType) ? null : incident.AnalystFeedbackType;
            incident.AnalystNote = string.IsNullOrWhiteSpace(incident.AnalystNote) ? null : incident.AnalystNote.Trim();
            incident.LastFeedbackUtc = incident.LastFeedbackUtc.HasValue ? NormalizeUtc(incident.LastFeedbackUtc.Value) : null;
            incident.SuppressedUntilUtc = incident.SuppressedUntilUtc.HasValue ? NormalizeUtc(incident.SuppressedUntilUtc.Value) : null;
            incident.IsSuppressed = incident.SuppressedUntilUtc.HasValue && incident.SuppressedUntilUtc.Value > DateTime.UtcNow
                ? incident.IsSuppressed
                : false;
            if (!incident.IsSuppressed && incident.SuppressedUntilUtc.HasValue && incident.SuppressedUntilUtc.Value <= DateTime.UtcNow)
                incident.SuppressedUntilUtc = null;
            incident.RiskScore = Math.Clamp(incident.RiskScore, 0, 100);
            TimelineBuilder.NormalizeTimeline(incident);
            return incident;
        }

        private static AnomalySignal NormalizeAnomaly(AnomalySignal anomaly)
        {
            anomaly.Id = string.IsNullOrWhiteSpace(anomaly.Id) ? Guid.NewGuid().ToString("N") : anomaly.Id;
            anomaly.SourceIp ??= string.Empty;
            anomaly.Category ??= string.Empty;
            anomaly.Title ??= string.Empty;
            anomaly.Description ??= string.Empty;
            anomaly.Severity = string.IsNullOrWhiteSpace(anomaly.Severity) ? "medium" : anomaly.Severity;
            anomaly.CreatedUtc = NormalizeUtc(anomaly.CreatedUtc);
            anomaly.UpdatedUtc = NormalizeUtc(anomaly.UpdatedUtc == default ? anomaly.CreatedUtc : anomaly.UpdatedUtc);
            anomaly.Score = double.IsFinite(anomaly.Score) ? Math.Clamp(anomaly.Score, 0, 1) : 0;
            anomaly.Reasons = (anomaly.Reasons ?? new List<string>())
                .Where(value => !string.IsNullOrWhiteSpace(value))
                .Distinct(StringComparer.OrdinalIgnoreCase)
                .ToList();
            anomaly.RelatedRuleIds = (anomaly.RelatedRuleIds ?? new List<string>())
                .Where(value => !string.IsNullOrWhiteSpace(value))
                .Distinct(StringComparer.OrdinalIgnoreCase)
                .ToList();
            anomaly.Tags = (anomaly.Tags ?? new List<string>())
                .Where(value => !string.IsNullOrWhiteSpace(value))
                .Distinct(StringComparer.OrdinalIgnoreCase)
                .ToList();
            anomaly.Features ??= new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);
            return anomaly;
        }

        private static BaselineSnapshot NormalizeBaselineSnapshot(BaselineSnapshot snapshot)
        {
            snapshot.HostId ??= string.Empty;
            snapshot.FirstSeenUtc = NormalizeUtc(snapshot.FirstSeenUtc);
            snapshot.LastSeenUtc = NormalizeUtc(snapshot.LastSeenUtc == default ? snapshot.FirstSeenUtc : snapshot.LastSeenUtc);
            snapshot.LastUpdatedUtc = NormalizeUtc(snapshot.LastUpdatedUtc == default ? snapshot.LastSeenUtc : snapshot.LastUpdatedUtc);
            snapshot.Confidence = string.IsNullOrWhiteSpace(snapshot.Confidence) ? "Low" : snapshot.Confidence;
            snapshot.WindowMinutes = Math.Max(1, snapshot.WindowMinutes);
            snapshot.ObservationWindows = Math.Max(0, snapshot.ObservationWindows);
            snapshot.OutboundBytesMean = SanitizeNumber(snapshot.OutboundBytesMean);
            snapshot.OutboundBytesStdDev = Math.Max(0, SanitizeNumber(snapshot.OutboundBytesStdDev));
            snapshot.UniqueDestinationMean = SanitizeNumber(snapshot.UniqueDestinationMean);
            snapshot.UniqueDestinationStdDev = Math.Max(0, SanitizeNumber(snapshot.UniqueDestinationStdDev));
            snapshot.UniquePortMean = SanitizeNumber(snapshot.UniquePortMean);
            snapshot.UniquePortStdDev = Math.Max(0, SanitizeNumber(snapshot.UniquePortStdDev));
            snapshot.DnsQueryMean = SanitizeNumber(snapshot.DnsQueryMean);
            snapshot.DnsQueryStdDev = Math.Max(0, SanitizeNumber(snapshot.DnsQueryStdDev));
            snapshot.SeverityWeightedAlertMean = SanitizeNumber(snapshot.SeverityWeightedAlertMean);
            snapshot.SeverityWeightedAlertStdDev = Math.Max(0, SanitizeNumber(snapshot.SeverityWeightedAlertStdDev));
            snapshot.KnownDestinations ??= new List<string>();
            snapshot.KnownPorts ??= new List<string>();
            snapshot.KnownCountries ??= new List<string>();
            snapshot.KnownAsns ??= new List<string>();
            snapshot.KnownJa4Fingerprints ??= new List<string>();
            snapshot.KnownHasshFingerprints ??= new List<string>();
            snapshot.KnownProcesses ??= new List<string>();
            return snapshot;
        }

        private static DateTime NormalizeUtc(DateTime value)
        {
            if (value == default)
                return DateTime.UtcNow;

            return value.Kind switch
            {
                DateTimeKind.Utc => value,
                DateTimeKind.Local => value.ToUniversalTime(),
                _ => DateTime.SpecifyKind(value, DateTimeKind.Utc)
            };
        }

        private static double SanitizeNumber(double value)
            => double.IsFinite(value) ? value : 0;

        private static LiteDatabase OpenDatabase(string path)
        {
            try
            {
                return new LiteDatabase(path);
            }
            catch (Exception ex)
            {
                Console.Error.WriteLine($"[LocalStore] Analytics DB open failed, recreating store: {ex.Message}");
                TryBackupCorruptFile(path);
                return new LiteDatabase(path);
            }
        }

        private static void TryBackupCorruptFile(string path)
        {
            try
            {
                if (!File.Exists(path))
                    return;

                var backup = path + ".corrupt-" + DateTime.UtcNow.ToString("yyyyMMddHHmmss");
                File.Move(path, backup, overwrite: true);
            }
            catch
            {
                try { File.Delete(path); } catch { }
            }
        }
    }
}
