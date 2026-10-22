// SPDX-License-Identifier: MIT
using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Text.Json;
using Carthago.Analytics.Models;

namespace Carthago.Analytics.Services
{
    public sealed class IncidentFeedbackStore
    {
        private const int DefaultRetentionCount = 2000;
        private readonly string _path;
        private readonly JsonSerializerOptions _jsonOptions = new() { WriteIndented = true };
        private readonly object _gate = new();
        private List<IncidentFeedback> _entries;

        public IncidentFeedbackStore(string? path = null)
        {
            _path = path ?? Path.Combine(
                Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData),
                "Carthago",
                "incident-feedback.json");

            Directory.CreateDirectory(Path.GetDirectoryName(_path)!);
            _entries = LoadEntriesSafe(_path);
            CleanupExpiredSuppressions();
        }

        public IReadOnlyList<IncidentFeedback> GetAll()
        {
            lock (_gate)
                return _entries.Select(Clone).ToArray();
        }

        public IReadOnlyList<IncidentFeedback> GetMatchingFeedback(Incident incident, DateTime? nowUtc = null)
        {
            if (incident == null)
                return Array.Empty<IncidentFeedback>();

            var now = nowUtc ?? DateTime.UtcNow;
            lock (_gate)
            {
                CleanupExpiredSuppressionsLocked(now);
                return _entries
                    .Where(entry => MatchesIncident(entry, incident, now))
                    .Select(Clone)
                    .ToArray();
            }
        }

        public IncidentFeedback? GetLatestExactFeedback(string incidentId)
        {
            if (string.IsNullOrWhiteSpace(incidentId))
                return null;

            lock (_gate)
            {
                return _entries
                    .Where(entry => string.Equals(entry.IncidentId, incidentId, StringComparison.OrdinalIgnoreCase))
                    .OrderByDescending(entry => entry.CreatedUtc)
                    .Select(Clone)
                    .FirstOrDefault();
            }
        }

        public void SaveFeedback(IncidentFeedback feedback)
        {
            if (feedback == null || string.IsNullOrWhiteSpace(feedback.FeedbackType))
                return;

            lock (_gate)
            {
                NormalizeFeedback(feedback);

                var dedupeKey = GetSemanticKey(feedback);
                if (!string.IsNullOrWhiteSpace(dedupeKey) && IsDeduplicatedFeedbackType(feedback.FeedbackType))
                {
                    _entries.RemoveAll(existing =>
                        string.Equals(GetSemanticKey(existing), dedupeKey, StringComparison.OrdinalIgnoreCase));
                }

                _entries.Add(Clone(feedback));
                TrimRetention();
                SaveEntriesSafe();
            }
        }

        public void DeleteFeedback(Func<IncidentFeedback, bool> predicate)
        {
            if (predicate == null)
                return;

            lock (_gate)
            {
                _entries = _entries.Where(entry => !predicate(entry)).ToList();
                SaveEntriesSafe();
            }
        }

        public void CleanupExpiredSuppressions()
        {
            lock (_gate)
            {
                CleanupExpiredSuppressionsLocked(DateTime.UtcNow);
                SaveEntriesSafe();
            }
        }

        private void CleanupExpiredSuppressionsLocked(DateTime nowUtc)
        {
            _entries = _entries
                .Where(entry => !string.Equals(entry.FeedbackType, "SuppressSimilar", StringComparison.OrdinalIgnoreCase)
                             || !entry.SuppressUntilUtc.HasValue
                             || entry.SuppressUntilUtc.Value > nowUtc)
                .ToList();
        }

        private void TrimRetention()
        {
            if (_entries.Count <= DefaultRetentionCount)
                return;

            _entries = _entries
                .OrderByDescending(entry => entry.CreatedUtc)
                .Take(DefaultRetentionCount)
                .ToList();
        }

        private void SaveEntriesSafe()
        {
            try
            {
                File.WriteAllText(_path, JsonSerializer.Serialize(_entries, _jsonOptions));
            }
            catch (Exception ex)
            {
                Console.Error.WriteLine($"[IncidentFeedbackStore] Failed to save feedback: {ex.Message}");
            }
        }

        private static List<IncidentFeedback> LoadEntriesSafe(string path)
        {
            try
            {
                if (!File.Exists(path))
                    return new List<IncidentFeedback>();

                var json = File.ReadAllText(path);
                var entries = JsonSerializer.Deserialize<List<IncidentFeedback>>(json);
                return (entries ?? new List<IncidentFeedback>())
                    .Select(NormalizeFeedback)
                    .ToList();
            }
            catch (Exception ex)
            {
                Console.Error.WriteLine($"[IncidentFeedbackStore] Failed to load feedback, starting empty: {ex.Message}");
                TryBackupCorruptFile(path);
                return new List<IncidentFeedback>();
            }
        }

        private static IncidentFeedback NormalizeFeedback(IncidentFeedback feedback)
        {
            feedback.Id = string.IsNullOrWhiteSpace(feedback.Id) ? Guid.NewGuid().ToString("N") : feedback.Id;
            feedback.IncidentId ??= string.Empty;
            feedback.FeedbackType = string.IsNullOrWhiteSpace(feedback.FeedbackType) ? "AddNote" : feedback.FeedbackType.Trim();
            feedback.CreatedUtc = NormalizeUtc(feedback.CreatedUtc);
            feedback.SourceIp = NormalizeEmpty(feedback.SourceIp);
            feedback.DestinationIp = NormalizeEmpty(feedback.DestinationIp);
            feedback.DestinationHost = NormalizeEmpty(feedback.DestinationHost);
            feedback.DestinationPort = NormalizeEmpty(feedback.DestinationPort);
            feedback.ProcessName = NormalizeEmpty(feedback.ProcessName);
            feedback.Category = NormalizeEmpty(feedback.Category);
            feedback.AnalystNote = NormalizeEmpty(feedback.AnalystNote);
            feedback.SuppressUntilUtc = feedback.SuppressUntilUtc.HasValue ? NormalizeUtc(feedback.SuppressUntilUtc.Value) : null;
            feedback.Tags = (feedback.Tags ?? Array.Empty<string>())
                .Where(tag => !string.IsNullOrWhiteSpace(tag))
                .Distinct(StringComparer.OrdinalIgnoreCase)
                .ToArray();
            return feedback;
        }

        private static bool MatchesIncident(IncidentFeedback feedback, Incident incident, DateTime nowUtc)
        {
            if (feedback == null || incident == null)
                return false;

            if (string.Equals(feedback.FeedbackType, "SuppressSimilar", StringComparison.OrdinalIgnoreCase)
                && feedback.SuppressUntilUtc.HasValue
                && feedback.SuppressUntilUtc.Value <= nowUtc)
            {
                return false;
            }

            var targetProcess = GetIncidentProcessName(incident);
            var targetPort = GetIncidentPort(incident);

            return MatchField(feedback.SourceIp, incident.PrimarySourceIp)
                   && MatchField(feedback.DestinationIp, incident.PrimaryDestinationIp)
                   && MatchField(feedback.DestinationHost, incident.PrimaryDestinationHost)
                   && MatchField(feedback.DestinationPort, targetPort)
                   && MatchField(feedback.ProcessName, targetProcess)
                   && MatchField(feedback.Category, incident.Category);
        }

        public static string? GetIncidentProcessName(Incident incident)
        {
            if (incident == null)
                return null;

            var eventProcess = incident.RelatedEvents
                .Select(evt => evt.ProcessName)
                .FirstOrDefault(value => !string.IsNullOrWhiteSpace(value));
            if (!string.IsNullOrWhiteSpace(eventProcess))
                return eventProcess.Trim();

            foreach (var anomaly in incident.RelatedAnomalies)
            {
                if (anomaly.Features.TryGetValue("ProcessName", out var processName)
                    && !string.IsNullOrWhiteSpace(processName))
                    return processName.Trim();
            }

            return null;
        }

        public static string? GetIncidentPort(Incident incident)
        {
            if (incident == null)
                return null;

            var eventPort = incident.RelatedEvents
                .Select(evt => evt.DestinationPort > 0 ? evt.DestinationPort.ToString() : null)
                .FirstOrDefault(value => !string.IsNullOrWhiteSpace(value));
            if (!string.IsNullOrWhiteSpace(eventPort))
                return eventPort;

            return incident.RelatedAnomalies
                .Select(anomaly => anomaly.DestinationPort)
                .FirstOrDefault(value => !string.IsNullOrWhiteSpace(value));
        }

        private static string? GetSemanticKey(IncidentFeedback feedback)
        {
            if (feedback == null)
                return null;

            return feedback.FeedbackType switch
            {
                "TrustDestinationForHost" => string.Join("|", feedback.FeedbackType, feedback.SourceIp ?? "", feedback.DestinationIp ?? "", feedback.DestinationHost ?? ""),
                "TrustPortForHost" => string.Join("|", feedback.FeedbackType, feedback.SourceIp ?? "", feedback.DestinationPort ?? "", feedback.Category ?? ""),
                "TrustProcessForHost" => string.Join("|", feedback.FeedbackType, feedback.SourceIp ?? "", feedback.ProcessName ?? "", feedback.Category ?? ""),
                "SuppressSimilar" => string.Join("|", feedback.FeedbackType, feedback.SourceIp ?? "", feedback.DestinationIp ?? "", feedback.DestinationHost ?? "", feedback.DestinationPort ?? "", feedback.ProcessName ?? "", feedback.Category ?? ""),
                _ => null
            };
        }

        private static bool IsDeduplicatedFeedbackType(string feedbackType)
        {
            return string.Equals(feedbackType, "TrustDestinationForHost", StringComparison.OrdinalIgnoreCase)
                   || string.Equals(feedbackType, "TrustPortForHost", StringComparison.OrdinalIgnoreCase)
                   || string.Equals(feedbackType, "TrustProcessForHost", StringComparison.OrdinalIgnoreCase)
                   || string.Equals(feedbackType, "SuppressSimilar", StringComparison.OrdinalIgnoreCase);
        }

        private static bool MatchField(string? expected, string? actual)
        {
            return string.IsNullOrWhiteSpace(expected)
                   || string.Equals(expected.Trim(), actual?.Trim(), StringComparison.OrdinalIgnoreCase);
        }

        private static string? NormalizeEmpty(string? value)
            => string.IsNullOrWhiteSpace(value) ? null : value.Trim();

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

        private static IncidentFeedback Clone(IncidentFeedback feedback)
        {
            return new IncidentFeedback
            {
                Id = feedback.Id,
                IncidentId = feedback.IncidentId,
                CreatedUtc = feedback.CreatedUtc,
                FeedbackType = feedback.FeedbackType,
                SourceIp = feedback.SourceIp,
                DestinationIp = feedback.DestinationIp,
                DestinationHost = feedback.DestinationHost,
                DestinationPort = feedback.DestinationPort,
                ProcessName = feedback.ProcessName,
                Category = feedback.Category,
                AnalystNote = feedback.AnalystNote,
                SuppressUntilUtc = feedback.SuppressUntilUtc,
                Tags = feedback.Tags.ToArray()
            };
        }

        private static void TryBackupCorruptFile(string path)
        {
            try
            {
                if (!File.Exists(path))
                    return;

                File.Move(path, path + ".corrupt-" + DateTime.UtcNow.ToString("yyyyMMddHHmmss"), overwrite: true);
            }
            catch
            {
                try { File.Delete(path); } catch { }
            }
        }
    }
}
