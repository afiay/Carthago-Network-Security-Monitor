// SPDX-License-Identifier: MIT
using System;
using System.Collections.Generic;
using System.IO;
using System.Text.Json;
using System.Threading;
using System.Threading.Tasks;

namespace Carthago.Services.Baseline
{
    public sealed class BaselineOptions
    {
        public string DirectoryPath { get; set; } = Path.Combine(
            Environment.GetFolderPath(Environment.SpecialFolder.CommonApplicationData),
            "Carthago", "baseline");

        public bool LearningMode { get; set; } = true;
    }

    public sealed record BaselineObservation(
        string Kind, string Subject, string Value, DateTime TimestampUtc, string Evidence);

    public sealed record BaselineDecision(
        bool IsFirstSeen, bool IsKnown, bool IsLearningMode, string Reason,
        int ObservationCount, DateTime? FirstSeenUtc, DateTime? LastSeenUtc);

    /// <summary>
    /// Durable, independently keyed observations. Historical JSON snapshots remain
    /// readable; new observations use an append-only journal to avoid full-file writes.
    /// </summary>
    public sealed class BaselineStore
    {
        private sealed class Entry
        {
            public int Count { get; set; }
            public DateTime FirstSeenUtc { get; set; }
            public DateTime LastSeenUtc { get; set; }
        }

        private sealed class JournalRecord
        {
            public string Operation { get; set; } = string.Empty;
            public string? Key { get; set; }
            public DateTime TimestampUtc { get; set; }
        }

        private static BaselineStore _current = new(new BaselineOptions());
        private readonly BaselineOptions _options;
        private readonly SemaphoreSlim _gate = new(1, 1);
        private readonly Dictionary<string, Entry> _entries = new(StringComparer.Ordinal);
        private bool _loaded;

        public BaselineStore(BaselineOptions options)
            => _options = options ?? throw new ArgumentNullException(nameof(options));

        public static BaselineStore Current => Volatile.Read(ref _current);

        public static void SetCurrent(BaselineStore store)
            => Interlocked.Exchange(ref _current, store ?? throw new ArgumentNullException(nameof(store)));

        public bool IsLearningMode => _options.LearningMode;

        public async Task<BaselineDecision> ObserveAsync(
            BaselineObservation observation, CancellationToken cancellationToken = default)
        {
            if (observation == null) throw new ArgumentNullException(nameof(observation));
            if (string.IsNullOrWhiteSpace(observation.Kind)
                || string.IsNullOrWhiteSpace(observation.Subject)
                || string.IsNullOrWhiteSpace(observation.Value))
                throw new ArgumentException("A baseline observation needs a kind, subject and value.", nameof(observation));

            await _gate.WaitAsync(cancellationToken).ConfigureAwait(false);
            try
            {
                await LoadIfNeededAsync(cancellationToken).ConfigureAwait(false);
                var key = JsonSerializer.Serialize(new[] { observation.Kind, observation.Subject, observation.Value });
                var timestamp = observation.TimestampUtc == default ? DateTime.UtcNow : observation.TimestampUtc.ToUniversalTime();
                // Persist first so an I/O failure cannot leave an unpersisted
                // observation counted as known in the live process.
                await AppendJournalAsync(new JournalRecord
                {
                    Operation = "observe", Key = key, TimestampUtc = timestamp
                }, cancellationToken).ConfigureAwait(false);
                var first = !_entries.TryGetValue(key, out _);
                var entry = AddObservation(key, timestamp);

                return new BaselineDecision(first, !first, IsLearningMode,
                    first ? "first seen" : "previously observed", entry.Count,
                    entry.FirstSeenUtc, entry.LastSeenUtc);
            }
            finally { _gate.Release(); }
        }

        public async Task ClearAsync(CancellationToken cancellationToken = default)
        {
            await _gate.WaitAsync(cancellationToken).ConfigureAwait(false);
            try
            {
                await AppendJournalAsync(new JournalRecord { Operation = "clear" }, cancellationToken)
                    .ConfigureAwait(false);
                _entries.Clear();
                _loaded = true;
            }
            finally { _gate.Release(); }
        }

        private string SnapshotPath => Path.Combine(_options.DirectoryPath, "baseline.json");
        private string JournalPath => Path.Combine(_options.DirectoryPath, "baseline-journal.jsonl");

        private Entry AddObservation(string key, DateTime timestamp)
        {
            if (!_entries.TryGetValue(key, out var entry))
                entry = new Entry { FirstSeenUtc = timestamp, LastSeenUtc = timestamp };

            entry.Count++;
            if (timestamp < entry.FirstSeenUtc) entry.FirstSeenUtc = timestamp;
            if (timestamp > entry.LastSeenUtc) entry.LastSeenUtc = timestamp;
            _entries[key] = entry;
            return entry;
        }

        private async Task LoadIfNeededAsync(CancellationToken cancellationToken)
        {
            if (_loaded) return;
            if (File.Exists(SnapshotPath))
            {
                var json = await File.ReadAllTextAsync(SnapshotPath, cancellationToken).ConfigureAwait(false);
                var saved = JsonSerializer.Deserialize<Dictionary<string, Entry>>(json);
                if (saved != null)
                    foreach (var item in saved) _entries[item.Key] = item.Value;
            }
            if (File.Exists(JournalPath))
            {
                using var reader = new StreamReader(JournalPath);
                while (true)
                {
                    var line = await reader.ReadLineAsync(cancellationToken).ConfigureAwait(false);
                    if (line == null) break;
                    if (string.IsNullOrWhiteSpace(line)) continue;
                    JournalRecord? record;
                    try { record = JsonSerializer.Deserialize<JournalRecord>(line); }
                    catch (JsonException) { continue; } // Ignore an incomplete journal line.
                    if (record?.Operation == "clear") _entries.Clear();
                    else if (record?.Operation == "observe" && !string.IsNullOrWhiteSpace(record.Key))
                        AddObservation(record.Key, record.TimestampUtc);
                }
            }
            _loaded = true;
        }

        private async Task AppendJournalAsync(JournalRecord record, CancellationToken cancellationToken)
        {
            Directory.CreateDirectory(_options.DirectoryPath);
            // A leading newline ensures the next valid event is independently
            // readable even if the previous append was interrupted mid-record.
            await File.AppendAllTextAsync(JournalPath,
                Environment.NewLine + JsonSerializer.Serialize(record) + Environment.NewLine,
                cancellationToken).ConfigureAwait(false);
        }
    }
}
