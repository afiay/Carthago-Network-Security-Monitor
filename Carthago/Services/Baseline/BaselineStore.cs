// SPDX-License-Identifier: MIT
using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
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

        // Explicit override: when true, baseline-dependent alerts never auto-promote.
        public bool LearningMode { get; set; }
        public int MinimumObservations { get; set; } = 100;
        public int MinimumDistinctKeys { get; set; } = 20;
        public TimeSpan MinimumObservationSpan { get; set; } = TimeSpan.FromHours(24);
        public TimeSpan MaximumObservationAge { get; set; } = TimeSpan.FromHours(48);
    }

    public sealed record BaselineReadiness(bool IsReady, int ObservationCount, int DistinctKeys,
        TimeSpan ObservationSpan, IReadOnlyList<string> Blockers)
    {
        public static BaselineReadiness Unavailable(string reason)
            => new(false, 0, 0, TimeSpan.Zero, new[] { reason });
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
        // Replay/benchmark execution needs an isolated store without replacing
        // the live process default or touching ProgramData baseline history.
        private static readonly AsyncLocal<BaselineStore?> ScopedCurrent = new();
        private readonly BaselineOptions _options;
        private readonly SemaphoreSlim _gate = new(1, 1);
        private readonly Dictionary<string, Entry> _entries = new(StringComparer.Ordinal);
        private bool _loaded;
        private bool _corruptJournal;
        private BaselineReadiness _readiness = BaselineReadiness.Unavailable("baseline not loaded");

        public BaselineStore(BaselineOptions options)
            => _options = options ?? throw new ArgumentNullException(nameof(options));

        public static BaselineStore Current => ScopedCurrent.Value ?? Volatile.Read(ref _current);

        // Nestable async-local override: unrelated tasks continue to use their
        // own baseline, and disposing the scope restores the previous store.
        public static IDisposable UseScoped(BaselineStore store)
        {
            if (store == null) throw new ArgumentNullException(nameof(store));
            var previous = ScopedCurrent.Value;
            ScopedCurrent.Value = store;
            return new ScopedBaseline(previous);
        }

        private sealed class ScopedBaseline : IDisposable
        {
            private readonly BaselineStore? _previous;
            private bool _disposed;

            public ScopedBaseline(BaselineStore? previous) => _previous = previous;

            public void Dispose()
            {
                if (_disposed) return;
                ScopedCurrent.Value = _previous;
                _disposed = true;
            }
        }

        public static void SetCurrent(BaselineStore store)
            => Interlocked.Exchange(ref _current, store ?? throw new ArgumentNullException(nameof(store)));

        public BaselineReadiness Readiness => Volatile.Read(ref _readiness);

        public bool IsLearningMode => _options.LearningMode || !Readiness.IsReady;

        public async Task<BaselineReadiness> GetReadinessAsync(CancellationToken cancellationToken = default)
        {
            await _gate.WaitAsync(cancellationToken).ConfigureAwait(false);
            try
            {
                await LoadIfNeededAsync(cancellationToken).ConfigureAwait(false);
                UpdateReadiness();
                return Readiness;
            }
            finally { _gate.Release(); }
        }

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
                try
                {
                    await AppendJournalAsync(new JournalRecord
                    {
                        Operation = "observe", Key = key, TimestampUtc = timestamp
                    }, cancellationToken).ConfigureAwait(false);
                }
                catch
                {
                    Volatile.Write(ref _readiness, BaselineReadiness.Unavailable("baseline persistence failed"));
                    throw;
                }
                var first = !_entries.TryGetValue(key, out _);
                var entry = AddObservation(key, timestamp);
                UpdateReadiness();

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
                UpdateReadiness();
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

        private void UpdateReadiness()
        {
            var now = DateTime.UtcNow;
            var count = 0;
            var first = DateTime.MaxValue;
            var last = DateTime.MinValue;
            var blockers = new List<string>();
            foreach (var entry in _entries.Values)
            {
                count += entry.Count;
                if (entry.FirstSeenUtc < first) first = entry.FirstSeenUtc;
                if (entry.LastSeenUtc > last) last = entry.LastSeenUtc;
                if (entry.Count <= 0 || entry.FirstSeenUtc == default || entry.LastSeenUtc < entry.FirstSeenUtc
                    || entry.LastSeenUtc > now.AddMinutes(5))
                    blockers.Add("invalid baseline observation timestamps or counts");
            }

            var span = _entries.Count == 0 ? TimeSpan.Zero : last - first;
            if (!_loaded) blockers.Add("baseline not loaded");
            if (_corruptJournal) blockers.Add("corrupt baseline journal");
            if (count < _options.MinimumObservations) blockers.Add("insufficient persisted observations");
            if (_entries.Count < _options.MinimumDistinctKeys) blockers.Add("insufficient distinct baseline keys");
            if (span < _options.MinimumObservationSpan) blockers.Add("baseline observation duration too short");
            if (_entries.Count == 0 || now - last > _options.MaximumObservationAge)
                blockers.Add("baseline observations are stale");
            if (_options.LearningMode) blockers.Add("forced learning mode");
            Volatile.Write(ref _readiness, new BaselineReadiness(blockers.Count == 0, count,
                _entries.Count, span, blockers.Distinct(StringComparer.OrdinalIgnoreCase).ToArray()));
        }

        private async Task LoadIfNeededAsync(CancellationToken cancellationToken)
        {
            if (_loaded) return;
            if (File.Exists(SnapshotPath))
            {
                var json = await File.ReadAllTextAsync(SnapshotPath, cancellationToken).ConfigureAwait(false);
                try
                {
                    var saved = JsonSerializer.Deserialize<Dictionary<string, Entry>>(json);
                    if (saved != null)
                        foreach (var item in saved) _entries[item.Key] = item.Value;
                    else _corruptJournal = true;
                }
                catch (JsonException) { _corruptJournal = true; }
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
                    catch (JsonException) { _corruptJournal = true; continue; }
                    if (record?.Operation == "clear") _entries.Clear();
                    else if (record?.Operation == "observe" && !string.IsNullOrWhiteSpace(record.Key))
                        AddObservation(record.Key, record.TimestampUtc);
                    else _corruptJournal = true;
                }
            }
            _loaded = true;
            UpdateReadiness();
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
