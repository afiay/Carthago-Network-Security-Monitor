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
    /// Durable, independently keyed observations. The snapshot is written atomically
    /// so a failed write cannot replace the last known-good baseline.
    /// </summary>
    public sealed class BaselineStore
    {
        private sealed class Entry
        {
            public int Count { get; set; }
            public DateTime FirstSeenUtc { get; set; }
            public DateTime LastSeenUtc { get; set; }
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
                var first = !_entries.TryGetValue(key, out var entry);
                if (first)
                    entry = new Entry { FirstSeenUtc = timestamp, LastSeenUtc = timestamp };

                entry!.Count++;
                if (timestamp < entry.FirstSeenUtc) entry.FirstSeenUtc = timestamp;
                if (timestamp > entry.LastSeenUtc) entry.LastSeenUtc = timestamp;
                _entries[key] = entry;
                await SaveAsync(cancellationToken).ConfigureAwait(false);

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
                _entries.Clear();
                _loaded = true;
                await SaveAsync(cancellationToken).ConfigureAwait(false);
            }
            finally { _gate.Release(); }
        }

        private string SnapshotPath => Path.Combine(_options.DirectoryPath, "baseline.json");

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
            _loaded = true;
        }

        private async Task SaveAsync(CancellationToken cancellationToken)
        {
            Directory.CreateDirectory(_options.DirectoryPath);
            var temporaryPath = SnapshotPath + "." + Guid.NewGuid().ToString("N") + ".tmp";
            try
            {
                await File.WriteAllTextAsync(temporaryPath, JsonSerializer.Serialize(_entries), cancellationToken)
                    .ConfigureAwait(false);
                File.Move(temporaryPath, SnapshotPath, overwrite: true);
            }
            finally
            {
                if (File.Exists(temporaryPath)) File.Delete(temporaryPath);
            }
        }
    }
}
