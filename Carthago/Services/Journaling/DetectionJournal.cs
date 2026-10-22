// SPDX-License-Identifier: MIT
// File: Services/Journaling/DetectionJournal.cs
using System;
using System.IO;
using System.Text;
using System.Text.Json;
using System.Text.Json.Serialization;
using System.Threading;
using System.Threading.Tasks;
using Carthago.Models;

namespace Carthago.Services
{
    public sealed class DetectionJournal
    {
        private static readonly Lazy<DetectionJournal> _current = new(() => new DetectionJournal(new DetectionJournalOptions()));
        private readonly DetectionJournalOptions _options;
        private readonly SemaphoreSlim _writeGate = new(1, 1);
        private readonly JsonSerializerOptions _jsonOptions = new()
        {
            PropertyNamingPolicy = JsonNamingPolicy.CamelCase,
            DefaultIgnoreCondition = JsonIgnoreCondition.WhenWritingNull,
            WriteIndented = false,
            Converters = { new JsonStringEnumConverter() }
        };

        public DetectionJournal(DetectionJournalOptions options) => _options = options ?? throw new ArgumentNullException(nameof(options));
        public static DetectionJournal Current => _current.Value;

        public string GetJournalPath(DateTime timestampUtc)
        {
            var utc = timestampUtc.Kind == DateTimeKind.Utc ? timestampUtc : timestampUtc.ToUniversalTime();
            return Path.Combine(_options.DirectoryPath, $"detections-{utc:yyyy-MM-dd}.jsonl");
        }

        public async Task<DetectionJournalWriteResult> AppendAsync(DetectionEvent evt, CancellationToken cancellationToken = default)
        {
            if (evt == null) throw new ArgumentNullException(nameof(evt));
            var ts = evt.TimestampUtc == default ? DateTime.UtcNow : evt.TimestampUtc;
            var path = GetJournalPath(ts);

            try
            {
                if (_options.CreateDirectoryIfMissing)
                    Directory.CreateDirectory(Path.GetDirectoryName(path)!);

                await _writeGate.WaitAsync(cancellationToken).ConfigureAwait(false);
                try
                {
                    var persistedAt = DateTime.UtcNow;
                    evt.PersistedAtUtc = persistedAt;
                    evt.JournalPath = path;
                    evt.DeliveryStatus = DetectionDeliveryStatus.Persisted;

                    await using var fs = new FileStream(path, FileMode.Append, FileAccess.Write, FileShare.Read, 16 * 1024, FileOptions.Asynchronous | FileOptions.WriteThrough);
                    var line = JsonSerializer.Serialize(evt, _jsonOptions) + Environment.NewLine;
                    var bytes = Encoding.UTF8.GetBytes(line);
                    await fs.WriteAsync(bytes.AsMemory(0, bytes.Length), cancellationToken).ConfigureAwait(false);
                    if (_options.FlushAfterEveryWrite)
                        await fs.FlushAsync(cancellationToken).ConfigureAwait(false);

                    return DetectionJournalWriteResult.Success(path, persistedAt);
                }
                finally
                {
                    _writeGate.Release();
                }
            }
            catch (Exception ex)
            {
                evt.DeliveryStatus = DetectionDeliveryStatus.FailedToPersist;
                evt.PersistenceError = ex.Message;
                RuleEngineMetrics.Increment(evt.RuleId, RuleMetricNames.JournalWriteFailedTotal);
                RuleEngineHealthState.ReportJournalWriteFailure(path, ex.Message);
                return DetectionJournalWriteResult.Failure(ex.Message, path);
            }
        }
    }
}
