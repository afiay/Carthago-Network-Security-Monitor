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

        /// <summary>
        /// Read OS-reported capacity for this journal instance's configured directory.
        /// No directory is created, no packet input is accepted, and this is not
        /// evidence of a failed write or permission to emit an R531 alert.
        /// </summary>
        public bool TryReadConfiguredVolumeCapacity(out long availableBytes, out long totalBytes)
            => ProtocolIntelligence.JournalVolumeCapacityProbe.TryRead(
                _options.DirectoryPath, out availableBytes, out totalBytes);

        /// <summary>
        /// Evaluate configured low-space policy against this journal's own OS-backed
        /// directory. Failure to sample is unknown, never a low-space finding.
        /// This is a synchronous health prerequisite, not an R531 alert.
        /// </summary>
        public bool TryEvaluateConfiguredVolumeCapacity(
            long minimumFreeBytes, double minimumFreePercent,
            out bool belowBothLimits, out long availableBytes, out long totalBytes)
        {
            belowBothLimits = false;
            availableBytes = 0;
            totalBytes = 0;
            if (minimumFreeBytes <= 0 || minimumFreePercent <= 0
                || minimumFreePercent > 100 || double.IsNaN(minimumFreePercent)
                || double.IsInfinity(minimumFreePercent))
                return false;

            if (!TryReadConfiguredVolumeCapacity(out availableBytes, out totalBytes))
                return false;

            belowBothLimits = ProtocolIntelligence.JournalVolumeCapacityProbe.IsBelowBothConfiguredLimits(
                availableBytes, totalBytes, minimumFreeBytes, minimumFreePercent);
            return true;
        }

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
