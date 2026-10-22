// SPDX-License-Identifier: MIT
// File: Services/Journaling/DetectionOutbox.cs
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
    /// <summary>
    /// Durable overflow/outbox spool for external sink delivery failures.
    /// This is intentionally separate from the mandatory detection journal:
    /// the journal proves the detection happened; the outbox proves a sink still needs attention/retry.
    /// </summary>
    public sealed class DetectionOutbox
    {
        private static readonly Lazy<DetectionOutbox> _current = new(() => new DetectionOutbox(new DetectionOutboxOptions()));
        private readonly DetectionOutboxOptions _options;
        private readonly SemaphoreSlim _writeGate = new(1, 1);
        private readonly JsonSerializerOptions _jsonOptions = new()
        {
            PropertyNamingPolicy = JsonNamingPolicy.CamelCase,
            DefaultIgnoreCondition = JsonIgnoreCondition.WhenWritingNull,
            WriteIndented = false,
            Converters = { new JsonStringEnumConverter() }
        };

        public DetectionOutbox(DetectionOutboxOptions options) => _options = options ?? throw new ArgumentNullException(nameof(options));

        public static DetectionOutbox Current => _current.Value;

        public string GetOutboxPath(DateTime timestampUtc)
        {
            var utc = timestampUtc.Kind == DateTimeKind.Utc ? timestampUtc : timestampUtc.ToUniversalTime();
            return Path.Combine(_options.DirectoryPath, $"sink-outbox-{utc:yyyy-MM-dd}.jsonl");
        }

        public async Task<DetectionOutboxWriteResult> AppendPendingAsync(
            DetectionEvent evt,
            string sinkName,
            string reason,
            CancellationToken cancellationToken = default)
        {
            if (evt == null) throw new ArgumentNullException(nameof(evt));

            var writtenAt = DateTime.UtcNow;
            var path = GetOutboxPath(writtenAt);

            try
            {
                if (_options.CreateDirectoryIfMissing)
                    Directory.CreateDirectory(Path.GetDirectoryName(path)!);

                var envelope = new
                {
                    outboxId = Guid.NewGuid().ToString("N"),
                    eventId = evt.EventId,
                    ruleId = evt.RuleId,
                    ruleName = evt.RuleName,
                    sinkName,
                    reason,
                    failedAtUtc = writtenAt,
                    journalPath = evt.JournalPath,
                    persistedAtUtc = evt.PersistedAtUtc,
                    eventSnapshot = evt
                };

                var line = JsonSerializer.Serialize(envelope, _jsonOptions) + Environment.NewLine;
                var bytes = Encoding.UTF8.GetBytes(line);

                await _writeGate.WaitAsync(cancellationToken).ConfigureAwait(false);
                try
                {
                    using var fs = new FileStream(path, FileMode.Append, FileAccess.Write, FileShare.Read, 4096, useAsync: true);
                    await fs.WriteAsync(bytes.AsMemory(0, bytes.Length), cancellationToken).ConfigureAwait(false);
                    if (_options.FlushAfterEveryWrite)
                        await fs.FlushAsync(cancellationToken).ConfigureAwait(false);
                }
                finally
                {
                    _writeGate.Release();
                }

                RuleEngineMetrics.Increment(evt.RuleId, RuleMetricNames.DetectionOutboxPendingTotal);
                return DetectionOutboxWriteResult.Success(path, writtenAt);
            }
            catch (Exception ex)
            {
                // Outbox failure must not erase the original detection; that detection is already in the local journal.
                RuleEngineHealthState.ReportSinkQueueBackpressure($"outbox write failed for {sinkName}: {ex.Message}");
                RuleEngineMetrics.Increment(evt.RuleId, RuleMetricNames.RuleSinkFailedTotal);
                return DetectionOutboxWriteResult.Failure(ex.Message, path);
            }
        }
    }
}
