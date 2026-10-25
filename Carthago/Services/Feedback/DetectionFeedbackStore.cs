// SPDX-License-Identifier: MIT
using System;
using System.Collections.Generic;
using System.IO;
using System.Runtime.CompilerServices;
using System.Text.Json;
using System.Text.Json.Serialization;
using System.Threading;
using System.Threading.Tasks;

namespace Carthago.Services.Feedback
{
    public enum DetectionFeedbackVerdict
    {
        Unknown,
        TruePositive,
        FalsePositive,
        ExpectedActivity,
        NeedsReview,
        SuppressSimilar
    }

    public sealed class DetectionFeedback
    {
        public string EventId { get; set; } = string.Empty;
        public string RuleId { get; set; } = string.Empty;
        public string? IncidentId { get; set; }
        public DetectionFeedbackVerdict Verdict { get; set; }
        public string? Note { get; set; }
        public DateTime TimestampUtc { get; set; } = DateTime.UtcNow;
    }

    public sealed class DetectionFeedbackOptions
    {
        public string DirectoryPath { get; set; } = Path.Combine(
            Environment.GetFolderPath(Environment.SpecialFolder.CommonApplicationData),
            "Carthago", "feedback");
    }

    /// <summary>
    /// Append-only analyst annotations. Detection events remain unchanged, and
    /// feedback can be reloaded independently of the detection journal.
    /// </summary>
    public sealed class DetectionFeedbackStore
    {
        private static readonly Lazy<DetectionFeedbackStore> Default = new(() => new DetectionFeedbackStore(new DetectionFeedbackOptions()));
        private readonly DetectionFeedbackOptions _options;
        private readonly SemaphoreSlim _writeGate = new(1, 1);
        private readonly JsonSerializerOptions _jsonOptions = new()
        {
            PropertyNamingPolicy = JsonNamingPolicy.CamelCase,
            Converters = { new JsonStringEnumConverter() }
        };

        public DetectionFeedbackStore(DetectionFeedbackOptions options)
            => _options = options ?? throw new ArgumentNullException(nameof(options));

        public static DetectionFeedbackStore Current => Default.Value;

        public async Task AppendAsync(DetectionFeedback feedback, CancellationToken cancellationToken = default)
        {
            if (feedback == null) throw new ArgumentNullException(nameof(feedback));
            if (string.IsNullOrWhiteSpace(feedback.EventId) || string.IsNullOrWhiteSpace(feedback.RuleId))
                throw new ArgumentException("Feedback needs an event ID and rule ID.", nameof(feedback));

            var utc = feedback.TimestampUtc == default ? DateTime.UtcNow : feedback.TimestampUtc.ToUniversalTime();
            var normalizedFeedback = new DetectionFeedback
            {
                EventId = feedback.EventId,
                RuleId = feedback.RuleId,
                IncidentId = feedback.IncidentId,
                Verdict = feedback.Verdict,
                Note = feedback.Note,
                TimestampUtc = utc
            };
            var path = Path.Combine(_options.DirectoryPath, $"feedback-{utc:yyyy-MM}.jsonl");
            await _writeGate.WaitAsync(cancellationToken).ConfigureAwait(false);
            try
            {
                Directory.CreateDirectory(_options.DirectoryPath);
                await File.AppendAllTextAsync(path, JsonSerializer.Serialize(normalizedFeedback, _jsonOptions) + Environment.NewLine,
                    cancellationToken).ConfigureAwait(false);
            }
            finally { _writeGate.Release(); }
        }

        public async IAsyncEnumerable<DetectionFeedback> ReadAllAsync(
            [EnumeratorCancellation] CancellationToken cancellationToken = default)
        {
            if (!Directory.Exists(_options.DirectoryPath)) yield break;

            foreach (var path in Directory.EnumerateFiles(_options.DirectoryPath, "feedback-*.jsonl"))
            {
                using var reader = new StreamReader(path);
                while (true)
                {
                    cancellationToken.ThrowIfCancellationRequested();
                    var line = await reader.ReadLineAsync(cancellationToken).ConfigureAwait(false);
                    if (line == null) break;
                    if (string.IsNullOrWhiteSpace(line)) continue;

                    DetectionFeedback? record;
                    try { record = JsonSerializer.Deserialize<DetectionFeedback>(line, _jsonOptions); }
                    catch (JsonException) { continue; } // Preserve readable entries after a torn write.
                    if (record != null) yield return record;
                }
            }
        }
    }
}
