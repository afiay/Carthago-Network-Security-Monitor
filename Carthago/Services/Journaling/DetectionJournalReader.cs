// SPDX-License-Identifier: MIT
// File: Services/Journaling/DetectionJournalReader.cs
using System;
using System.Collections.Generic;
using System.IO;
using System.Text.Json;
using System.Threading;
using System.Threading.Tasks;
using Carthago.Models;

namespace Carthago.Services
{
    public sealed class DetectionJournalReader
    {
        private readonly DetectionJournalOptions _options;
        private readonly JsonSerializerOptions _jsonOptions = new()
        {
            PropertyNameCaseInsensitive = true,
            Converters = { new System.Text.Json.Serialization.JsonStringEnumConverter() }
        };

        public DetectionJournalReader(DetectionJournalOptions options) => _options = options ?? throw new ArgumentNullException(nameof(options));

        public async IAsyncEnumerable<DetectionEvent> ReadDayAsync(DateTime dayUtc, [System.Runtime.CompilerServices.EnumeratorCancellation] CancellationToken cancellationToken = default)
        {
            var path = Path.Combine(_options.DirectoryPath, $"detections-{dayUtc.ToUniversalTime():yyyy-MM-dd}.jsonl");
            if (!File.Exists(path)) yield break;

            using var fs = new FileStream(path, FileMode.Open, FileAccess.Read, FileShare.ReadWrite);
            using var sr = new StreamReader(fs);
            while (!sr.EndOfStream)
            {
                cancellationToken.ThrowIfCancellationRequested();
                var line = await sr.ReadLineAsync().ConfigureAwait(false);
                if (string.IsNullOrWhiteSpace(line)) continue;
                DetectionEvent? evt = null;
                try { evt = JsonSerializer.Deserialize<DetectionEvent>(line, _jsonOptions); }
                catch { /* Keep reader tolerant of one corrupt line. */ }
                if (evt != null) yield return evt;
            }
        }
    }
}
