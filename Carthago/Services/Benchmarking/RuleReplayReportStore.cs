// SPDX-License-Identifier: MIT
// File: Services/Benchmarking/RuleReplayReportStore.cs
using System;
using System.IO;
using System.Text.Json;
using System.Text.Json.Serialization;
using System.Threading;
using System.Threading.Tasks;

namespace Carthago.Services.Benchmarking
{
    public sealed class RuleReplayReportStore
    {
        private static readonly JsonSerializerOptions JsonOptions = new()
        {
            PropertyNamingPolicy = JsonNamingPolicy.CamelCase,
            DefaultIgnoreCondition = JsonIgnoreCondition.WhenWritingNull,
            WriteIndented = true,
            Converters = { new JsonStringEnumConverter() }
        };

        public string GetJsonPath(string outputDirectory) => Path.Combine(outputDirectory, "rule-replay-benchmark.json");

        public async Task SaveAsync(RuleReplayDirectoryResult result, string outputDirectory, CancellationToken cancellationToken = default)
        {
            if (result == null) throw new ArgumentNullException(nameof(result));
            Directory.CreateDirectory(outputDirectory);
            var path = GetJsonPath(outputDirectory);
            await File.WriteAllTextAsync(path, JsonSerializer.Serialize(result, JsonOptions), cancellationToken).ConfigureAwait(false);
        }

        public async Task<RuleReplayDirectoryResult?> LoadAsync(string outputDirectory, CancellationToken cancellationToken = default)
        {
            var path = GetJsonPath(outputDirectory);
            if (!File.Exists(path))
                return null;

            await using var stream = File.Open(path, FileMode.Open, FileAccess.Read, FileShare.ReadWrite);
            return await JsonSerializer.DeserializeAsync<RuleReplayDirectoryResult>(stream, JsonOptions, cancellationToken).ConfigureAwait(false);
        }
    }
}
