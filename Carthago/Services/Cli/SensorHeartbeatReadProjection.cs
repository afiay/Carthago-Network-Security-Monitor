// SPDX-License-Identifier: MIT
using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Threading;
using System.Threading.Tasks;
using System.Globalization;
using System.Text;
using System.Text.Json;
using Carthago.Contracts;

namespace Carthago.Services.Cli;

/// <summary>Bounded read-only view of local heartbeat journals, not authenticated sensor liveness.</summary>
public static class SensorHeartbeatReadProjection
{
    public const int LookbackDays = 7, MaxFileBytes = 1024 * 1024, MaxSensors = 10000;
    public static readonly TimeSpan FreshnessWindow = TimeSpan.FromMinutes(5);
    public static readonly TimeSpan FutureTolerance = TimeSpan.FromSeconds(30);

    public static async Task<LiveSensorRow[]?> ReadAsync(string directory, DateTimeOffset now, CancellationToken token)
    {
        var latest = new Dictionary<string, DateTimeOffset>(StringComparer.OrdinalIgnoreCase);
        bool found = false;
        for (int day = 0; day < LookbackDays; day++)
        {
            token.ThrowIfCancellationRequested();
            string path = Path.Combine(directory, "heartbeats-" +
                now.UtcDateTime.AddDays(-day).ToString("yyyy-MM-dd", CultureInfo.InvariantCulture) + ".jsonl");
            FileStream stream;
            try { stream = new FileStream(path, FileMode.Open, FileAccess.Read, FileShare.ReadWrite, 4096, useAsync: true); }
            catch (FileNotFoundException) { continue; }
            catch (DirectoryNotFoundException) { continue; }
            await using (stream)
            {
                found = true;
                if (stream.Length > MaxFileBytes) throw new InvalidDataException("Heartbeat journal exceeds read limit.");
                using var data = new MemoryStream();
                byte[] buffer = new byte[8192];
                int n;
                while ((n = await stream.ReadAsync(buffer, token).ConfigureAwait(false)) != 0)
                {
                    if (data.Length + n > MaxFileBytes) throw new InvalidDataException("Heartbeat journal exceeds read limit.");
                    data.Write(buffer, 0, n);
                }
                string source = new UTF8Encoding(false, true).GetString(data.ToArray());
                using var reader = new StringReader(source);
                string? line;
                while ((line = reader.ReadLine()) is not null)
                {
                    token.ThrowIfCancellationRequested();
                    if (string.IsNullOrWhiteSpace(line)) continue;
                    if (line.Length > 8192) throw new InvalidDataException("Heartbeat record too large.");
                    using var doc = JsonDocument.Parse(line, new JsonDocumentOptions { MaxDepth = 8 });
                    var root = doc.RootElement;
                    if (root.ValueKind == JsonValueKind.Object && root.EnumerateObject().GroupBy(p => p.Name, StringComparer.Ordinal).Any(g => g.Count() > 1))
                        throw new InvalidDataException("Duplicate heartbeat field.");
                    if (root.ValueKind != JsonValueKind.Object ||
                        !root.TryGetProperty("SensorId", out var idValue) || idValue.ValueKind != JsonValueKind.String ||
                        !root.TryGetProperty("TimestampUtc", out var timestamp) || timestamp.ValueKind != JsonValueKind.String ||
                        !timestamp.TryGetDateTimeOffset(out var observed) || observed.Offset != TimeSpan.Zero ||
                        observed == default || !LiveQueryProtocol.SensorIdValid(idValue.GetString()))
                        throw new InvalidDataException("Malformed heartbeat record.");
                    string id = idValue.GetString()!;
                    if (!latest.TryGetValue(id, out var previous) || observed > previous) latest[id] = observed;
                    if (latest.Count > MaxSensors) throw new InvalidDataException("Too many sensors.");
                }
            }
        }
        if (!found) return null;
        return latest.OrderBy(x => x.Key, StringComparer.OrdinalIgnoreCase)
            .Select(x => new LiveSensorRow(x.Key, x.Value, x.Value > now + FutureTolerance ? "future" :
                now - x.Value > FreshnessWindow ? "stale" : "fresh")).ToArray();
    }
}
