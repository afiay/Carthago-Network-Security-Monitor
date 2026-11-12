// SPDX-License-Identifier: MIT
using System;
using System.Collections.Generic;
using System.Globalization;
using System.IO;
using System.Linq;
using System.Text.Json;
using System.Threading;

namespace Carthago.Services;

internal sealed record AssetHistoryRow(string SessionId, string SessionStartedUtc, ObservedAssetRow Asset);
internal sealed record AssetHistorySnapshot(int SessionCount, IReadOnlyList<AssetHistoryRow> Rows, string? Error);

// Independent of detection baseline readiness. One replaceable file per capture
// session, never an append of the same cumulative counters.
internal sealed class AssetHistoryStore
{
    internal const int MaxSessions = 32;
    private const int MaxRows = 2048;
    private const long MaxBytes = 8 * 1024 * 1024;
    private static readonly object IoGate = new();
    private readonly string _directory;
    private string? _lastSaveError;
    internal string? LastSaveError => Volatile.Read(ref _lastSaveError);

    // Public constructor/properties for System.Text.Json, even though internal type.
    public sealed record Checkpoint(int Version, Guid SessionId, DateTimeOffset StartedUtc, ObservedAssetRow[] Assets);

    internal AssetHistoryStore(string? directory = null)
        => _directory = directory ?? Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData),
            "Carthago", "asset-history");

    internal bool Save(ObservedAssetRegistry registry)
    {
        lock (IoGate)
        {
            string? temp = null;
            try
            {
                // Snapshot under the same writer gate, so a periodic save cannot
                // overwrite a newer final checkpoint with an older snapshot.
                var rows = registry.Snapshot();
                if (rows.Count == 0) return true;
                Directory.CreateDirectory(_directory);
                var checkpoint = new Checkpoint(1, registry.SessionId, registry.SessionStartedUtc, rows.ToArray());
                string path = Path.Combine(_directory, FileName(checkpoint));
                temp = path + "." + Guid.NewGuid().ToString("N") + ".tmp";
                using (var stream = new FileStream(temp, FileMode.CreateNew, FileAccess.Write, FileShare.None))
                {
                    JsonSerializer.Serialize(stream, checkpoint);
                    if (stream.Length > MaxBytes) throw new IOException("Asset checkpoint exceeds storage limit.");
                    stream.Flush(flushToDisk: true);
                }
                File.Move(temp, path, overwrite: true);
                temp = null;
                foreach (var old in Files().Skip(MaxSessions)) File.Delete(old);
                Volatile.Write(ref _lastSaveError, null);
                return true;
            }
            catch (Exception ex) when (ex is IOException or UnauthorizedAccessException or JsonException or NotSupportedException)
            {
                Volatile.Write(ref _lastSaveError, ex.Message);
                return false;
            }
            finally
            {
                if (temp is not null)
                    try { File.Delete(temp); } catch (IOException) { } catch (UnauthorizedAccessException) { }
            }
        }
    }

    internal AssetHistorySnapshot Read()
    {
        lock (IoGate)
        {
            var result = new List<AssetHistoryRow>();
            int sessions = 0, skipped = 0;
            try
            {
                if (!Directory.Exists(_directory)) return new(0, result, null);
                foreach (var path in Files().Take(MaxSessions))
                {
                    try
                    {
                        using var stream = new FileStream(path, FileMode.Open, FileAccess.Read, FileShare.Read | FileShare.Delete);
                        if (stream.Length > MaxBytes) { skipped++; continue; }
                        var saved = JsonSerializer.Deserialize<Checkpoint>(stream);
                        if (saved is null || saved.Version != 1 || saved.SessionId == Guid.Empty
                            || saved.StartedUtc == default || saved.Assets is null || saved.Assets.Length is < 1 or > MaxRows
                            || Path.GetFileName(path) != FileName(saved)
                            || saved.Assets.Any(a => !Valid(a)))
                        { skipped++; continue; }
                        sessions++;
                        string started = saved.StartedUtc.UtcDateTime.ToString("u", CultureInfo.InvariantCulture);
                        foreach (var asset in saved.Assets)
                            result.Add(new(saved.SessionId.ToString("N"), started, asset));
                    }
                    catch (Exception ex) when (ex is IOException or UnauthorizedAccessException or JsonException or NotSupportedException)
                    { skipped++; }
                }
                return new(sessions, result.ToArray(), skipped == 0 ? null : $"{skipped} unreadable or invalid checkpoint(s) skipped.");
            }
            catch (Exception ex) when (ex is IOException or UnauthorizedAccessException)
            { return new(sessions, result.ToArray(), ex.Message); }
        }
    }

    private IEnumerable<string> Files() => Directory.EnumerateFiles(_directory, "asset-*.json")
        .Where(path =>
        {
            var name = Path.GetFileNameWithoutExtension(path);
            return name.Length == 6 + 19 + 1 + 32 && name.StartsWith("asset-", StringComparison.Ordinal)
                && long.TryParse(name.AsSpan(6, 19), NumberStyles.None, CultureInfo.InvariantCulture, out _)
                && name[25] == '-' && Guid.TryParseExact(name[26..], "N", out _);
        }).OrderByDescending(path => Path.GetFileName(path), StringComparer.Ordinal);

    private static string FileName(Checkpoint saved) =>
        $"asset-{saved.StartedUtc.UtcDateTime.Ticks.ToString("D19", CultureInfo.InvariantCulture)}-{saved.SessionId:N}.json";

    private static bool Valid(ObservedAssetRow? a)
        => a is not null && a.Observations > 0 && !string.IsNullOrWhiteSpace(a.InterfaceScope)
            && a.Evidence is "ARP sender claim" or "Local host IP"
            && !string.IsNullOrWhiteSpace(a.Addresses) && a.Addresses.Length <= 4096
            && a.Services is not null && a.Services.Length <= 512
            && DateTimeOffset.TryParseExact(a.FirstSeenUtc, "u", CultureInfo.InvariantCulture,
                DateTimeStyles.AssumeUniversal, out var first)
            && DateTimeOffset.TryParseExact(a.LastSeenUtc, "u", CultureInfo.InvariantCulture,
                DateTimeStyles.AssumeUniversal, out var last) && first <= last;
}
