// SPDX-License-Identifier: MIT
// SOURCE CANDIDATE — UNVERIFIED; TESTS AUTHORED — 0 EXECUTED.
using System;
using System.Collections.Generic;
using System.IO;
using System.IO.Compression;
using System.Linq;
using System.Security.Cryptography;
using System.Text.Json;
using System.Threading;
using System.Threading.Tasks;

namespace Carthago.Services.SessionFiles;

/// <summary>Versioned CSA ZIP container: manifest.json + one JSON array per category.</summary>
public sealed class CarthagoSessionArchiveService
{
    private const long MaximumEntryBytes = 256L * 1024 * 1024;
    private const long MaximumTotalBytes = 512L * 1024 * 1024;
    private const int MaximumRowsPerCategory = 1_000_000;
    private const int MaximumArchiveEntries = 1 + 11;

    public async Task SaveAsync(string destination, CarthagoSessionSnapshot snapshot, CancellationToken token = default)
    {
        ArgumentNullException.ThrowIfNull(snapshot);
        if (!string.Equals(Path.GetExtension(destination), CarthagoSessionSnapshot.FileExtension, StringComparison.OrdinalIgnoreCase))
            throw new InvalidOperationException("Carthago session archives must use the .csa extension.");

        string fullPath = Path.GetFullPath(destination);
        string tempPath = fullPath + "." + Guid.NewGuid().ToString("N") + ".tmp";
        try
        {
            var manifest = new Manifest
            {
                Format = "CarthagoSessionArchive",
                Version = CarthagoSessionSnapshot.FormatVersion,
                CreatedUtc = snapshot.CreatedUtc,
                Origin = snapshot.Origin,
                Limitations = snapshot.Limitations.ToArray()
            };

            await using (var file = new FileStream(tempPath, FileMode.CreateNew, FileAccess.Write, FileShare.None, 65536, useAsync: true))
            {
                using (var zip = new ZipArchive(file, ZipArchiveMode.Create, leaveOpen: true))
                {
                    foreach (string category in CarthagoSessionSnapshot.CategoryOrder)
                    {
                        token.ThrowIfCancellationRequested();
                        snapshot.Categories.TryGetValue(category, out var rows);
                        rows ??= new List<JsonElement>();
                        if (rows.Count > MaximumRowsPerCategory)
                            throw new InvalidOperationException($"{category} has too many rows for one session archive.");

                        string filename = $"data/{category}.json";
                        byte[] payload = JsonSerializer.SerializeToUtf8Bytes(rows, SessionJson.Options);
                        if (payload.LongLength > MaximumEntryBytes)
                            throw new InvalidOperationException($"{category} exceeds the per-category archive size limit.");
                        manifest.Entries.Add(new ManifestEntry
                        {
                            Category = category,
                            Path = filename,
                            Count = rows.Count,
                            ByteLength = payload.LongLength,
                            Sha256 = Convert.ToHexString(SHA256.HashData(payload))
                        });
                        var entry = zip.CreateEntry(filename, CompressionLevel.Fastest);
                        await using var entryStream = entry.Open();
                        await entryStream.WriteAsync(payload, token).ConfigureAwait(false);
                    }

                    if (manifest.Entries.Sum(x => x.ByteLength) > MaximumTotalBytes)
                        throw new InvalidOperationException("Session exceeds the overall archive size limit.");
                    var manifestEntry = zip.CreateEntry("manifest.json", CompressionLevel.Fastest);
                    await using var manifestStream = manifestEntry.Open();
                    byte[] manifestBytes = JsonSerializer.SerializeToUtf8Bytes(manifest, SessionJson.Options);
                    await manifestStream.WriteAsync(manifestBytes, token).ConfigureAwait(false);
                }
                await file.FlushAsync(token).ConfigureAwait(false);
            }

            // The completed temporary file is on the destination volume. Existing
            // sessions are not touched until the new archive has been fully written.
            File.Move(tempPath, fullPath, overwrite: true);
        }
        finally
        {
            if (File.Exists(tempPath)) File.Delete(tempPath);
        }
    }

    public async Task<CarthagoSessionSnapshot> OpenAsync(string path, CancellationToken token = default)
    {
        await using var file = new FileStream(path, FileMode.Open, FileAccess.Read, FileShare.Read, 65536, useAsync: true);
        using var zip = new ZipArchive(file, ZipArchiveMode.Read);
        if (zip.Entries.Count != MaximumArchiveEntries)
            throw new InvalidDataException("Session archive has unexpected or missing entries.");

        var manifestZipEntry = zip.GetEntry("manifest.json") ?? throw new InvalidDataException("Missing CSA manifest.");
        byte[] manifestBytes = await ReadBoundedAsync(manifestZipEntry, 512 * 1024, token).ConfigureAwait(false);
        var manifest = JsonSerializer.Deserialize<Manifest>(manifestBytes, SessionJson.Options)
                       ?? throw new InvalidDataException("Invalid CSA manifest.");
        if (manifest.Format != "CarthagoSessionArchive" || manifest.Version != CarthagoSessionSnapshot.FormatVersion)
            throw new InvalidDataException("Unsupported CSA archive format/version.");
        if (manifest.Entries.Count != CarthagoSessionSnapshot.CategoryOrder.Length
            || manifest.Entries.Sum(e => e.ByteLength) > MaximumTotalBytes)
            throw new InvalidDataException("Invalid CSA inventory.");

        var session = CarthagoSessionSnapshot.CreateEmpty();
        session.CreatedUtc = manifest.CreatedUtc;
        session.Origin = manifest.Origin;
        session.Limitations.AddRange(manifest.Limitations ?? Array.Empty<string>());
        foreach (string category in CarthagoSessionSnapshot.CategoryOrder)
        {
            token.ThrowIfCancellationRequested();
            ManifestEntry? inventory = manifest.Entries.SingleOrDefault(e => e.Category == category);
            if (inventory is null || inventory.Path != $"data/{category}.json"
                || inventory.Count < 0 || inventory.Count > MaximumRowsPerCategory
                || inventory.ByteLength < 0 || inventory.ByteLength > MaximumEntryBytes)
                throw new InvalidDataException($"Invalid archive entry declaration for {category}.");
            ZipArchiveEntry entry = zip.GetEntry(inventory.Path)
                                    ?? throw new InvalidDataException($"Missing {category} data.");
            byte[] payload = await ReadBoundedAsync(entry, MaximumEntryBytes, token).ConfigureAwait(false);
            if (payload.LongLength != inventory.ByteLength
                || !string.Equals(Convert.ToHexString(SHA256.HashData(payload)), inventory.Sha256, StringComparison.OrdinalIgnoreCase))
                throw new InvalidDataException($"Integrity check failed for {category}.");
            var rows = JsonSerializer.Deserialize<List<JsonElement>>(payload, SessionJson.Options)
                       ?? throw new InvalidDataException($"Invalid {category} rows.");
            if (rows.Count != inventory.Count)
                throw new InvalidDataException($"Row count mismatch for {category}.");
            session.Categories[category] = rows;
        }
        return session;
    }

    private static async Task<byte[]> ReadBoundedAsync(ZipArchiveEntry entry, long maximumBytes, CancellationToken token)
    {
        if (entry.Length > maximumBytes)
            throw new InvalidDataException("CSA archive entry is too large.");
        await using var source = entry.Open();
        using var target = new MemoryStream();
        byte[] buffer = new byte[65536];
        int count;
        while ((count = await source.ReadAsync(buffer, token).ConfigureAwait(false)) != 0)
        {
            if (target.Length + count > maximumBytes)
                throw new InvalidDataException("CSA entry exceeded decompression limit.");
            target.Write(buffer, 0, count);
        }
        return target.ToArray();
    }

    private sealed class Manifest
    {
        public string Format { get; set; } = "";
        public int Version { get; set; }
        public DateTime CreatedUtc { get; set; }
        public string Origin { get; set; } = "";
        public string[] Limitations { get; set; } = Array.Empty<string>();
        public List<ManifestEntry> Entries { get; set; } = new();
    }

    private sealed class ManifestEntry
    {
        public string Category { get; set; } = "";
        public string Path { get; set; } = "";
        public int Count { get; set; }
        public long ByteLength { get; set; }
        public string Sha256 { get; set; } = "";
    }
}
