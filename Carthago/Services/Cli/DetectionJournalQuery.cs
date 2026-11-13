// SPDX-License-Identifier: MIT
using System;
using System.Collections.Generic;
using System.IO;
using System.Text;
using System.Text.Json;
using System.Threading;
using System.Threading.Tasks;
using Carthago.Contracts;

namespace Carthago.Services.Cli;

/// <summary>Bounded point-in-time journal read. Missing, malformed or oversized data is unavailable.</summary>
public static class DetectionJournalQuery
{
    public const int MaxBytes = 8 * 1024 * 1024, MaxRows = 20000, MaxLineChars = 128 * 1024;

    public static async Task<InvestigationPage?> ReadAsync(string path, InvestigationFilter filter, CancellationToken token)
    {
        var rows = await ReadRowsAsync(path, token).ConfigureAwait(false);
        if (rows is null) return null;
        return Project(rows, filter, token);
    }

    public static async Task<InvestigationPage?> ReadWindowAsync(Func<DateTime, string> pathForDay,
        InvestigationFilter filter, JournalWindow window, CancellationToken token)
    {
        var rows = new List<JsonElement>();
        int days = 0;
        foreach (var day in window.Days())
        {
            if (++days > 2) throw new InvalidDataException("Too many journal days.");
            var dayRows = await ReadRowsAsync(pathForDay(day), token).ConfigureAwait(false);
            if (dayRows is null) return null; // no silent partial coverage
            rows.AddRange(dayRows);
        }
        return Project(rows, filter, token, window);
    }

    private static InvestigationPage Project(List<JsonElement> rows, InvestigationFilter filter,
        CancellationToken token, JournalWindow? window = null)
    {
        var page = InvestigationProjection.Select(rows, InvestigationKind.Alerts, filter, token, window);
        if (page.OmittedRows != 0) throw new InvalidDataException("Journal contains invalid detection identities.");
        return page;
    }

    private static async Task<List<JsonElement>?> ReadRowsAsync(string path, CancellationToken token)
    {
        FileStream stream;
        try { stream = new FileStream(path, FileMode.Open, FileAccess.Read, FileShare.ReadWrite, 8192, useAsync: true); }
        catch (FileNotFoundException) { return null; }
        catch (DirectoryNotFoundException) { return null; }
        await using (stream)
        {
            long length = stream.Length;
            if (length > MaxBytes) throw new InvalidDataException("Journal exceeds query limit.");
            byte[] bytes = new byte[(int)length];
            await stream.ReadExactlyAsync(bytes, token).ConfigureAwait(false);
            // An append in progress is not a complete point-in-time snapshot.
            if (bytes.Length > 0 && bytes[^1] != (byte)'\n')
                throw new InvalidDataException("Incomplete journal record.");
            string text = new UTF8Encoding(false, true).GetString(bytes);
            var rows = new List<JsonElement>();
            using var reader = new StringReader(text);
            string? line;
            while ((line = reader.ReadLine()) is not null)
            {
                token.ThrowIfCancellationRequested();
                if (string.IsNullOrWhiteSpace(line)) continue;
                if (line.Length > MaxLineChars || rows.Count >= MaxRows)
                    throw new InvalidDataException("Journal record limit exceeded.");
                using var doc = JsonDocument.Parse(line, new JsonDocumentOptions { MaxDepth = 32 });
                if (doc.RootElement.ValueKind != JsonValueKind.Object)
                    throw new InvalidDataException("Malformed journal row.");
                rows.Add(doc.RootElement.Clone());
            }
            return rows;
        }
    }
}
