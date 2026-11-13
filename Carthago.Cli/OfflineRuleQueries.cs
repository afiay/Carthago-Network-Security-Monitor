// SPDX-License-Identifier: MIT
using System.Globalization;
using System.Text;
using System.Text.Json;
using Carthago.Services.SessionFiles;

namespace Carthago.Cli;

/// <summary>Read-only projections of explicitly supplied, untrusted offline files.</summary>
public static class OfflineRuleQueries
{
    public const int MaxPageSize = 100;
    public const int MaxLedgerBytes = 4 * 1024 * 1024;
    public const int MaxLedgerRows = 10000;

    public sealed record RuleRow(string RuleId, string? Name, string? Category, string? DefaultSeverity,
        bool? EnabledByDefault, bool? IsPlanned, string? Maturity, string? SignalKind, int? Revision);
    public sealed record RulePage(int Total, int Offset, int Limit, IReadOnlyList<RuleRow> Rules);
    public sealed record QualitySummary(int LedgerRows, int AuditPending, int ProducerBlocked,
        int OtherOrUnclassified, string Validation, string Provenance);

    public static bool IsRuleId(string id) => id.Length is >= 4 and <= 10
        && id[0] == 'R' && id.Skip(1).All(c => c is >= '0' and <= '9');

    public static bool TryPage(string offset, string limit, out int start, out int size)
    {
        bool validStart = int.TryParse(offset, NumberStyles.None, CultureInfo.InvariantCulture, out start);
        bool validSize = int.TryParse(limit, NumberStyles.None, CultureInfo.InvariantCulture, out size);
        return validStart && validSize && start >= 0 && size is >= 1 and <= MaxPageSize;
    }

    public static async Task<RulePage> ListAsync(string path, int offset, int limit, CancellationToken token)
    {
        if (offset < 0 || limit is < 1 or > MaxPageSize) throw new ArgumentOutOfRangeException(nameof(limit));
        var rules = await ReadRulesAsync(path, token);
        return new RulePage(rules.Count, offset, limit, rules.Skip(offset).Take(limit).ToArray());
    }

    public static async Task<RuleRow?> ShowAsync(string path, string id, CancellationToken token)
    {
        if (!IsRuleId(id)) throw new ArgumentException("Invalid rule ID.", nameof(id));
        var rules = await ReadRulesAsync(path, token);
        return rules.SingleOrDefault(r => r.RuleId == id);
    }

    private static async Task<IReadOnlyList<RuleRow>> ReadRulesAsync(string path, CancellationToken token)
    {
        if (!string.Equals(Path.GetExtension(path), ".csa", StringComparison.OrdinalIgnoreCase))
            throw new InvalidDataException("Expected a CSA file.");
        var snapshot = await new CarthagoSessionArchiveService().OpenAsync(path, token);
        var result = new List<RuleRow>();
        var ids = new HashSet<string>(StringComparer.Ordinal);
        foreach (var row in snapshot.Categories["Rules"])
        {
            token.ThrowIfCancellationRequested();
            if (row.ValueKind != JsonValueKind.Object) throw new InvalidDataException("Invalid rule row.");
            string? id = Text(row, "RuleId");
            if (id is null || !IsRuleId(id) || !ids.Add(id))
                throw new InvalidDataException("Invalid or duplicate rule ID.");
            result.Add(new RuleRow(id, Text(row, "RuleName"), Text(row, "Category"),
                Text(row, "DefaultSeverity"), Bool(row, "EnabledByDefault"), Bool(row, "IsPlanned"),
                Text(row, "Maturity"), Text(row, "SignalKind"),
                row.TryGetProperty("Revision", out var rev) && rev.ValueKind == JsonValueKind.Number
                    && rev.TryGetInt32(out int n) && n > 0 ? n : null));
        }
        return result.OrderBy(r => long.Parse(r.RuleId.AsSpan(1), CultureInfo.InvariantCulture))
            .ThenBy(r => r.RuleId, StringComparer.Ordinal).ToArray();
    }

    // Fixed projection: never emit description, evidence, raw payload or arbitrary columns.
    // Reject terminal control / format characters and excessive text rather than echo them.
    private static string? Text(JsonElement row, string key)
    {
        if (!row.TryGetProperty(key, out var value) || value.ValueKind != JsonValueKind.String) return null;
        string? text = value.GetString();
        return text is not null && text.Length <= 256 && !text.Any(c => char.IsControl(c)
            || char.GetUnicodeCategory(c) == UnicodeCategory.Format) ? text : null;
    }

    private static bool? Bool(JsonElement row, string key)
        => row.TryGetProperty(key, out var value) && value.ValueKind is JsonValueKind.True or JsonValueKind.False
            ? value.GetBoolean() : null;

    public static async Task<QualitySummary> QualityAsync(string path, CancellationToken token)
    {
        // Read a bounded snapshot of the explicit ledger, never follow linked paths or execute tests.
        await using var stream = new FileStream(path, FileMode.Open, FileAccess.Read, FileShare.Read,
            4096, useAsync: true);
        if (stream.Length > MaxLedgerBytes) throw new InvalidDataException("Ledger too large.");
        using var buffer = new MemoryStream();
        byte[] chunk = new byte[8192];
        int read;
        while ((read = await stream.ReadAsync(chunk, token)) != 0)
        {
            if (buffer.Length + read > MaxLedgerBytes) throw new InvalidDataException("Ledger too large.");
            buffer.Write(chunk, 0, read);
        }
        string source = new UTF8Encoding(false, true).GetString(buffer.ToArray());
        using var reader = new StringReader(source);
        const string header = "| Rule | Implementation | Producer | Positive | Negative | Boundary | Status/blocker |";
        bool found = false, inTable = false;
        int pending = 0, blocked = 0, other = 0;
        var ids = new HashSet<string>(StringComparer.Ordinal);
        string? line;
        while ((line = reader.ReadLine()) is not null)
        {
            token.ThrowIfCancellationRequested();
            if (!found)
            {
                if (line.Trim() == header) { found = true; inTable = true; }
                continue;
            }
            if (!inTable) continue;
            if (line.Trim() == "|---|---|---|---|---|---|---|") continue;
            if (!line.StartsWith('|')) { inTable = false; continue; }
            var fields = line.Split('|');
            if (fields.Length != 9 || fields[0].Length != 0 || fields[^1].Trim().Length != 0)
                throw new InvalidDataException("Unexpected ledger row format.");
            string id = fields[1].Trim();
            if (!IsRuleId(id) || !ids.Add(id) || ids.Count > MaxLedgerRows)
                throw new InvalidDataException("Invalid or duplicate ledger rule.");
            string status = fields[7].Trim();
            if (status.Equals("audit pending", StringComparison.OrdinalIgnoreCase)) pending++;
            else if (status.Contains("producer-blocked", StringComparison.OrdinalIgnoreCase)) blocked++;
            else other++;
        }
        if (!found || ids.Count == 0) throw new InvalidDataException("Missing qualification table.");
        // The markdown ledger is provisional and cannot prove execution or coverage.
        return new QualitySummary(ids.Count, pending, blocked, other, "not_assessed", "untrusted_local_ledger");
    }
}
