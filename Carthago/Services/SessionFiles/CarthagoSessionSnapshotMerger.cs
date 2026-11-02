// SPDX-License-Identifier: MIT
// SOURCE CANDIDATE — UNVERIFIED; TESTS AUTHORED — 0 EXECUTED.
using System;
using System.Collections.Generic;
using System.Globalization;
using System.Linq;
using System.Text.Json;

namespace Carthago.Services.SessionFiles;

/// <summary>
/// Combines an existing passive archive with a new available-data snapshot.
/// Duplicate stable identities replace older rows without ever feeding them
/// back into capture, rule evaluation, journals or analytics state.
/// </summary>
public static class CarthagoSessionSnapshotMerger
{
    public static CarthagoSessionSnapshot Merge(CarthagoSessionSnapshot previous, CarthagoSessionSnapshot current)
    {
        ArgumentNullException.ThrowIfNull(previous);
        ArgumentNullException.ThrowIfNull(current);

        var result = CarthagoSessionSnapshot.CreateEmpty();
        result.CreatedUtc = previous.CreatedUtc <= current.CreatedUtc ? previous.CreatedUtc : current.CreatedUtc;
        result.Origin = previous.Origin;
        result.Limitations.AddRange(previous.Limitations.Concat(current.Limitations)
            .Distinct(StringComparer.Ordinal));

        foreach (string category in CarthagoSessionSnapshot.CategoryOrder)
        {
            var rows = result.Categories[category];
            var indexes = new Dictionary<string, int>(StringComparer.Ordinal);
            foreach (JsonElement row in GetRows(previous, category).Concat(GetRows(current, category)))
            {
                string key = Identity(category, row);
                if (indexes.TryGetValue(key, out int index))
                {
                    if (IsNotOlder(row, rows[index])) rows[index] = row.Clone();
                }
                else
                {
                    indexes[key] = rows.Count;
                    rows.Add(row.Clone());
                }
            }
        }

        return result;
    }

    private static IEnumerable<JsonElement> GetRows(CarthagoSessionSnapshot snapshot, string category)
        => snapshot.Categories.TryGetValue(category, out var rows) ? rows : Enumerable.Empty<JsonElement>();

    private static string Identity(string category, JsonElement row)
    {
        string[] columns = category switch
        {
            "Traffic" or "Enrichment" or "Incidents" or "Anomalies" => new[] { "Id" },
            "Alerts" => new[] { "EventId" },
            "Hosts" => new[] { "Host" },
            "Rules" => new[] { "RuleId" },
            "Timeline" => new[] { "IncidentId", "Id" },
            "Evidence" => new[] { "EventId", "Key", "Source", "Value" },
            "Overview" => new[] { "CapturedAtUtc" },
            "Baselines" => new[] { "LastUpdatedUtc" },
            _ => Array.Empty<string>()
        };

        if (columns.Length > 0 && row.ValueKind == JsonValueKind.Object)
        {
            var parts = new List<string>();
            foreach (string column in columns)
            {
                if (!row.TryGetProperty(column, out var property) || property.ValueKind == JsonValueKind.Null)
                    return "raw:" + row.GetRawText();
                parts.Add(property.ToString());
            }
            return category + ":" + string.Join("\u001F", parts);
        }
        // No reliable identity: deduplicate only byte-identical JSON, never
        // collapse unrelated records using an invented key.
        return "raw:" + row.GetRawText();
    }

    private static bool IsNotOlder(JsonElement incoming, JsonElement existing)
    {
        DateTimeOffset? left = GetRevision(incoming);
        DateTimeOffset? right = GetRevision(existing);
        return left is null || right is null || left >= right;
    }

    private static DateTimeOffset? GetRevision(JsonElement row)
    {
        if (row.ValueKind != JsonValueKind.Object) return null;
        foreach (string key in new[] { "UpdatedUtc", "LastUpdatedUtc", "LastSeenUtc", "TimestampUtc" })
        {
            if (row.TryGetProperty(key, out var property)
                && property.ValueKind == JsonValueKind.String
                && DateTimeOffset.TryParse(property.GetString(), CultureInfo.InvariantCulture,
                    DateTimeStyles.AssumeUniversal, out DateTimeOffset parsed))
                return parsed;
        }
        return null;
    }
}
