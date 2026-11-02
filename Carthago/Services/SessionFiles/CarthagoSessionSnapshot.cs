// SPDX-License-Identifier: MIT
// SOURCE CANDIDATE — UNVERIFIED; TESTS AUTHORED — 0 EXECUTED.
using System;
using System.Collections.Generic;
using System.Linq;
using System.Text.Json;
using System.Text.Json.Nodes;
using System.Text.Json.Serialization;

namespace Carthago.Services.SessionFiles;

/// <summary>
/// A passive, redacted record of available analysis. Imported rows are NEVER
/// deserialized into trusted TrafficRecord/DetectionEvent producer objects.
/// </summary>
public sealed class CarthagoSessionSnapshot
{
    public const string FileExtension = ".csa";
    public const int FormatVersion = 1;

    public DateTime CreatedUtc { get; set; } = DateTime.UtcNow;
    public string Origin { get; set; } = "Carthago local analysis";
    public List<string> Limitations { get; set; } = new();
    public Dictionary<string, List<JsonElement>> Categories { get; set; } = new(StringComparer.Ordinal);

    public static readonly string[] CategoryOrder =
    {
        "Overview", "Traffic", "Alerts", "Incidents", "Anomalies",
        "Hosts", "Baselines", "Evidence", "Timeline", "Rules", "Enrichment"
    };

    public static CarthagoSessionSnapshot CreateEmpty()
    {
        var result = new CarthagoSessionSnapshot();
        foreach (string category in CategoryOrder)
            result.Categories.Add(category, new List<JsonElement>());
        return result;
    }

    public void AddRows<T>(string category, IEnumerable<T> rows)
    {
        if (!Categories.TryGetValue(category, out var target))
            throw new ArgumentException("Unknown session category.", nameof(category));

        foreach (T row in rows)
        {
            JsonNode? node = JsonSerializer.SerializeToNode(row, SessionJson.Options);
            if (node is null) continue;
            SessionPrivacy.Redact(node);
            target.Add(JsonSerializer.SerializeToElement(node, SessionJson.Options));
        }
    }
}

internal static class SessionJson
{
    internal static readonly JsonSerializerOptions Options = new()
    {
        WriteIndented = false,
        PropertyNameCaseInsensitive = false,
        DefaultIgnoreCondition = JsonIgnoreCondition.Never,
        ReferenceHandler = ReferenceHandler.IgnoreCycles,
        MaxDepth = 48,
        Converters = { new JsonStringEnumConverter() }
    };
}

internal static class SessionPrivacy
{
    private static readonly string[] SensitiveNames =
    {
        "password", "passwd", "credential", "secret", "authorization",
        "token", "apikey", "api_key", "privatekey", "private_key", "cookie",
        "httprequestheaders", "lastsinkerror", "persistenceerror"
    };

    internal static void Redact(JsonNode node)
    {
        if (node is JsonObject obj)
        {
            if (obj.TryGetPropertyValue("IsSensitive", out JsonNode? sensitiveMarker)
                && sensitiveMarker is JsonValue marker
                && marker.TryGetValue<bool>(out bool markedSensitive)
                && markedSensitive && obj.ContainsKey("Value"))
            {
                obj["Value"] = "[REDACTED]";
            }
            foreach (string key in obj.Select(p => p.Key).ToArray())
            {
                // Do not remove boolean telemetry such as *TokenPatternObserved:
                // those are security signals, not the underlying credentials.
                bool sensitive = SensitiveNames.Any(s => key.Contains(s, StringComparison.OrdinalIgnoreCase))
                    && !(key.EndsWith("Observed", StringComparison.OrdinalIgnoreCase)
                      || key.EndsWith("Pattern", StringComparison.OrdinalIgnoreCase)
                      || key.EndsWith("Count", StringComparison.OrdinalIgnoreCase));
                if (sensitive)
                    obj[key] = "[REDACTED]";
                else if (obj[key] is JsonNode child)
                    Redact(child);
            }
        }
        else if (node is JsonArray array)
        {
            foreach (JsonNode? element in array)
                if (element is not null) Redact(element);
        }
    }
}
