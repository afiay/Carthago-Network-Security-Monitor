// SPDX-License-Identifier: MIT
using System.Text.Json;

namespace Carthago.Contracts;

/// <summary>Explicit, bounded service settings; no secrets, commands or runtime privilege switches.</summary>
public static class MonitorServiceConfiguration
{
    public const int MaxBytes = 16 * 1024;
    public const int SchemaVersion = 1;

    public static ForegroundMonitorOptions Load(string path)
    {
        if (!Path.IsPathFullyQualified(path)) throw new InvalidDataException("Absolute configuration path required.");
        if (OperatingSystem.IsWindows())
        {
            // Service configuration must be a local drive path, not UNC/device syntax.
            string root = Path.GetPathRoot(path) ?? "";
            if (root.Length != 3 || !char.IsAsciiLetter(root[0]) || root[1] != ':' || root[2] != '\\')
                throw new InvalidDataException("Local drive configuration path required.");
            // Reject reparse points at the file and its ancestors. ACL protection remains
            // an operator prerequisite; this is not a race-free filesystem trust proof.
            string? current = Path.GetFullPath(path);
            while (current is not null)
            {
                if ((File.GetAttributes(current) & FileAttributes.ReparsePoint) != 0)
                    throw new InvalidDataException("Reparse-point configuration path rejected.");
                current = Path.GetDirectoryName(current);
            }
        }
        using var stream = new FileStream(path, FileMode.Open, FileAccess.Read, FileShare.Read);
        if (stream.Length > MaxBytes) throw new InvalidDataException("Configuration too large.");
        var bytes = new byte[(int)stream.Length];
        stream.ReadExactly(bytes);
        if (stream.ReadByte() != -1) throw new InvalidDataException("Configuration changed while reading.");
        return Parse(bytes);
    }

    public static ForegroundMonitorOptions Parse(ReadOnlyMemory<byte> bytes)
    {
        if (bytes.Length is < 1 or > MaxBytes) throw new InvalidDataException("Invalid configuration size.");
        // Accept UTF-8 BOM written by Windows PowerShell, not other encodings.
        if (bytes.Length >= 3 && bytes.Span[0] == 0xef && bytes.Span[1] == 0xbb && bytes.Span[2] == 0xbf)
            bytes = bytes[3..];
        using var doc = JsonDocument.Parse(bytes, new JsonDocumentOptions { MaxDepth = 4 });
        if (doc.RootElement.ValueKind != JsonValueKind.Object) throw new InvalidDataException("Expected configuration object.");
        var seen = new HashSet<string>(StringComparer.Ordinal);
        int? schema = null;
        string? id = null, filter = null;
        int seconds = 5;
        foreach (var p in doc.RootElement.EnumerateObject())
        {
            if (!seen.Add(p.Name)) throw new InvalidDataException("Duplicate configuration field.");
            switch (p.Name)
            {
                case "schemaVersion":
                    if (p.Value.ValueKind != JsonValueKind.Number || !p.Value.TryGetInt32(out int version))
                        throw new InvalidDataException("Invalid schema version.");
                    schema = version; break;
                case "interfaceId":
                    if (p.Value.ValueKind != JsonValueKind.String) throw new InvalidDataException("Invalid interface.");
                    id = p.Value.GetString(); break;
                case "filter":
                    if (p.Value.ValueKind is not (JsonValueKind.String or JsonValueKind.Null))
                        throw new InvalidDataException("Invalid filter.");
                    filter = p.Value.GetString(); break;
                case "statusSeconds":
                    if (p.Value.ValueKind != JsonValueKind.Number || !p.Value.TryGetInt32(out seconds))
                        throw new InvalidDataException("Invalid sample interval.");
                    break;
                default: throw new InvalidDataException("Unknown configuration field.");
            }
        }
        if (schema != SchemaVersion || id is null) throw new InvalidDataException("Schema version and interface required.");
        var args = new List<string> { "monitor", "start", "--interface", id, "--status-seconds",
            seconds.ToString(System.Globalization.CultureInfo.InvariantCulture) };
        if (filter is not null) { args.Add("--filter"); args.Add(filter); }
        if (!ForegroundMonitor.TryParse(args.ToArray(), out var options))
            throw new InvalidDataException("Invalid monitor configuration.");
        return options!; // Service never enables foreground IPC or CLI stop.
    }
}
