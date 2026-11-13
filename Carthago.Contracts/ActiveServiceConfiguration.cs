// SPDX-License-Identifier: MIT
using System.Text.Json;

namespace Carthago.Contracts;

public sealed record ActiveServiceSelection(string ProfileId, Guid GrantId);
public sealed record ActiveServiceOptions(string AccountSid, IReadOnlyList<ActiveServiceSelection> Profiles);

public static class ActiveServiceConfiguration
{
    public const int MaxBytes = 16384;
    public static ActiveServiceOptions Load(string path)
    {
        if (!OperatingSystem.IsWindows() || !Path.IsPathFullyQualified(path))
            throw new InvalidDataException("Windows absolute local configuration path required.");
        string root = Path.GetPathRoot(path) ?? "";
        if (root.Length != 3 || !char.IsAsciiLetter(root[0]) || root[1] != ':' || root[2] != '\\')
            throw new InvalidDataException("Local drive configuration required.");
        for (string? current = Path.GetFullPath(path); current is not null; current = Path.GetDirectoryName(current))
            if ((File.GetAttributes(current) & FileAttributes.ReparsePoint) != 0)
                throw new InvalidDataException("Reparse point rejected.");
        using var stream = new FileStream(path, FileMode.Open, FileAccess.Read, FileShare.Read);
        if (stream.Length is < 1 or > MaxBytes) throw new InvalidDataException("Invalid configuration size.");
        var bytes = new byte[(int)stream.Length];
        stream.ReadExactly(bytes);
        if (stream.ReadByte() != -1) throw new InvalidDataException("Configuration changed.");
        return Parse(bytes);
    }

    public static ActiveServiceOptions Parse(ReadOnlyMemory<byte> bytes)
    {
        if (bytes.Length is < 1 or > MaxBytes) throw new InvalidDataException("Invalid configuration size.");
        if (bytes.Length >= 3 && bytes.Span[0] == 0xef && bytes.Span[1] == 0xbb && bytes.Span[2] == 0xbf)
            bytes = bytes[3..];
        using var doc = JsonDocument.Parse(bytes, new JsonDocumentOptions { MaxDepth = 5 });
        var fields = Object(doc.RootElement, "schemaVersion", "accountSid", "profiles");
        if (fields["schemaVersion"].ValueKind != JsonValueKind.Number ||
            !fields["schemaVersion"].TryGetInt32(out int version) || version != 1)
            throw new InvalidDataException("Invalid schema.");
        string sid = String(fields["accountSid"]);
        // First deployment supports explicit local/domain user accounts only.
        // Reject SYSTEM, LocalService, NetworkService, virtual and group SIDs.
        var parts = sid.Split('-');
        if (parts.Length != 8 || !sid.StartsWith("S-1-5-21-", StringComparison.Ordinal) ||
            parts.Skip(4).Any(p => p.Length == 0 || p.Length > 10 || p.Any(c => c is < '0' or > '9') ||
                (p.Length > 1 && p[0] == '0') || !uint.TryParse(p, out _)))
            throw new InvalidDataException("Dedicated local/domain user SID required.");
        var array = fields["profiles"];
        if (array.ValueKind != JsonValueKind.Array || array.GetArrayLength() is < 1 or > 16)
            throw new InvalidDataException("One to sixteen profiles required.");
        var result = new List<ActiveServiceSelection>();
        var ids = new HashSet<string>(StringComparer.Ordinal);
        foreach (var entry in array.EnumerateArray())
        {
            var row = Object(entry, "profileId", "grantId");
            string id = String(row["profileId"]), grant = String(row["grantId"]);
            if (id.Length != 64 || id.Any(c => c is not (>= '0' and <= '9' or >= 'a' and <= 'f')) ||
                !ids.Add(id) || !Guid.TryParseExact(grant, "D", out var guid) || guid == Guid.Empty || grant != guid.ToString("D"))
                throw new InvalidDataException("Invalid or duplicate profile selection.");
            result.Add(new(id, guid));
        }
        return new(sid, result.AsReadOnly());
    }

    private static Dictionary<string, JsonElement> Object(JsonElement value, params string[] keys)
    {
        if (value.ValueKind != JsonValueKind.Object) throw new InvalidDataException("Expected object.");
        var fields = new Dictionary<string, JsonElement>(StringComparer.Ordinal);
        foreach (var p in value.EnumerateObject())
            if (!keys.Contains(p.Name, StringComparer.Ordinal) || !fields.TryAdd(p.Name, p.Value))
                throw new InvalidDataException("Unknown or duplicate configuration field.");
        if (fields.Count != keys.Length) throw new InvalidDataException("Missing configuration field.");
        return fields;
    }
    private static string String(JsonElement value) => value.ValueKind == JsonValueKind.String
        ? value.GetString() ?? "" : throw new InvalidDataException("Expected string.");
}
