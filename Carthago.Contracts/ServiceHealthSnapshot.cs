// SPDX-License-Identifier: MIT
using System.Text.Json;
using System.Text.Json.Serialization;

namespace Carthago.Contracts;

public sealed record ServiceHealthSnapshot(int SchemaVersion, Guid SessionId, int ProcessId,
    DateTimeOffset ProcessStartedUtc, DateTimeOffset SampledUtc, ForegroundMonitorCounters Counters);

public static class ServiceHealthStore
{
    public const int MaxBytes = 4096;
    public static readonly TimeSpan MaxAge = TimeSpan.FromSeconds(120);
    private static readonly JsonSerializerOptions Json = new(JsonSerializerDefaults.Web)
    {
        UnmappedMemberHandling = JsonUnmappedMemberHandling.Disallow,
        PropertyNameCaseInsensitive = false,
        MaxDepth = 6
    };
    public static string DefaultPath => Path.Combine(
        Environment.GetFolderPath(Environment.SpecialFolder.CommonApplicationData),
        "Carthago", "ServiceStatus", "monitor.json");

    public static void Validate(ServiceHealthSnapshot s)
    {
        if (s.SchemaVersion != 1 || s.SessionId == Guid.Empty || s.ProcessId <= 0 ||
            s.ProcessStartedUtc == default || s.ProcessStartedUtc.Offset != TimeSpan.Zero ||
            s.SampledUtc.Offset != TimeSpan.Zero || s.SampledUtc < s.ProcessStartedUtc ||
            s.Counters is not { } c || c.Captured < 0 || c.Parsed < 0 || c.ParseErrors < 0 || c.Detections < 0)
            throw new InvalidDataException("Invalid service health snapshot.");
    }

    // Directory must be provisioned with administrator-controlled ACLs before service start.
    public static void CheckPath(string path)
    {
        if (!Path.IsPathFullyQualified(path)) throw new InvalidDataException("Absolute status path required.");
        string? dir = Path.GetDirectoryName(path);
        if (dir is null || !Directory.Exists(dir)) throw new DirectoryNotFoundException("Status directory unavailable.");
        while (dir is not null)
        {
            if ((File.GetAttributes(dir) & FileAttributes.ReparsePoint) != 0)
                throw new InvalidDataException("Reparse-point status directory rejected.");
            dir = Path.GetDirectoryName(dir);
        }
        if (File.Exists(path) && (File.GetAttributes(path) & FileAttributes.ReparsePoint) != 0)
            throw new InvalidDataException("Reparse-point status file rejected.");
    }

    public static void Write(string path, ServiceHealthSnapshot snapshot)
    {
        Validate(snapshot);
        CheckPath(path);
        byte[] bytes = JsonSerializer.SerializeToUtf8Bytes(snapshot, Json);
        if (bytes.Length > MaxBytes) throw new InvalidDataException("Status too large.");
        string temporary = path + "." + Guid.NewGuid().ToString("N") + ".tmp";
        try
        {
            using (var stream = new FileStream(temporary, FileMode.CreateNew, FileAccess.Write, FileShare.None))
            {
                stream.Write(bytes);
                stream.Flush(flushToDisk: true);
            }
            File.Move(temporary, path, overwrite: true);
        }
        finally { if (File.Exists(temporary)) File.Delete(temporary); }
    }

    public static ServiceHealthSnapshot Read(string path)
    {
        CheckPath(path);
        using var stream = new FileStream(path, FileMode.Open, FileAccess.Read, FileShare.Read | FileShare.Delete);
        if (stream.Length is < 1 or > MaxBytes) throw new InvalidDataException("Invalid status size.");
        byte[] bytes = new byte[(int)stream.Length];
        stream.ReadExactly(bytes);
        if (stream.ReadByte() != -1) throw new InvalidDataException("Status changed while reading.");
        using var doc = JsonDocument.Parse(bytes, new JsonDocumentOptions { MaxDepth = 6 });
        RequireFields(doc.RootElement, "schemaVersion", "sessionId", "processId", "processStartedUtc", "sampledUtc", "counters");
        RequireFields(doc.RootElement.GetProperty("counters"), "captured", "parsed", "parseErrors", "detections");
        var snapshot = JsonSerializer.Deserialize<ServiceHealthSnapshot>(bytes, Json)
            ?? throw new InvalidDataException("Missing status.");
        Validate(snapshot);
        return snapshot;
    }

    private static void RequireFields(JsonElement element, params string[] required)
    {
        if (element.ValueKind != JsonValueKind.Object) throw new InvalidDataException("Expected status object.");
        var seen = new HashSet<string>(StringComparer.Ordinal);
        foreach (var p in element.EnumerateObject())
            if (!seen.Add(p.Name) || !required.Contains(p.Name, StringComparer.Ordinal))
                throw new InvalidDataException("Unknown or duplicate status field.");
        if (seen.Count != required.Length) throw new InvalidDataException("Missing status field.");
    }

    public static string Assess(ServiceHealthSnapshot s, int processId, DateTimeOffset? processStartedUtc, DateTimeOffset now)
    {
        Validate(s);
        if (processStartedUtc is null) return "process_identity_unavailable";
        if (s.ProcessId != processId || s.ProcessStartedUtc != processStartedUtc.Value) return "process_mismatch";
        if (s.SampledUtc > now) return "future_sample";
        if (now - s.SampledUtc > MaxAge) return "stale";
        return "fresh_sample";
    }
}
