// SPDX-License-Identifier: MIT
using System.Buffers.Binary;
using System.Globalization;
using System.Text.Json;
using System.Text.Json.Serialization;

namespace Carthago.Contracts;

public enum LiveQueryKind { RulesList = 1, RuleShow = 2, RulesValidate = 3, SensorsList = 4, SensorsHealth = 5 }
public enum LiveQueryState { Available = 1, Unavailable = 2, NotFound = 3 }
public sealed record LiveQuery(int Version, Guid Correlation, LiveQueryKind Kind, int Offset, int Limit, string? RuleId);
public sealed record LiveRuleRow(string RuleId, string Name, string Category, string DefaultSeverity, bool EnabledByDefault, bool Planned);
public sealed record LiveSensorRow(string SensorId, DateTimeOffset LastHeartbeatUtc, string Freshness);
public sealed record LiveQueryResult(int Version, Guid Correlation, LiveQueryKind Kind, LiveQueryState State,
    DateTimeOffset ObservedUtc, int? Total = null, LiveRuleRow[]? Rules = null, LiveSensorRow[]? Sensors = null,
    int? CatalogErrors = null, int? Fresh = null, int? Stale = null, int? Future = null);

/// <summary>Bounded v2 read protocol, separate endpoint; v1 remains unchanged.</summary>
public static class LiveQueryProtocol
{
    public const int Version = 2, MaxPage = 100, MaxRequestBytes = 1024, MaxResponseBytes = 128 * 1024;
    private static readonly JsonSerializerOptions Json = new(JsonSerializerDefaults.Web)
    {
        UnmappedMemberHandling = JsonUnmappedMemberHandling.Disallow,
        PropertyNameCaseInsensitive = false,
        MaxDepth = 8
    };

    public static bool RuleIdValid(string? value) => value is { Length: >= 4 and <= 10 } &&
        value[0] == 'R' && value.Skip(1).All(c => c is >= '0' and <= '9');
    public static bool SensorIdValid(string? value) => value is { Length: >= 1 and <= 128 } &&
        value.All(c => c is >= 'a' and <= 'z' or >= 'A' and <= 'Z' or >= '0' and <= '9' or '-' or '_' or '.' or ':');
    public static bool SafeText(string? value) => value is { Length: <= 256 } &&
        !value.Any(c => char.IsControl(c) || char.GetUnicodeCategory(c) == UnicodeCategory.Format);

    public static void ValidateQuery(LiveQuery q)
    {
        if (q.Version != Version || q.Correlation == Guid.Empty || !Enum.IsDefined(q.Kind) ||
            q.Offset < 0 || q.Limit is < 1 or > MaxPage ||
            (q.Kind == LiveQueryKind.RuleShow ? !RuleIdValid(q.RuleId) : q.RuleId is not null) ||
            (q.Kind is not (LiveQueryKind.RulesList or LiveQueryKind.SensorsList) && (q.Offset != 0 || q.Limit != 1)))
            throw new InvalidDataException("Invalid live query.");
    }

    public static void ValidateResult(LiveQueryResult r, LiveQuery q)
    {
        ValidateQuery(q);
        if (r.Version != Version || r.Correlation != q.Correlation || r.Kind != q.Kind ||
            !Enum.IsDefined(r.State) || r.ObservedUtc.Offset != TimeSpan.Zero || r.ObservedUtc == default)
            throw new InvalidDataException("Invalid live response identity.");
        bool noData = r.Total is null && r.Rules is null && r.Sensors is null && r.CatalogErrors is null &&
            r.Fresh is null && r.Stale is null && r.Future is null;
        if (r.State != LiveQueryState.Available)
        {
            if (!noData || (r.State == LiveQueryState.NotFound && q.Kind != LiveQueryKind.RuleShow))
                throw new InvalidDataException("Unavailable response contains data.");
            return;
        }
        bool countsAbsent = r.Fresh is null && r.Stale is null && r.Future is null;
        switch (q.Kind)
        {
            case LiveQueryKind.RulesList:
            case LiveQueryKind.RuleShow:
                if (r.Total is null or < 0 || r.Rules is null || r.Sensors is not null || r.CatalogErrors is not null || !countsAbsent ||
                    r.Rules.Length != Math.Min(q.Limit, Math.Max(0, r.Total.Value - q.Offset)) ||
                    r.Rules.Any(x => x is null || !RuleIdValid(x.RuleId) || !SafeText(x.Name) ||
                        !SafeText(x.Category) || !SafeText(x.DefaultSeverity)) ||
                    r.Rules.Select(x => x.RuleId).Distinct(StringComparer.Ordinal).Count() != r.Rules.Length ||
                    (q.Kind == LiveQueryKind.RuleShow && (r.Total != 1 || r.Rules.Length != 1 || r.Rules[0].RuleId != q.RuleId)))
                    throw new InvalidDataException("Invalid rule response.");
                break;
            case LiveQueryKind.RulesValidate:
                if (r.CatalogErrors is null or < 0 || r.Total is not null || r.Rules is not null || r.Sensors is not null || !countsAbsent)
                    throw new InvalidDataException("Invalid validation response.");
                break;
            case LiveQueryKind.SensorsList:
                if (r.Total is null or < 0 || r.Sensors is null || r.Rules is not null || r.CatalogErrors is not null || !countsAbsent ||
                    r.Sensors.Length != Math.Min(q.Limit, Math.Max(0, r.Total.Value - q.Offset)) ||
                    r.Sensors.Any(x => x is null || !SensorIdValid(x.SensorId) || x.LastHeartbeatUtc.Offset != TimeSpan.Zero ||
                        x.LastHeartbeatUtc == default || x.Freshness is not ("fresh" or "stale" or "future")) ||
                    r.Sensors.Select(x => x.SensorId).Distinct(StringComparer.OrdinalIgnoreCase).Count() != r.Sensors.Length)
                    throw new InvalidDataException("Invalid sensor response.");
                break;
            case LiveQueryKind.SensorsHealth:
                if (r.Total is null or < 0 || r.Fresh is null or < 0 || r.Stale is null or < 0 || r.Future is null or < 0 ||
                    (long)r.Fresh.Value + r.Stale.Value + r.Future.Value != r.Total ||
                    r.Rules is not null || r.Sensors is not null || r.CatalogErrors is not null)
                    throw new InvalidDataException("Invalid sensor health response.");
                break;
        }
    }

    public static async Task WriteAsync<T>(Stream stream, T value, int maxBytes, CancellationToken token)
    {
        byte[] body = JsonSerializer.SerializeToUtf8Bytes(value, Json);
        if (body.Length is 0 || body.Length > maxBytes) throw new InvalidDataException("Frame too large.");
        byte[] header = new byte[4];
        BinaryPrimitives.WriteInt32BigEndian(header, body.Length);
        await stream.WriteAsync(header, token).ConfigureAwait(false);
        await stream.WriteAsync(body, token).ConfigureAwait(false);
    }

    public static async Task<T> ReadAsync<T>(Stream stream, int maxBytes, CancellationToken token) where T : class
    {
        byte[] header = new byte[4];
        await stream.ReadExactlyAsync(header, token).ConfigureAwait(false);
        int size = BinaryPrimitives.ReadInt32BigEndian(header);
        if (size < 2 || size > maxBytes) throw new InvalidDataException("Invalid frame length.");
        byte[] body = new byte[size];
        await stream.ReadExactlyAsync(body, token).ConfigureAwait(false);
        using var document = JsonDocument.Parse(body, new JsonDocumentOptions { MaxDepth = 8 });
        RejectDuplicateProperties(document.RootElement);
        return JsonSerializer.Deserialize<T>(body, Json) ?? throw new InvalidDataException("Missing frame data.");
    }

    private static void RejectDuplicateProperties(JsonElement element)
    {
        if (element.ValueKind == JsonValueKind.Object)
        {
            var names = new HashSet<string>(StringComparer.Ordinal);
            foreach (var property in element.EnumerateObject())
            {
                if (!names.Add(property.Name)) throw new InvalidDataException("Duplicate JSON field.");
                RejectDuplicateProperties(property.Value);
            }
        }
        else if (element.ValueKind == JsonValueKind.Array)
            foreach (var item in element.EnumerateArray()) RejectDuplicateProperties(item);
    }
}
